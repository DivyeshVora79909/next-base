//! Two bounded fake email transports. Every HTTP call follows an exact native
//! start/lease confirmation; key loading uses only the retained accepted binding.
use super::*;
use crate::{
    credentials::crypto::{ApiKeySecret, Provider},
    credentials::grants,
    email::{EmailOutcome, SendInput},
};
use state::{Claim, Mode, WorkClass};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{sync::watch, task::JoinSet};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub resend_origin: String,
    pub brevo_origin: String,
    #[serde(default)]
    pub mode: WorkerMode,
    pub policies: Vec<super::admission::Policy>,
    #[serde(default)]
    pub probe_directory: Option<PathBuf>,
}
impl Config {
    pub(crate) fn validate<B: Binding>(&self) -> Result<()> {
        if !B::credential_enabled()
            || B::NAME != "services"
            || self.resend_origin == self.brevo_origin
            || self
                .probe_directory
                .as_ref()
                .is_some_and(|path| !path.is_absolute() || !path.is_dir())
        {
            return Err(configuration());
        }
        if origin(&self.resend_origin)?.origin() == origin(&self.brevo_origin)?.origin() {
            return Err(configuration());
        }
        super::admission::Policies::new(self.policies.clone())?;
        Ok(())
    }
}
fn configuration() -> Error {
    Error::new(
        "invalid_config",
        "email workers require fixed fake loopback origins and quota policies",
    )
}
fn transport() -> Error {
    Error::new("email_transport", "email provider call is unavailable")
}
fn origin(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).map_err(|_| configuration())?;
    if url.scheme() != "http"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || !url.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    {
        return Err(configuration());
    }
    Ok(url)
}
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| Error::new("internal", "email transaction task"))?
}
async fn probe(
    config: &Config,
    point: &str,
    id: Uuid,
    stop: &mut watch::Receiver<bool>,
) -> Result<bool> {
    let Some(directory) = &config.probe_directory else {
        return Ok(!*stop.borrow());
    };
    std::fs::write(
        directory.join(format!("{id}.{point}.json")),
        local::encode(&json!({"execution_id":id,"boundary":point}))?,
    )
    .map_err(local::storage)?;
    while (directory.join(format!("{point}.hold")).exists()
        || directory.join(format!("{id}.{point}.hold")).exists())
        && !*stop.borrow()
    {
        tokio::select! { _=tokio::time::sleep(Duration::from_millis(25))=>{}, _=stop.changed()=>break }
    }
    Ok(!*stop.borrow())
}
fn encoded_body(provider: Provider, request: &SendInput) -> Result<Value> {
    request.validate()?;
    let email = &request.email;
    Ok(match provider {
        Provider::Resend => {
            json!({"from":email.sender,"to":email.to,"subject":email.subject,"text":email.text})
        }
        Provider::Brevo => {
            json!({"sender":{"email":email.sender},"to":email.to.iter().map(|address|json!({"email":address})).collect::<Vec<_>>(),"subject":email.subject,"textContent":email.text})
        }
    })
}
fn auth_header(provider: Provider, secret: &ApiKeySecret) -> Result<reqwest::header::HeaderValue> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(secret.as_bytes().len() + 7));
    if provider == Provider::Resend {
        bytes.extend_from_slice(b"Bearer ");
    }
    bytes.extend_from_slice(secret.as_bytes());
    let mut header = reqwest::header::HeaderValue::from_bytes(&bytes).map_err(|_| transport())?;
    header.set_sensitive(true);
    Ok(header)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResendResponse {
    id: Option<String>,
    rebase: ResendEvent,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResendEvent {
    provider: Provider,
    #[serde(with = "uuid_text")]
    execution_id: Uuid,
    account: String,
    request_hash: String,
    status: Disposition,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrevoResponse {
    #[serde(rename = "messageId")]
    message_id: Option<String>,
    event: BrevoEvent,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrevoEvent {
    provider: Provider,
    #[serde(with = "uuid_text")]
    execution: Uuid,
    account: String,
    #[serde(rename = "requestHash")]
    request_hash: String,
    disposition: Disposition,
}
fn decode_outcome(provider: Provider, bytes: &[u8]) -> Result<EmailOutcome> {
    // Parsing through the duplicate-rejecting JSON boundary precedes typed shape checks.
    let value = crate::json::parse(bytes).map_err(|_| transport())?;
    match provider {
        Provider::Resend => {
            let response: ResendResponse =
                serde_json::from_value(value.clone()).map_err(|_| transport())?;
            if serde_json::to_value(&response).map_err(|_| transport())? != value {
                return Err(transport());
            }
            Ok(EmailOutcome {
                execution_id: response.rebase.execution_id,
                provider: response.rebase.provider,
                account: response.rebase.account,
                request_hash: response.rebase.request_hash,
                disposition: response.rebase.status,
                receipt: response.id,
            })
        }
        Provider::Brevo => {
            let response: BrevoResponse =
                serde_json::from_value(value.clone()).map_err(|_| transport())?;
            if serde_json::to_value(&response).map_err(|_| transport())? != value {
                return Err(transport());
            }
            Ok(EmailOutcome {
                execution_id: response.event.execution,
                provider: response.event.provider,
                account: response.event.account,
                request_hash: response.event.request_hash,
                disposition: response.event.disposition,
                receipt: response.message_id,
            })
        }
    }
}

async fn call<B: Binding>(
    store: Arc<Store<B>>,
    runtime: Arc<grants::Runtime>,
    client: reqwest::Client,
    config: Config,
    claim: &Claim,
) -> Result<Option<B::Outcome>> {
    let owner = store.clone();
    let proof = claim.clone();
    let keys = runtime.clone();
    let prepared = blocking(move || {
        let row = if proof.mode == Mode::Submit {
            owner.confirm_effect_start(&proof)?
        } else {
            owner.confirm_effect_reconcile(&proof)?
        };
        let accepted = row.email_binding.as_ref().ok_or_else(transport)?;
        let (read, _, _) = owner.read(owner.model().identity())?;
        let secret = grants::load_pinned_secret::<B>(&read, accepted, row.tenant, keys.crypto())?;
        Ok((row, secret))
    })
    .await;
    let (row, secret) = match prepared {
        Ok(ready) => ready,
        Err(error) if error.code == "stale_version" => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(async {
        let accepted = row.email_binding.as_ref()?;
        let input = B::email_input(&row.request)?;
        let provider = accepted.provider();
        let endpoint = match provider {
            Provider::Resend => &config.resend_origin,
            Provider::Brevo => &config.brevo_origin,
        };
        let path = match provider {
            Provider::Resend => "/emails",
            Provider::Brevo => "/v3/smtp/email",
        };
        let mut url = format!("{}{path}", endpoint.trim_end_matches('/'));
        if claim.mode == Mode::Reconcile {
            url.push('/');
            url.push_str(&row.id.to_string());
        }
        let mut request = if claim.mode == Mode::Submit {
            client.post(url).json(&encoded_body(provider, input).ok()?)
        } else {
            client.get(url)
        };
        request = request
            .header("x-rebase-action", crate::email::EMAIL_OPERATION)
            .header("x-rebase-account", accepted.account())
            .header("x-rebase-request-hash", input.email.request_hash().ok()?);
        request = match provider {
            Provider::Resend => request
                .header(
                    reqwest::header::AUTHORIZATION,
                    auth_header(provider, &secret).ok()?,
                )
                .header(
                    "idempotency-key",
                    format!("{}/{}", crate::email::EMAIL_OPERATION, row.id),
                ),
            Provider::Brevo => request
                .header("api-key", auth_header(provider, &secret).ok()?)
                .header("x-rebase-execution", row.id.to_string()),
        };
        // Key loading and request construction may take time. Confirm freshness and
        // exact ownership again immediately before handing the request to HTTP.
        let owner = store.clone();
        let proof = claim.clone();
        blocking(move || {
            if proof.mode == Mode::Submit {
                owner.confirm_effect_start(&proof)?;
            } else {
                owner.confirm_effect_reconcile(&proof)?;
            }
            Ok(())
        })
        .await
        .ok()?;
        let mut response = request.send().await.ok()?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|size| size > MAX_OUTCOME as u64)
        {
            return None;
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if bytes.len().checked_add(chunk.len())? > MAX_OUTCOME {
                return None;
            }
            bytes.extend_from_slice(&chunk);
        }
        let outcome = decode_outcome(provider, &bytes).ok()?;
        outcome.validate(&input.email, row.id).ok()?;
        outcome
            .validate_binding(provider, accepted.account())
            .ok()?;
        let outcome: B::Outcome =
            serde_json::from_value(serde_json::to_value(outcome).ok()?).ok()?;
        B::effect_outcome(&row.request, row.id, &outcome).ok()?;
        Some(outcome)
    }
    .await)
}
struct Completed<B: Binding> {
    claim: Claim,
    outcome: Result<Option<B::Outcome>>,
}
async fn finish<B: Binding>(
    store: Arc<Store<B>>,
    config: &Config,
    completed: Completed<B>,
    stop: &mut watch::Receiver<bool>,
) -> Result<()> {
    let outcome = completed.outcome?;
    probe(config, "after_provider", completed.claim.execution, stop).await?;
    let id = completed.claim.execution;
    match blocking(move || store.finish_effect(&completed.claim, outcome.as_ref())).await {
        Ok(()) => {
            probe(config, "after_fact", id, stop).await?;
            Ok(())
        }
        Err(error) if error.code == "stale_version" => Ok(()),
        Err(error) => Err(error),
    }
}
pub(crate) async fn run<B: Binding>(
    store: Arc<Store<B>>,
    config: Config,
    runtime: Arc<grants::Runtime>,
    activation: Uuid,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    config.validate::<B>()?;
    let policies = Arc::new(super::admission::Policies::new(config.policies.clone())?);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(2))
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .pool_max_idle_per_host(2)
        .build()
        .map_err(|_| transport())?;
    let mut calls: JoinSet<Completed<B>> = JoinSet::new();
    let mut interval = tokio::time::interval(Duration::from_millis(250));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result: Result<()> = async {
        loop {
            if *stop.borrow() { break; }
            tokio::select! {
                _=stop.changed()=>break,
                completed=calls.join_next(),if !calls.is_empty()=>{
                    let completed=completed.ok_or_else(||Error::new("internal","missing email task"))?.map_err(|_|Error::new("internal","email provider task"))?;
                    finish(store.clone(),&config,completed,&mut stop).await?;
                },
                _=interval.tick()=>{
                    let owner=store.clone(); let candidates=blocking(move ||owner.scan_effects(activation)).await?;
                    for candidate in candidates {
                        if *stop.borrow() {break;}
                        if candidate.class==WorkClass::Apply {let owner=store.clone();blocking(move ||owner.apply_effect(&candidate)).await?;continue;}
                        if candidate.class!=WorkClass::Expiry && calls.len()>=2 {continue;}
                        let owner=store.clone(); let Some(claim)=blocking(move ||owner.claim_effect(&candidate)).await? else {continue;};
                        let claim=if claim.mode==Mode::Submit {
                            if !probe(&config,"before_start",claim.execution,&mut stop).await? {break;}
                            let owner=store.clone();let limits=policies.clone();
                            let started=match blocking(move ||owner.start_effect_email(&claim,&limits)).await {
                                Ok(Some(started))=>started,Ok(None)=>continue,
                                Err(error) if error.code=="stale_version"=>continue,Err(error)=>return Err(error),
                            };
                            if !probe(&config,"after_start",started.execution,&mut stop).await? {break;}
                            started
                        } else {claim};
                        let client=client.clone();let configuration=config.clone();let keys=runtime.clone();let owner=store.clone();
                        calls.spawn(async move {let outcome=call(owner,keys,client,configuration,&claim).await;Completed{claim,outcome}});
                    }
                },
            }
        }
        Ok(())
    }.await;
    // Stop owns/drains in-flight calls and their blocking confirmations. A
    // caller timeout never frees capacity for a replacement submission.
    while let Some(completed) = calls.join_next().await {
        if let Ok(completed) = completed
            && let Err(error) = finish(store.clone(), &config, completed, &mut stop).await
        {
            eprintln!(
                "{}",
                json!({"event":"email_finish_deferred","kind":error.code})
            );
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{email::EmailRequest, models::services::Services};
    fn input() -> SendInput {
        SendInput {
            email: EmailRequest {
                sender: "Sender@example.com".into(),
                to: vec!["Receiver@example.net".into()],
                subject: "subject".into(),
                text: "body\nsecond".into(),
            },
            selection: grants::Selection::Byoc {
                credential: Uuid::from_u128(1),
            },
            execute_at: None,
            not_after: None,
        }
    }
    #[test]
    fn fake_wire_shapes_are_distinct_and_responses_bind_all_identities() {
        let input = input();
        let execution = Uuid::from_u128(2);
        let hash = input.email.request_hash().unwrap();
        assert_eq!(
            encoded_body(Provider::Resend, &input).unwrap(),
            json!({"from":"Sender@example.com","to":["Receiver@example.net"],"subject":"subject","text":"body\nsecond"})
        );
        assert_eq!(
            encoded_body(Provider::Brevo, &input).unwrap(),
            json!({"sender":{"email":"Sender@example.com"},"to":[{"email":"Receiver@example.net"}],"subject":"subject","textContent":"body\nsecond"})
        );
        let resend = json!({"id":"resend:test","rebase":{"provider":"resend","execution_id":execution,"account":"test","request_hash":hash,"status":"succeeded"}});
        let brevo = json!({"messageId":"brevo:test","event":{"provider":"brevo","execution":execution,"account":"test","requestHash":hash,"disposition":"succeeded"}});
        for (provider, value) in [
            (Provider::Resend, resend.clone()),
            (Provider::Brevo, brevo.clone()),
        ] {
            let outcome = decode_outcome(provider, &serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(outcome.validate(&input.email, execution).is_ok());
            assert!(outcome.validate_binding(provider, "test").is_ok());
            let mut extra = value.clone();
            extra["extra"] = json!(1);
            assert!(decode_outcome(provider, &serde_json::to_vec(&extra).unwrap()).is_err());
        }
        assert!(decode_outcome(Provider::Resend, &serde_json::to_vec(&brevo).unwrap()).is_err());
        assert!(decode_outcome(Provider::Brevo, &serde_json::to_vec(&resend).unwrap()).is_err());
        assert!(decode_outcome(Provider::Resend, br#"{"id":null,"id":null,"rebase":{}}"#).is_err());
        assert!(decode_outcome(Provider::Resend, br#"[null,{}]"#).is_err());
    }
    #[test]
    fn config_requires_loopback_and_secret_headers_remain_sensitive() {
        for bad in [
            "https://127.0.0.1:1",
            "http://example.com",
            "http://127.0.0.1/path",
            "http://user:secret@localhost",
            "http://127.0.0.1/?x=1",
        ] {
            assert!(origin(bad).is_err());
        }
        assert!(origin("http://127.0.0.1:1234").is_ok());
        let config = Config {
            resend_origin: "http://127.0.0.1:1234".into(),
            brevo_origin: "http://127.0.0.1:1235".into(),
            mode: WorkerMode::Disabled,
            policies: vec![],
            probe_directory: None,
        };
        assert!(config.validate::<Services>().is_ok());
        let secret =
            ApiKeySecret::from_bytes(br#"{"api_key":"PUBLIC_TEST_PRIVATE"}"#.to_vec()).unwrap();
        for provider in [Provider::Resend, Provider::Brevo] {
            let header = auth_header(provider, &secret).unwrap();
            assert!(header.is_sensitive());
            assert!(!format!("{header:?}").contains("PUBLIC_TEST_PRIVATE"));
        }
    }
}
