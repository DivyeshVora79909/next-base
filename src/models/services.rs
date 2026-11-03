//! Credential metadata and private envelopes share the ordinary source transaction.
use crate::{
    access_index::Declaration,
    binding::{Binding, NativeInput},
    credentials::crypto::Metadata,
    indexes::standard::Standard,
    integrity::{Snapshot, require},
    local::Store,
    model::{Contract, InputField, Prepared, PublishedField, Visibility},
    native_codec::{Key, StoredValue, decimal, optional_decimal, uuid_text},
    native_slice::{Attempt, Context, Error, Model, ModelChange, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const CREDENTIAL: u16 = 1001;
pub type Input = Metadata;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Services;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Derived {
    /// Stable internal identity for this lifetime; omitted from public projections.
    #[serde(with = "uuid_text")]
    pub incarnation: Uuid,
    pub has_secret: bool,
    #[serde(with = "optional_decimal")]
    pub secret_revision: Option<u64>,
    #[serde(with = "decimal")]
    pub use_epoch: u64,
}
impl Derived {
    pub fn validate(&self) -> Result<()> {
        if self.incarnation.is_nil()
            || self.has_secret != self.secret_revision.is_some()
            || self.secret_revision == Some(0)
        {
            return Err(Error::new("corrupt_state", "credential system metadata"));
        }
        Ok(())
    }
}

impl NativeInput for Metadata {
    fn contract(&self) -> u16 {
        CREDENTIAL
    }
    fn validate(&self) -> Result<()> {
        Metadata::validate(self)
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        let metadata: Self = serde_json::from_value(fields.clone())
            .map_err(|_| Error::new("invalid_input", "complete credential metadata required"))?;
        metadata.validate()?;
        if code != CREDENTIAL
            || serde_json::to_value(&metadata).map_err(crate::local::storage)? != fields
        {
            return Err(Error::new(
                "invalid_input",
                "canonical credential metadata required",
            ));
        }
        Ok(metadata)
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        vec![]
    }
}

impl Binding for Services {
    type Index = Standard;
    type Input = Input;
    type Derived = Derived;
    type Outcome = ();
    const NAME: &'static str = "services";
    const BEHAVIOR: &'static str = "services-credential-current-envelope-incarnation-1";
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn declarations() -> Result<Vec<Contract>> {
        let mut schema = Metadata::schema();
        schema["$schema"] = json!(crate::model::SCHEMA_DIALECT);
        Ok(vec![Contract {
            code: CREDENTIAL,
            name: "Credential",
            visibility: Visibility::Public,
            schema,
            fields: ["label", "provider", "account", "enabled", "scopes"]
                .into_iter()
                .enumerate()
                .map(|(position, name)| InputField {
                    code: position as u16 + 1,
                    name,
                    mutable: !matches!(name, "provider" | "account"),
                })
                .collect(),
            published: vec![
                PublishedField {
                    code: 101,
                    name: "has_secret",
                    binding: "bool",
                },
                PublishedField {
                    code: 102,
                    name: "secret_revision",
                    binding: "option<u64>",
                },
                PublishedField {
                    code: 103,
                    name: "use_epoch",
                    binding: "u64",
                },
            ],
            access_indexes: vec![Declaration::created(10011)],
            uniqueness: vec![],
            publication_inputs: vec![],
            references: vec![],
            roots: vec![],
            memberships: vec![],
            queries: vec![],
            outputs: vec![],
            calculations: vec![],
            calculation_order: vec![],
            rules: vec![
                "provider and account are immutable",
                "enabled credentials require a current private envelope",
                "disable enable owner or scope changes advance use_epoch once",
            ],
            schema_source: "src/credentials/crypto.rs",
            behavior_source: "src/models/services.rs",
        }])
    }
    fn valid_derived(input: &Input, derived: Option<&Derived>) -> bool {
        derived
            .is_some_and(|state| state.validate().is_ok() && (!input.enabled || state.has_secret))
    }
    fn published_shape(_code: u16) -> Value {
        json!({"has_secret":false,"secret_revision":null,"use_epoch":"0"})
    }
    fn credential_enabled() -> bool {
        true
    }
    fn credential_operation(
        store: &Store<Self>,
        runtime: &crate::credentials::grants::Runtime,
        operation: crate::credentials::Operation,
    ) -> Result<Value> {
        match operation {
            crate::credentials::Operation::WriteSecret(request) => {
                store.write_secret(runtime.crypto(), &request)
            }
            crate::credentials::Operation::AuthorizeEmail(request) => {
                serde_json::to_value(store.authorize_email(runtime, &request)?)
                    .map_err(crate::local::storage)
            }
        }
    }
    fn credential_operator(
        store: &Store<Self>,
        crypto: Option<&crate::credentials::crypto::Crypto>,
        operation: crate::credentials::Operator,
    ) -> Result<Value> {
        match operation {
            crate::credentials::Operator::RewrapPlan(ids) => {
                serde_json::to_value(store.credential_rewrap_plan(&ids)?)
                    .map_err(crate::local::storage)
            }
            crate::credentials::Operator::Rewrap(request) => store.rewrap_credentials(
                crypto.ok_or_else(|| Error::new("credential_keys", "credential keys required"))?,
                &request,
            ),
            crate::credentials::Operator::VerifyCustody => store.verify_credential_custody(
                crypto.ok_or_else(|| Error::new("credential_keys", "credential keys required"))?,
            ),
        }
    }
    fn settle_changes<L: FnMut(&[u8]) -> Result<Option<Vec<u8>>>>(
        ws: &mut Attempt<L, Self>,
        _model: &Prepared<Self>,
        _context: Context,
        changes: &[ModelChange<Self>],
        revision: Uuid,
        _allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        for change in changes {
            let key = Key::CredentialSecret(change.id);
            let original = match ws.original(&Key::Record(change.id))? {
                Some(StoredValue::Record(record)) => Some(record),
                None => None,
                _ => {
                    return Err(Error::new(
                        "corrupt_state",
                        "credential original source role",
                    ));
                }
            };
            let previous_revision = original
                .as_ref()
                .map(|record| -> Result<Option<u64>> {
                    let state = record.derived.as_ref().ok_or_else(|| {
                        Error::new("corrupt_state", "credential system metadata missing")
                    })?;
                    state.validate()?;
                    Ok(state.secret_revision)
                })
                .transpose()?
                .flatten();
            match (previous_revision, ws.original(&key)?) {
                (None, None) => {}
                (Some(revision), Some(StoredValue::CredentialSecret(envelope)))
                    if envelope.credential == change.id && envelope.secret_revision == revision =>
                {
                    envelope.validate()?;
                }
                _ => {
                    return Err(Error::new(
                        "corrupt_state",
                        "credential original private inventory",
                    ));
                }
            }
            let secret = match ws.get(&key)? {
                Some(StoredValue::CredentialSecret(envelope)) => Some(envelope),
                None => None,
                _ => return Err(Error::new("corrupt_state", "credential private row role")),
            };
            let Some(mut current) = ws.record(change.id)? else {
                ws.put(key, None)?;
                continue;
            };
            current.input.validate()?;
            let epoch = if let Some(previous) = &change.old {
                if previous.input.provider != current.input.provider
                    || previous.input.account != current.input.account
                {
                    return Err(Error::new(
                        "invalid_input",
                        "credential provider and account are immutable",
                    ));
                }
                let state = previous.derived.as_ref().ok_or_else(|| {
                    Error::new("corrupt_state", "credential system metadata missing")
                })?;
                state.validate()?;
                let changed = previous.owner != current.owner
                    || previous.input.enabled != current.input.enabled
                    || previous.input.scopes != current.input.scopes;
                state
                    .use_epoch
                    .checked_add(u64::from(changed))
                    .ok_or_else(|| Error::new("revision_exhausted", "credential use epoch"))?
            } else {
                0
            };
            if let Some(secret) = &secret {
                secret.validate()?;
                if secret.credential != change.id {
                    return Err(Error::new("corrupt_state", "credential private identity"));
                }
            }
            if current.input.enabled && secret.is_none() {
                return Err(Error::new(
                    "invariant",
                    "enabled credential requires a secret",
                ));
            }
            current.derived = Some(Derived {
                incarnation: change
                    .old
                    .as_ref()
                    .and_then(|record| record.derived.as_ref())
                    .map_or(revision, |state| state.incarnation),
                has_secret: secret.is_some(),
                secret_revision: secret.as_ref().map(|secret| secret.secret_revision),
                use_epoch: epoch,
            });
            ws.put(Key::Record(change.id), Some(StoredValue::Record(current)))?;
        }
        Ok(())
    }
    fn fixture_catalog() -> Value {
        json!([{"name":"credential-metadata","description":"Disabled credential metadata without a provider secret"}])
    }
    fn fixture_plan(model: &Prepared<Self>, name: &str, namespace: Uuid) -> Result<Value> {
        if name != "credential-metadata" {
            return Err(Error::new("invalid_input", "unknown services fixture"));
        }
        let id = Uuid::new_v5(&namespace, b"services/credential-metadata");
        let fields = json!({"label":"Mail credential","provider":"resend","account":"fixture-mail","enabled":false,"scopes":["email.send"]});
        model.validate(CREDENTIAL, &fields)?;
        Ok(
            json!({"model":model.identity(),"fixture":{"name":name,"namespace":namespace},
            "commands":[{"op":"create","id":id,"contract":CREDENTIAL,"fields":fields}],"returning":[id]}),
        )
    }
    fn check(store: &Store<Self>) -> Result<Value> {
        let snapshot = Snapshot::load(store)?;
        let mut expected = snapshot.expected_keys.clone();
        for (&id, record) in &snapshot.records {
            record.input.validate()?;
            require(record.contract == CREDENTIAL, "credential source contract")?;
            let state = record
                .derived
                .as_ref()
                .ok_or_else(|| Error::new("corrupt_state", "credential system metadata missing"))?;
            state.validate()?;
            require(
                !record.input.enabled || state.has_secret,
                "enabled credential without a secret",
            )?;
            let key = Key::CredentialSecret(id);
            match (state.secret_revision, snapshot.all.get(&key)) {
                (Some(revision), Some(StoredValue::CredentialSecret(envelope))) => {
                    envelope.validate()?;
                    require(
                        envelope.credential == id && envelope.secret_revision == revision,
                        "credential source/private revision",
                    )?;
                    expected.insert(key);
                }
                (None, None) => {}
                _ => return Err(Error::new("corrupt_state", "credential private inventory")),
            }
        }
        snapshot.finish(
            expected,
            BTreeMap::new(),
            snapshot.routes.clone(),
            BTreeMap::new(),
        )
    }
}
