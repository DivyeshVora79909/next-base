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
pub const EMAIL_SEND: u16 = 1002;
pub const IDENTITY: u16 = 1003;
pub const AUTH_DELIVERY: u16 = 1004;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Input {
    Credential(Metadata),
    EmailSend(crate::email::SendInput),
    Identity(crate::authentication::types::Input),
    AuthDelivery(crate::authentication::proof_types::AuthDelivery),
}
impl Input {
    pub(crate) fn credential(&self) -> Result<&Metadata> {
        match self {
            Self::Credential(metadata) => Ok(metadata),
            _ => Err(Error::new("invalid_input", "credential source required")),
        }
    }
    #[cfg(test)]
    pub(crate) fn credential_mut(&mut self) -> &mut Metadata {
        match self {
            Self::Credential(metadata) => metadata,
            _ => panic!("credential source required"),
        }
    }
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum System {
    Credential(Derived),
    Identity(crate::authentication::types::State),
}
impl System {
    pub fn credential(&self) -> Result<&Derived> {
        match self {
            Self::Credential(state) => Ok(state),
            Self::Identity(_) => Err(Error::new(
                "corrupt_state",
                "credential system state required",
            )),
        }
    }
    #[cfg(test)]
    pub(crate) fn credential_mut(&mut self) -> &mut Derived {
        match self {
            Self::Credential(state) => state,
            _ => panic!("credential state required"),
        }
    }
}

impl NativeInput for Input {
    fn contract(&self) -> u16 {
        match self {
            Self::Credential(_) => CREDENTIAL,
            Self::EmailSend(_) => EMAIL_SEND,
            Self::Identity(_) => IDENTITY,
            Self::AuthDelivery(_) => AUTH_DELIVERY,
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Credential(metadata) => metadata.validate(),
            Self::EmailSend(email) => email.validate(),
            Self::Identity(identity) => identity.validate(),
            Self::AuthDelivery(delivery) => delivery.validate(),
        }
    }
    fn bind(code: u16, fields: Value) -> Result<Self> {
        match code {
            CREDENTIAL => {
                let metadata: Metadata = serde_json::from_value(fields.clone()).map_err(|_| {
                    Error::new("invalid_input", "complete credential metadata required")
                })?;
                metadata.validate()?;
                if serde_json::to_value(&metadata).map_err(crate::local::storage)? != fields {
                    return Err(Error::new(
                        "invalid_input",
                        "canonical credential metadata required",
                    ));
                }
                Ok(Self::Credential(metadata))
            }
            EMAIL_SEND => Ok(Self::EmailSend(crate::email::SendInput::bind(fields)?)),
            IDENTITY => Ok(Self::Identity(crate::authentication::types::Input::bind(
                fields,
            )?)),
            AUTH_DELIVERY => {
                let delivery: crate::authentication::proof_types::AuthDelivery =
                    serde_json::from_value(fields.clone()).map_err(|_| {
                        Error::new("invalid_input", "private authentication delivery required")
                    })?;
                delivery.validate()?;
                if serde_json::to_value(&delivery).map_err(crate::local::storage)? != fields {
                    return Err(Error::new(
                        "invalid_input",
                        "canonical authentication delivery required",
                    ));
                }
                Ok(Self::AuthDelivery(delivery))
            }
            _ => Err(Error::new("invalid_input", "unknown services contract")),
        }
    }
    fn references(&self) -> Vec<(Uuid, u16, u16)> {
        vec![]
    }
}

impl Binding for Services {
    type Index = Standard;
    type Input = Input;
    type Derived = System;
    type Outcome = crate::email::EmailOutcome;
    const NAME: &'static str = "services";
    const BEHAVIOR: &'static str = "services-private-auth-delivery-pinned-server-authority-4";
    fn engine() -> Result<Model> {
        Ok(Model::from_behavior(Self::NAME, Self::BEHAVIOR))
    }
    fn declarations() -> Result<Vec<Contract>> {
        let mut schema = Metadata::schema();
        schema["$schema"] = json!(crate::model::SCHEMA_DIALECT);
        Ok(vec![
            Contract {
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
            },
            Contract {
                code: EMAIL_SEND,
                name: "EmailSend",
                visibility: Visibility::Public,
                schema: {
                    let mut schema = crate::email::SendInput::schema();
                    schema["$schema"] = json!(crate::model::SCHEMA_DIALECT);
                    schema
                },
                fields: ["email", "selection", "execute_at", "not_after"]
                    .into_iter()
                    .enumerate()
                    .map(|(position, name)| InputField {
                        code: position as u16 + 1,
                        name,
                        mutable: false,
                    })
                    .collect(),
                published: vec![],
                access_indexes: vec![Declaration::created(10021)],
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
                    "all authored fields are immutable",
                    "acceptance requires a current purpose-specific credential grant",
                ],
                schema_source: "src/email.rs",
                behavior_source: "src/models/services.rs",
            },
            Contract {
                code: IDENTITY,
                name: "Identity",
                visibility: Visibility::Public,
                schema: {
                    let mut schema = crate::authentication::types::Input::schema();
                    schema["$schema"] = json!(crate::model::SCHEMA_DIALECT);
                    schema
                },
                fields: vec![
                    InputField {
                        code: 1,
                        name: "kind",
                        mutable: false,
                    },
                    InputField {
                        code: 2,
                        name: "value",
                        mutable: true,
                    },
                ],
                published: vec![
                    PublishedField {
                        code: 101,
                        name: "identity_revision",
                        binding: "u64",
                    },
                    PublishedField {
                        code: 102,
                        name: "verified_revision",
                        binding: "option<u64>",
                    },
                    PublishedField {
                        code: 103,
                        name: "verified_at",
                        binding: "option<i64>",
                    },
                ],
                access_indexes: vec![Declaration::created(10031)],
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
                    crate::authentication::types::POLICY,
                    "kind and User owner are immutable",
                    "self management requires current trusted recent authentication",
                    "normalized identity claims are unique within the tenant store",
                ],
                schema_source: "src/authentication/types.rs",
                behavior_source: "src/authentication/mod.rs",
            },
            Contract {
                code: AUTH_DELIVERY,
                name: "AuthDelivery",
                visibility: Visibility::Engine,
                schema: {
                    let mut schema = crate::authentication::proof_types::AuthDelivery::schema();
                    schema["$schema"] = json!(crate::model::SCHEMA_DIALECT);
                    schema
                },
                fields: ["challenge", "generation", "payload", "expires_at"]
                    .into_iter()
                    .enumerate()
                    .map(|(position, name)| InputField {
                        code: position as u16 + 1,
                        name,
                        mutable: false,
                    })
                    .collect(),
                published: vec![],
                access_indexes: vec![],
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
                    "private server-authored ciphertext only",
                    "current challenge and server credential policy authorize dispatch",
                ],
                schema_source: "src/authentication/proof_types.rs",
                behavior_source: "src/authentication/proof.rs",
            },
        ])
    }
    fn valid_derived(input: &Input, derived: Option<&System>) -> bool {
        match (input, derived) {
            (Input::Credential(metadata), Some(System::Credential(state))) => {
                state.validate().is_ok() && (!metadata.enabled || state.has_secret)
            }
            (Input::EmailSend(_) | Input::AuthDelivery(_), None) => true,
            (Input::Identity(_), Some(System::Identity(state))) => state.validate().is_ok(),
            _ => false,
        }
    }
    fn published_shape(code: u16) -> Value {
        match code {
            CREDENTIAL => json!({"has_secret":false,"secret_revision":null,"use_epoch":"0"}),
            IDENTITY => {
                json!({"identity_revision":"1","verified_revision":null,"verified_at":null})
            }
            _ => json!({}),
        }
    }
    fn identity_enabled() -> bool {
        true
    }
    fn identity_input(input: &Input) -> Option<&crate::authentication::types::Input> {
        match input {
            Input::Identity(identity) => Some(identity),
            _ => None,
        }
    }
    fn identity_values(
        record: &crate::native_slice::ModelRecord<Self>,
    ) -> Result<(
        &crate::authentication::types::Input,
        &crate::authentication::types::State,
    )> {
        match (&record.input, record.derived.as_ref()) {
            (Input::Identity(input), Some(System::Identity(state))) => {
                state.validate()?;
                Ok((input, state))
            }
            _ => Err(Error::new(
                "corrupt_state",
                "identity source and system state required",
            )),
        }
    }
    fn credential_values(
        record: &crate::native_slice::ModelRecord<Self>,
    ) -> Result<(&Metadata, &Derived)> {
        let metadata = record.input.credential()?;
        let state = record
            .derived
            .as_ref()
            .ok_or_else(|| Error::new("corrupt_state", "credential system metadata missing"))?
            .credential()?;
        state.validate()?;
        Ok((metadata, state))
    }
    fn email_input(input: &Input) -> Option<&crate::email::SendInput> {
        match input {
            Input::EmailSend(email) => Some(email),
            _ => None,
        }
    }
    fn auth_delivery(input: &Input) -> Option<&crate::authentication::proof_types::AuthDelivery> {
        match input {
            Input::AuthDelivery(delivery) => Some(delivery),
            _ => None,
        }
    }
    fn effect_actions() -> Vec<crate::effects::ActionDeclaration> {
        vec![
            crate::effects::ActionDeclaration {
                code: EMAIL_SEND,
                name: "EmailSend",
                version: "email-send-1",
                source_contract: EMAIL_SEND,
                reference_slot: 0,
                target_contract: EMAIL_SEND,
                provider_account: "credential",
                application_fields: vec![],
                authority: crate::effects::ActionAuthority::SourceUse,
            },
            crate::effects::ActionDeclaration {
                code: AUTH_DELIVERY,
                name: "AuthDelivery",
                version: "auth-delivery-1",
                source_contract: AUTH_DELIVERY,
                reference_slot: 0,
                target_contract: AUTH_DELIVERY,
                provider_account: "credential",
                application_fields: vec![],
                authority: crate::effects::ActionAuthority::Authentication,
            },
        ]
    }
    fn effect_request_limit() -> usize {
        65536
    }
    fn effect_template(input: &Input) -> Result<Option<crate::effects::Template>> {
        Ok(match input {
            Input::EmailSend(email) => Some(crate::effects::Template {
                target: Uuid::nil(),
                execute_at: email.execute_at,
                not_after: email.not_after,
            }),
            Input::AuthDelivery(delivery) => Some(crate::effects::Template {
                target: Uuid::nil(),
                execute_at: None,
                not_after: Some(delivery.expires_at),
            }),
            _ => None,
        })
    }
    fn effect_outcome(
        request: &Input,
        execution: Uuid,
        outcome: &Self::Outcome,
    ) -> Result<crate::effects::Disposition> {
        match request {
            Input::EmailSend(email) => outcome.validate(&email.email, execution),
            Input::AuthDelivery(_) => {
                let action =
                    Self::effect_action(AUTH_DELIVERY).expect("compiled authentication action");
                outcome.validate_hash(
                    &crate::effects::hash_request::<Self>(request, &action)?,
                    execution,
                )
            }
            _ => Err(Error::new("invalid_input", "delivery source required")),
        }
    }
    fn effect_outcome_schema() -> Value {
        crate::email::EmailOutcome::schema()
    }
    fn effect_validate_binding(
        outcome: &Self::Outcome,
        provider: crate::credentials::crypto::Provider,
        account: &str,
    ) -> Result<()> {
        outcome.validate_binding(provider, account)
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
        model: &Prepared<Self>,
        context: Context,
        changes: &[ModelChange<Self>],
        revision: Uuid,
        _allocate: &mut dyn FnMut() -> Result<Uuid>,
    ) -> Result<()> {
        crate::authentication::settle_identities(ws, model, context, changes, revision)?;
        for change in changes {
            if change
                .old
                .as_ref()
                .is_some_and(|record| record.contract != CREDENTIAL)
                || ws
                    .record(change.id)?
                    .as_ref()
                    .is_some_and(|record| record.contract != CREDENTIAL)
            {
                continue;
            }
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
            let previous_state = original
                .as_ref()
                .map(Self::credential_values)
                .transpose()?
                .map(|(_, state)| state);
            let previous_revision = previous_state.and_then(|state| state.secret_revision);
            if let Some(secret_revision) = previous_revision {
                match ws.original(&Key::CredentialSecret(change.id, secret_revision))? {
                    Some(StoredValue::CredentialSecret(envelope))
                        if envelope.credential == change.id
                            && envelope.secret_revision == secret_revision
                            && previous_state
                                .is_some_and(|state| state.incarnation == envelope.incarnation) =>
                    {
                        envelope.validate()?
                    }
                    _ => {
                        return Err(Error::new(
                            "corrupt_state",
                            "credential original private inventory",
                        ));
                    }
                }
            }
            // Secret ingress stages the next revision before ordinary settlement.
            // Metadata-only mutations retain the current envelope unchanged.
            let next = previous_revision.unwrap_or(0).checked_add(1);
            let staged = if let Some(next) = next {
                match ws.get(&Key::CredentialSecret(change.id, next))? {
                    Some(StoredValue::CredentialSecret(envelope)) => {
                        if ws
                            .original(&Key::CredentialSecret(change.id, next))?
                            .is_some()
                        {
                            return Err(Error::new(
                                "corrupt_state",
                                "unclaimed credential next revision",
                            ));
                        }
                        Some(envelope)
                    }
                    None => None,
                    _ => return Err(Error::new("corrupt_state", "credential private row role")),
                }
            } else {
                None
            };
            let secret = if staged.is_some() {
                staged
            } else if let Some(secret_revision) = previous_revision {
                match ws.get(&Key::CredentialSecret(change.id, secret_revision))? {
                    Some(StoredValue::CredentialSecret(envelope)) => Some(envelope),
                    _ => {
                        return Err(Error::new(
                            "corrupt_state",
                            "credential current envelope missing",
                        ));
                    }
                }
            } else {
                None
            };
            let Some(mut current) = ws.record(change.id)? else {
                continue;
            };
            let metadata = current.input.credential()?;
            metadata.validate()?;
            let epoch = if let Some(previous) = &change.old {
                let (old_metadata, state) = Self::credential_values(previous)?;
                if old_metadata.provider != metadata.provider
                    || old_metadata.account != metadata.account
                {
                    return Err(Error::new(
                        "invalid_input",
                        "credential provider and account are immutable",
                    ));
                }
                let changed = previous.owner != current.owner
                    || old_metadata.enabled != metadata.enabled
                    || old_metadata.scopes != metadata.scopes;
                state
                    .use_epoch
                    .checked_add(u64::from(changed))
                    .ok_or_else(|| Error::new("revision_exhausted", "credential use epoch"))?
            } else {
                0
            };
            let incarnation = previous_state
                .map(|state| state.incarnation)
                .or_else(|| secret.as_ref().map(|secret| secret.incarnation))
                .unwrap_or(revision);
            if let Some(secret) = &secret {
                secret.validate()?;
                if secret.credential != change.id || secret.incarnation != incarnation {
                    return Err(Error::new("corrupt_state", "credential private identity"));
                }
            }
            if metadata.enabled && secret.is_none() {
                return Err(Error::new(
                    "invariant",
                    "enabled credential requires a secret",
                ));
            }
            current.derived = Some(System::Credential(Derived {
                incarnation,
                has_secret: secret.is_some(),
                secret_revision: secret.as_ref().map(|secret| secret.secret_revision),
                use_epoch: epoch,
            }));
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
        let pins = crate::credentials::store::pinned_revisions::<Self>(
            &snapshot.read.open_table(crate::effects::EXECUTIONS)?,
        )?;
        let mut required = std::collections::BTreeSet::new();
        for (&id, record) in &snapshot.records {
            record.input.validate()?;
            if let Input::Credential(metadata) = &record.input {
                require(record.contract == CREDENTIAL, "credential source contract")?;
                let (_, state) = Self::credential_values(record)?;
                require(
                    !metadata.enabled || state.has_secret,
                    "enabled credential without a secret",
                )?;
                if let Some(revision) = state.secret_revision {
                    required.insert((id, revision));
                }
            } else if let Input::Identity(_) = &record.input {
                require(record.contract == IDENTITY, "identity source contract")?;
                Self::identity_values(record)?;
            } else {
                require(
                    matches!(
                        (record.contract, &record.input),
                        (EMAIL_SEND, Input::EmailSend(_)) | (AUTH_DELIVERY, Input::AuthDelivery(_))
                    ) && record.derived.is_none(),
                    "delivery source contract",
                )?;
            }
        }
        for (&key, binding) in &pins {
            let record = snapshot
                .records
                .get(&key.0)
                .ok_or_else(|| Error::new("corrupt_state", "retained credential source missing"))?;
            let (metadata, state) = Self::credential_values(record)?;
            require(
                state.incarnation == binding.incarnation()
                    && metadata.provider == binding.provider()
                    && metadata.account == binding.account(),
                "retained credential identity",
            )?;
            required.insert(key);
        }
        for (id, revision) in required {
            let key = Key::CredentialSecret(id, revision);
            let record = &snapshot.records[&id];
            let (_, state) = Self::credential_values(record)?;
            match snapshot.all.get(&key) {
                Some(StoredValue::CredentialSecret(envelope)) => {
                    envelope.validate()?;
                    require(
                        envelope.credential == id
                            && envelope.secret_revision == revision
                            && envelope.incarnation == state.incarnation
                            && state
                                .secret_revision
                                .is_some_and(|current| revision <= current),
                        "credential source/private revision",
                    )?;
                    expected.insert(key);
                }
                _ => return Err(Error::new("corrupt_state", "credential private inventory")),
            }
        }
        if snapshot
            .records
            .values()
            .any(|record| Self::identity_input(&record.input).is_some())
            || snapshot
                .all
                .keys()
                .any(|key| matches!(key, Key::AuthenticationRevision(_)))
        {
            crate::authentication::check(&snapshot, &mut expected)?;
        }
        snapshot.finish(
            expected,
            BTreeMap::new(),
            snapshot.routes.clone(),
            BTreeMap::new(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::types::{Kind, State};

    #[test]
    fn private_delivery_is_unindexed_unreferenced_and_absent_from_public_contracts() {
        let prepared = Prepared::<Services>::load().unwrap();
        let contract = prepared.contract(AUTH_DELIVERY).unwrap();
        assert_eq!(contract.visibility, Visibility::Engine);
        assert!(contract.fields.iter().all(|field| !field.mutable));
        assert!(contract.access_indexes.is_empty());
        assert!(contract.references.is_empty());
        assert!(contract.published.is_empty());
        assert!(prepared.public_contract(AUTH_DELIVERY).is_err());
        let catalog = prepared.public_catalog();
        assert!(
            catalog["contracts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|contract| contract["code"] != AUTH_DELIVERY)
        );
        let actions = Services::effect_actions();
        assert_eq!(actions.len(), 2);
        let private = Services::effect_action(AUTH_DELIVERY).unwrap();
        assert_eq!(
            private.authority,
            crate::effects::ActionAuthority::Authentication
        );
        assert!(!private.public());
        assert!(!private.application_required());
        assert!(private.source_anchor());
        assert!(Services::effect_action(EMAIL_SEND).unwrap().public());
        assert!(Services::effect_action(65535).is_none());
    }

    #[test]
    fn authentication_hash_binds_randomized_ciphertext_and_immutable_delivery_metadata() {
        use crate::authentication::{proof_crypto::Crypto, proof_types::AuthDelivery};
        let crypto = Crypto::test_key("test-proof", [8; 32]);
        let email = crate::email::EmailRequest {
            sender: "proof@example.test".into(),
            to: vec!["person@example.test".into()],
            subject: "Verification code".into(),
            text: "000042".into(),
        };
        let plaintext = serde_json::to_vec(&email).unwrap();
        let delivery = AuthDelivery {
            challenge: Uuid::from_u128(21),
            generation: Uuid::from_u128(22),
            payload: crypto.seal(&"delivery-test", &plaintext).unwrap(),
            expires_at: 300_000,
        };
        let input = Input::AuthDelivery(delivery.clone());
        assert!(input.references().is_empty());
        assert!(Services::email_input(&input).is_none());
        assert!(Services::valid_derived(&input, None));
        let value = serde_json::to_value(&input).unwrap();
        assert_eq!(Input::bind(AUTH_DELIVERY, value.clone()).unwrap(), input);
        assert!(Input::bind(EMAIL_SEND, value.clone()).is_err());
        let action = Services::effect_action(AUTH_DELIVERY).unwrap();
        let hash = crate::effects::hash_request::<Services>(&input, &action).unwrap();
        assert_ne!(hash, email.request_hash().unwrap());
        for field in 0..4 {
            let mut changed = delivery.clone();
            match field {
                0 => changed.challenge = Uuid::from_u128(23),
                1 => changed.generation = Uuid::from_u128(24),
                2 => changed.expires_at += 1,
                _ => changed.payload = crypto.seal(&"delivery-test", &plaintext).unwrap(),
            }
            let changed = Input::AuthDelivery(changed);
            assert_ne!(
                hash,
                crate::effects::hash_request::<Services>(&changed, &action).unwrap()
            );
        }
        let mut changed_action = action.clone();
        changed_action.version = "auth-delivery-changed";
        assert_ne!(
            hash,
            crate::effects::hash_request::<Services>(&input, &changed_action).unwrap()
        );
        let serialized = value.to_string();
        for secret in ["000042", "person@example.test", "proof@example.test"] {
            assert!(!serialized.contains(secret));
            assert!(!format!("{input:?}").contains(secret));
        }
        let mut malformed = value;
        malformed["expires_at"] = json!(300_000);
        assert!(Input::bind(AUTH_DELIVERY, malformed).is_err());
    }

    #[test]
    fn services_system_variants_keep_flat_wire_objects_and_reject_crossed_roles() {
        let credential=Input::Credential(serde_json::from_value(json!({"label":"Fixture","provider":"resend","account":"fixture","enabled":true,"scopes":["email.send"]})).unwrap());
        let identity = Input::bind(
            IDENTITY,
            json!({"kind":"email","value":" Person@EXAMPLE.COM "}),
        )
        .unwrap();
        assert_eq!(
            identity,
            Input::Identity(crate::authentication::types::Input {
                kind: Kind::Email,
                value: "person@example.com".into()
            })
        );
        let credential_state = System::Credential(Derived {
            incarnation: Uuid::from_u128(1),
            has_secret: true,
            secret_revision: Some(7),
            use_epoch: 9,
        });
        let identity_state = System::Identity(State::new(Uuid::from_u128(2)).unwrap());
        assert_eq!(
            serde_json::to_value(&credential_state).unwrap(),
            json!({"incarnation":Uuid::from_u128(1),"has_secret":true,"secret_revision":"7","use_epoch":"9"})
        );
        assert_eq!(
            serde_json::to_value(&identity_state).unwrap(),
            json!({"incarnation":Uuid::from_u128(2),"identity_revision":"1","verified_revision":null,"verified_at":null})
        );
        assert!(Services::valid_derived(
            &credential,
            Some(&credential_state)
        ));
        assert!(Services::valid_derived(&identity, Some(&identity_state)));
        assert!(!Services::valid_derived(&credential, Some(&identity_state)));
        assert!(!Services::valid_derived(&identity, Some(&credential_state)));
        assert!(!Services::valid_derived(&identity, None));
        for system in [credential_state, identity_state] {
            let value = serde_json::to_value(&system).unwrap();
            assert_eq!(
                serde_json::from_value::<System>(value.clone()).unwrap(),
                system
            );
            let mut hybrid = value;
            hybrid["unexpected_state"] = json!(true);
            assert!(serde_json::from_value::<System>(hybrid).is_err());
        }
        assert!(
            Input::bind(
                CREDENTIAL,
                json!({"kind":"email","value":"person@example.com"})
            )
            .is_err()
        );
        assert!(Input::bind(IDENTITY, serde_json::to_value(credential).unwrap()).is_err());
        let public = Services::published_shape(IDENTITY);
        assert_eq!(
            public,
            json!({"identity_revision":"1","verified_revision":null,"verified_at":null})
        );
        assert!(public.get("incarnation").is_none());
    }
}
