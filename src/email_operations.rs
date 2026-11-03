//! Email acceptance uses the ordinary source transaction; bearer evidence is transient.
use crate::{
    binding::Binding,
    credentials::grants::Runtime,
    local::{Mutation, Store},
    native_codec::uuid_text,
    native_slice::{Command, Error, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    #[serde(with = "uuid_text")]
    pub source: Uuid,
    pub grant: String,
}
impl std::fmt::Debug for Authorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorization")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enqueue {
    pub model: String,
    pub context: String,
    #[serde(with = "uuid_text")]
    pub operation_id: Uuid,
    pub commands: Vec<Command>,
    #[serde(with = "crate::local::canonical_ids")]
    pub returning: Vec<Uuid>,
    pub authorizations: Vec<Authorization>,
}
#[derive(Clone, Copy)]
pub(crate) struct Stage<'a> {
    pub runtime: &'a Runtime,
    pub request: &'a Enqueue,
}
impl Enqueue {
    fn mutation(&self) -> Result<Mutation> {
        let mut commands = self.commands.clone();
        let mut sources = BTreeSet::new();
        for command in &mut commands {
            if let Command::Create {
                id,
                contract,
                fields: input,
                ..
            } = command
                && *contract == crate::models::services::EMAIL_SEND
            {
                if !sources.insert(*id) {
                    return Err(invalid());
                }
                let typed: crate::email::SendInput =
                    serde_json::from_value(input.clone()).map_err(|_| invalid())?;
                *input =
                    serde_json::to_value(typed.normalized()?).map_err(crate::local::storage)?;
            }
        }
        if sources.is_empty()
            || sources.len() > 16
            || self.authorizations.len() != sources.len()
            || self
                .authorizations
                .iter()
                .map(|a| a.source)
                .collect::<BTreeSet<_>>()
                != sources
        {
            return Err(invalid());
        }
        Ok(Mutation {
            model: self.model.clone(),
            context: self.context.clone(),
            operation_id: self.operation_id,
            commands,
            returning: self.returning.clone(),
        })
    }
}
fn invalid() -> Error {
    Error::new(
        "invalid_input",
        "email enqueue requires matching source authorizations and canonical intent",
    )
}
impl<B: Binding> Store<B> {
    pub fn enqueue_email(&self, runtime: &Runtime, request: &Enqueue) -> Result<Value> {
        self.enqueue_email_controlled(runtime, request, None, &mut || Ok(()), false)
    }
    pub(crate) fn enqueue_email_controlled(
        &self,
        runtime: &Runtime,
        request: &Enqueue,
        abort: Option<usize>,
        before_commit: &mut dyn FnMut() -> Result<()>,
        lose_response: bool,
    ) -> Result<Value> {
        if !B::credential_enabled()
            || B::effect_action(crate::models::services::EMAIL_SEND)
                .is_none_or(|action| action.authority != crate::effects::ActionAuthority::SourceUse)
        {
            return Err(Error::new(
                "unsupported_query",
                "model has no email service",
            ));
        }
        let mutation = request.mutation()?;
        self.mutate_services(
            &mutation,
            &mut || Ok(Uuid::new_v4()),
            abort,
            before_commit,
            lose_response,
            None,
            Some(Stage { runtime, request }),
        )
    }
}
pub(crate) fn capabilities() -> Value {
    json!({"method":"email.enqueue", "contract":crate::models::services::EMAIL_SEND,
        "intent_schema":crate::email::SendInput::schema(),
        "authorizations_schema":{"type":"array","minItems":1,"maxItems":16,"items":{"type":"object","additionalProperties":false,"required":["source","grant"],"properties":{"source":{"type":"string","format":"uuid"},"grant":{"type":"string"}}}},
        "logical_request":"ordinary normalized mutation envelope; authorization evidence excluded from hash and receipt",
        "limits":{"creates":16,"request_bytes":65536,"effect_request_bytes":65536},
        "secrets":"grants are transient; saved plans contain intent only"})
}
