//! Typed encrypted credential operations in the native source transaction.
pub mod crypto;
pub mod grants;
pub mod lifecycle;
pub mod store;

use crate::{
    binding::Binding,
    native_slice::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub keyring: PathBuf,
    pub platform: Vec<grants::PlatformBinding>,
}
impl Config {
    pub fn validate<B: Binding>(&self) -> Result<()> {
        if !B::credential_enabled() || !self.keyring.is_absolute() {
            return Err(Error::new(
                "invalid_config",
                "credential runtime requires services and an absolute private keyring",
            ));
        }
        grants::PlatformBindings::new(self.platform.clone())?;
        Ok(())
    }
    pub fn load<B: Binding>(&self) -> Result<grants::Runtime> {
        self.validate::<B>()?;
        Ok(grants::Runtime::new(
            Arc::new(crypto::Crypto::load(&self.keyring)?),
            grants::PlatformBindings::new(self.platform.clone())?,
        ))
    }
}

/// Closed compiled calls, never a client-selected function name or closure.
pub enum Operation {
    WriteSecret(store::WriteSecret),
    AuthorizeEmail(grants::AuthorizeRequest),
}

/// Closed operator calls; exposed only through stopped-service host grants.
pub enum Operator {
    RewrapPlan(Vec<uuid::Uuid>),
    Rewrap(lifecycle::RewrapRequest),
    VerifyCustody,
}
