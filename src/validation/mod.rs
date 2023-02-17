//! Support RPKI and repository content validation.
//!
//! The code in this module is intended to support content (pre-)validation
//! for use in the Krill tool suite (krill-sync, krill publication server)
//! and for automated testing.
//!
//! It is not intended to provide a full stand-alone fully featured RPKI
//! validator such as Routinator, FORT, etc. We only implement what we
//! need here - e.g. we do not support rsync fetching.
//!

mod report;
pub use self::report::*;

mod tal;
pub use self::tal::*;

mod validator;
pub use self::validator::*;
