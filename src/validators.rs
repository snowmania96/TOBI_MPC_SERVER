use dkls23::keygen::Keyshare;
// use dkls23::setup::sign::Setup as DSGSetup;
// use dkls23::sign::SignWithRecid;
// use dkls23::sign::ValidatedSetup as SignValidatedSetup;

use simple_setup_msg::keygen::ValidatedSetup as KeygenValidatedSetup;
use std::error::Error;

pub fn post_keygen(_setup: &KeygenValidatedSetup, _share: &Keyshare) -> Result<(), Box<dyn Error>> {
    Ok(())
}
//
// /// Checks the given token against the Redis cache. Performs basic structure tests. Returns the a boolean indicating validity.
// pub fn validate_setup_sign(setup: &DSGSetup) -> bool {
//     true
// }
//
// pub fn post_sign(setup: &SignValidatedSetup, _sign: &SignWithRecid) -> Result<(), Box<dyn Error>> {
//     Ok(())
// }
//
// pub fn handle_failed_signature(setup: &SignValidatedSetup) -> Result<(), Box<dyn Error>> {
//     Ok(())
// }
