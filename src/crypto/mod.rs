use ring::rand::SystemRandom;
use once_cell::sync::Lazy;

pub mod ecdsa;
pub mod error;
pub mod rsa;

#[cfg(not(windows))]
static RANDOM: Lazy<SystemRandom> = Lazy::new(SystemRandom::new);
