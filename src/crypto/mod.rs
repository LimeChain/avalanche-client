use once_cell::sync::Lazy;
use ring::rand::SystemRandom;

pub mod ecdsa;
pub mod error;
pub mod rsa;

#[cfg(not(windows))]
static RANDOM: Lazy<SystemRandom> = Lazy::new(SystemRandom::new);
