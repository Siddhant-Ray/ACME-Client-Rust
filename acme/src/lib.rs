use error::Error;
use log::info;
use openssl::{
    pkey::{Private, Public},
    rsa::Rsa,
    x509::X509Req,
};
use reqwest::blocking::Client;
use acc::{Certificate, Directory};
use util::generate_rsa_key;


// Common error module
pub mod error;
// All account creation and management
mod acc;
// Contains utility methods used in the acme context. 
pub mod util;

const KEY_WIDTH: u32 = 2048;

// Generate certificate for a given domain



