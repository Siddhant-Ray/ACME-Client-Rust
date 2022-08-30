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

// Generate certificate for a given domain.
pub fn generate_certificate_for_domain<T: AsRef<str>>(
    keypair_for_cert: &(Rsa<Private>, Rsa<Public>),
    optional_csr: Option<X509Req>,
    domain: T,
    server: T,
    email: T,
    standalone: bool,
    verbose: bool,
) -> Result<Certificate, Error> {
    let keypair = generate_rsa_key()?;
    // create a new client 
    let client = Client::new();

    // fetch the directory and create a new account
    let dir_infos = Directory::fetch_dir(&client, server.as_ref())?;
    let new_acc = dir_infos.create_account(&client, &keypair, email.as_ref())?;
    if verbose {
        info!("Created account: {:#?}", new_acc);
    }

    // create a new order
    let order = new_acc.create_new_order(
        &client,
        &dir_infos.new_order,
        &keypair,
        domain.as_ref(),
        optional_csr,
    )?;
    if verbose {
        info!(
            "Opened new order for domain {}: {:#?}",
            domain.as_ref(),
            &order
        );
    }

    // fetch the auth challenges
    let challenge = order.fetch_auth_challenges(&client, &new_acc.account_location, &keypair)?;
    if verbose {
        info!(
            "Got the following authorization challenges: {:#?}",
            &challenge
        );
    }

    // complete the challenge and save the nonce that's needed for further authentification
    let new_nonce = challenge.solve_http_challenge(
        &client,
        &new_acc.account_location,
        &keypair,
        standalone,
    )?;
    if verbose {
        info!("Succesfully completed the http challenge");
    }

    // finalize the order to retrieve location of the final cert
    let updated_order = order.finalize_order(
        &client,
        &new_acc.account_location,
        new_nonce,
        &keypair,
        keypair_for_cert,
        domain.as_ref(),
    )?;

    // download the certificate
    let cert_chain =
        updated_order.download_certificate(&client, &new_acc.account_location, &keypair)?;
    if verbose {
        info!("Received the following certificate chain: {}", cert_chain);
    }

    Ok(cert_chain)
}


