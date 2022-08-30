use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use core::fmt::Debug;
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{Private, Public},
    rsa::Rsa,
    sha::Sha256,
    x509::{X509NameBuilder, X509Req, X509ReqBuilder},
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    error::{Error, Result},
    util::{
        b64, check_for_existing_server, extract_payload_and_nonce,
        extract_payload_location_and_nonce, jwk, jws,
    },
};

pub type Nonce = String;
pub type Certificate = String;

// The current status of the request. 
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StatusType {
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "invalid")]
    Invalid,
}

// The directory information that get returned in the first request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,
    pub key_change: String,
    #[serde(skip)]
    nonce: Nonce,
}

impl Directory {
    // Fetches the directory information from a specific server. This is the first request
    // that's send to the server as it's return value holds information about the endpoints.
    pub fn fetch_dir(client: &Client, server_url: &str) -> Result<Self> {
        let mut dir_infos: Self = client.get(server_url).send()?.json()?;

        // fetch the new nonce
        let nonce = client
            .head(&dir_infos.new_nonce)
            .send()?
            .headers()
            .get("replay-nonce")
            .ok_or(Error::BadNonce)?
            .to_str()?
            .to_owned();

        dir_infos.nonce = nonce;

        Ok(dir_infos)
    }

    /// Creates a new account.
    pub fn create_account(
        &self,
        client: &Client,
        p_key: &Rsa<Private>,
        email: &str,
    ) -> Result<Account> {
        let jwk = jwk(p_key)?;
        let header = json!({
            "alg": "RS256",
            "url": self.new_account,
            "jwk": jwk,
            "nonce": self.nonce,
        });

        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", email)]
        });

        let payload = jws(payload, header, p_key)?;

        let response = client
            .post(&self.new_account)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&payload)?)
            .send()?;

        let (location, nonce, mut account): (String, Nonce, Account) =
            extract_payload_location_and_nonce(response)?;

        account.nonce = nonce;
        account.account_location = location;

        Ok(account)
    }
}

// A struct that holds information about an Account.
#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub status: String,
    contact: Option<Vec<String>>,
    terms_of_service_agreed: Option<bool>,
    pub orders: Option<Vec<String>>,
    #[serde(skip)]
    pub nonce: Nonce,
    #[serde(skip)]
    pub account_location: String,
}

impl Account {
    // Creates a new order for issuing a dns certificate for a certain domain.
    pub fn create_new_order(
        &self,
        client: &Client,
        new_order_url: &str,
        p_key: &Rsa<Private>,
        domain: &str,
        optional_csr: Option<X509Req>,
    ) -> Result<Order> {
        let header = json!({
            "alg": "RS256",
            "url": new_order_url,
            "kid": self.account_location,
            "nonce": self.nonce,
        });

        let payload = json!({
            "identifiers": [
                { "type": "dns", "value": domain }
            ],
        });

        let payload = jws(payload, header, p_key)?;

        let response = client
            .post(new_order_url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&payload)?)
            .send()?;

        let (nonce, mut order): (Nonce, Order) = extract_payload_and_nonce(response)?;
        order.nonce = nonce;
        order.optional_csr = optional_csr;

        Ok(order)
    }
}

impl Order {
    // Fetches the available authorisation options from the server for a certain order.
    pub fn fetch_auth_challenges(
        &self,
        client: &Client,
        account_url: &str,
        p_key: &Rsa<Private>,
    ) -> Result<ChallengeAuthorisation> {
        let auth_url = self
            .authorizations
            .first()
            .ok_or(Error::NoHttpChallengePresent)?
            .to_string();

        let header = json!({
            "alg": "RS256",
            "url": auth_url,
            "kid": account_url,
            "nonce": self.nonce,
        });

        let payload = json!("");

        let jws = jws(payload, header, p_key)?;

        let response = client
            .post(&auth_url)
            .header("Content-Type", "application/jose+json")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()?;

        let (nonce, mut challenge): (Nonce, ChallengeAuthorisation) =
            extract_payload_and_nonce(response)?;

        challenge.nonce = nonce;

        Ok(challenge)
    }

    /// Finalizes an order whose challenge was already done. This returns an `UpdatedOrder` object which
    /// is able to download the issued certificate. This method `panics` if the challenge was not yet completed.
    pub fn finalize_order(
        self,
        client: &Client,
        account_url: &str,
        new_nonce: Nonce,
        p_key: &Rsa<Private>,
        cert_keypair: &(Rsa<Private>, Rsa<Public>),
        domain: &str,
    ) -> Result<UpdatedOrder> {
        let header = json!({
        "alg": "RS256",
        "url": self.finalize,
        "kid": account_url,
        "nonce": new_nonce,
        });

        let csr = if let Some(csr) = self.optional_csr {
            csr
        } else {
            Order::request_csr(cert_keypair, domain.to_owned())?
        };

        let csr_string = b64(&csr.to_der()?);

        let payload = json!({ "csr": csr_string });

        let jws = jws(payload, header, p_key)?;

        let response = client
            .post(&self.finalize)
            .header("Content-Type", "application/jose+json")
            .header("Accept", "application/pem-certificate-chain")
            .body(serde_json::to_string_pretty(&jws)?)
            .send()?;

        let (nonce, mut updated_order): (Nonce, UpdatedOrder) =
            extract_payload_and_nonce(response)?;

        updated_order.nonce = nonce;

        Ok(updated_order)
    }

    // Factors a csr request, which needs to be sent during finalization.
    fn request_csr(keypair: &(Rsa<Private>, Rsa<Public>), common_name: String) -> Result<X509Req> {
        let mut request = X509ReqBuilder::new()?;
        let mut c_name = X509NameBuilder::new()?;

        let pri_key = &openssl::pkey::PKey::private_key_from_pem(&keypair.0.private_key_to_pem()?)?;
        let public_key =
            &openssl::pkey::PKey::public_key_from_pem(&keypair.1.public_key_to_pem()?)?;

        c_name.append_entry_by_nid(Nid::COMMONNAME, &common_name)?;
        let name = c_name.build();
        request.set_pubkey(public_key)?;
        request.set_subject_name(name.as_ref())?;
        request.sign(pri_key, MessageDigest::sha256())?;

        Ok(request.build())
    }
}

// TODO: Add an implementation for ChallengeAuthorisation and UpdatedOrder.