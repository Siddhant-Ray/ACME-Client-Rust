use std::net::TcpStream;

use base64::encode_config;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::Signer,
    x509::X509Req,
};
use reqwest::blocking::Response;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::{
    error::{Error, Result},
    acc::{Certificate, Nonce},
    KEY_WIDTH,
};

pub fn check_for_existing_server() -> bool {
    // These will parse so it's okay to unwrap here.
    let addrs = [
        "0.0.0.0:80".parse().unwrap(),
        "127.0.0.1:80".parse().unwrap(),
    ];

    TcpStream::connect(&addrs[..]).is_ok()
}

// Generates a `RSA` private key.
pub(crate) fn generate_rsa_key() -> Result<Rsa<Private>> {
    Ok(Rsa::generate(KEY_WIDTH)?)
}

// Generate a key pair.
pub fn generate_rsa_keypair() -> Result<(Rsa<Private>, Rsa<Public>)> {
    let rsa_key = generate_rsa_key()?;
    Ok((
        Rsa::private_key_from_pem(&rsa_key.private_key_to_pem()?)?,
        Rsa::public_key_from_pem(&rsa_key.public_key_to_pem()?)?,
    ))
}

// Create a jwk from a private key.
pub(crate) fn jwk(key: &PKey<Private>) -> Result<serde_json::Value> {
    let rsa_key = key.rsa()?;
    let n = encode_config(&rsa_key.n().to_vec(), base64::URL_SAFE_NO_PAD);
    let e = encode_config(&rsa_key.e().to_vec(), base64::URL_SAFE_NO_PAD);

    Ok(json!({
        "kty": "RSA",
        "n": n,
        "e": e,
    }))
}

// Construct a JSON Web Signature.
pub fn jws(
    payload: serde_json::Value,
    header: serde_json::Value,
    private_key: &Rsa<Private>,
) -> Result<serde_json::Value> {
    // edge case when the payload needs to be empty, e.g. for
    // fetching the challenges or downloading the certificate
    let empty_payload = payload == json!("");

    let payload64 = b64(serde_json::to_string_pretty(&payload)?.as_bytes());
    let header64 = b64(serde_json::to_string_pretty(&header)?.as_bytes());

    let p_key = PKey::private_key_from_pem(&private_key.private_key_to_pem()?)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &p_key)?;

    signer.set_rsa_padding(Padding::PKCS1)?;
    if empty_payload {
        signer.update(format!("{}.", header64).as_bytes())?;
    } else {
        signer.update(format!("{}.{}", header64, payload64).as_bytes())?;
    }

    let signature = b64(&signer.sign_to_vec()?);

    Ok(json!({
        "protected": header64,
        "payload": if empty_payload { "" } else { &payload64 },
        "signature": signature
    }))
}

// Create b64 encoding.
pub fn b64(bytes: &[u8]) -> String {
    encode_config(bytes, base64::URL_SAFE_NO_PAD)
}

// Extract the payload and nonce from a response.
#[inline]
pub(crate) fn extract_payload_and_nonce<T>(response: Response) -> Result<(Nonce, T)>
where
    T: DeserializeOwned,
{
    let replay_nonce = response
        .headers()
        .get("replay-nonce")
        .ok_or(Error::IncorrectResponse)?
        .to_str()?
        .to_owned();

    Ok((replay_nonce, response.json()?))
}

// Extract the location and nonce from a response.
#[inline]
pub(crate) fn extract_payload_location_and_nonce<T>(
    response: Response,
) -> Result<(Nonce, T, String)>
where
    T: DeserializeOwned,
{
    let replay_nonce = response
        .headers()
        .get("replay-nonce")
        .ok_or(Error::IncorrectResponse)?
        .to_str()?
        .to_owned();

    let location = response
        .headers()
        .get("location")
        .ok_or(Error::IncorrectResponse)?
        .to_str()?
        .to_owned();

    Ok((replay_nonce, response.json()?, location))
}

// Load a certificate from a pem file.
pub fn load_csr_from_file(path: &str) -> Result<X509Req> {
    let bytes = std::fs::read(path)?;

    Ok(X509Req::from_pem(&bytes)?)
}

// Parses the certificate and writes them into to files.
pub fn save_certificates(certificate_chain: Certificate) -> Result<()> {
    // extract the first certificat (certificate for the specified domain)
    let cert_me = certificate_chain
        .lines()
        .take_while(|line| !line.is_empty())
        .map(|line| {
            let mut line_with_end = line.to_owned();
            line_with_end.push_str("\r\n");
            line_with_end
        })
        .collect::<String>();

    // save the certs to files
    std::fs::write("my_cert.crt", cert_me.into_bytes())?;
    std::fs::write("cert_chain.crt", certificate_chain.into_bytes())?;

    Ok(())
}

// Save rsa keypair to private and public key files.
pub fn save_keypair(keypair: &(Rsa<Private>, Rsa<Public>)) -> Result<()> {
    let private_key = keypair.0.private_key_to_pem()?;
    let public_key = keypair.1.public_key_to_pem()?;

    std::fs::write("priv.pem", &private_key)?;
    std::fs::write("pub.pem", &public_key)?;

    Ok(())
}

// Load a private and public key from files.
pub fn load_keys_from_file(
    path_to_private: &str,
    path_to_public: &str,
    ) -> Result<(Rsa<Private>, Rsa<Public>)> {
    let priv_key = std::fs::read(path_to_private)?;
    let pub_key = std::fs::read(path_to_public)?;

    Ok((
        Rsa::private_key_from_pem(&priv_key)?,
        Rsa::public_key_from_pem(&pub_key)?,
    ))
}


