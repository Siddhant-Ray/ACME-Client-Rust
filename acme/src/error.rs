use std::io;
use thiserror::Error;

use openssl::error::ErrorStack;
use reqwest::header::ToStrError;

#[derive(Error, Debug)]

pub enum Error {
    #[error("Account does not exist")]
    AccountDoesNotExist,
    #[error("Certificate thas already been revoked")]
    AlreadyRevokedCertificate,
    #[error("The CSR is unacceptable")]
    BadCSR,
    #[error("Unacceptable anti-replay nonce")]
    BadNonce,
    #[error("Server does not support PKey")]
    BadPublicKey,
    #[error("Revocation reason provided is not allowed")]
    BadRevocationReason,
    #[error("Signing with an algorithm not supported")]
    BadSignatureAlgorithm,
    #[error("CAA records forbid the CA from issuing a certificate")]
    CaaError,
    #[error("Specific error conditions are indicated in the \"subproblems\" array")]
    Compound,
    #[error("Server could not connect to validation target")]
    Connection,
    #[error("Problem with a DNS query")]
    DnsError,
    #[error("The request must include a value for the \"externalAccountBinding\" field")]
    ExternalAccountRequired,
    #[error("Response received didn't match the challenge's requirements")]
    IncorrectResponse,
    #[error("Invalid contact URL for account")]
    InvalidContact,
    #[error("The request message was malformed")]
    MalformedRequest,
    #[error("Finalize an order that is not ready to be finalized")]
    OrderNotReady,
    #[error("Exceeds rate limit")]
    RateLimited,
    #[error("Not issue certificates for the identifier")]
    RejectedIdentifier,
    #[error("Internal error")]
    InternalServerError,
    #[error("TLS error during validation")]
    TlsError,
    #[error("Insufficient authorization")]
    Unauthorized,
    #[error("Unsupported protocol scheme")]
    UnsupportedContact,
    #[error("Unsupported type identifier")]
    UnsupportedIdentifier,
    #[error("Visit the \"instance\" URL and take actions specified there")]
    UserActionRequired,
    #[error("Error reading the string: {0}")]
    FromUtf8Error(#[from] std::str::Utf8Error),
    #[error("Error in reqwest: {0}")]
    FromReqwestError(#[from] reqwest::Error),
    #[error("Error in openssl: {0}")]
    FromRsaError(#[from] ErrorStack),
    #[error("Error while de/encoding json: {0}")]
    FromSerdeError(#[from] serde_json::Error),
    #[error("Error writing header value: {0}")]
    FromToStrError(#[from] ToStrError),
    #[error("IO error {0}")]
    FromIoError(#[from] io::Error),
    #[error("Currently just http challenges are allowed, so this error is raised if no http challenge is present")]
    NoHttpChallengePresent,
    #[error("There was no web server found")]
    NoWebServer,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
