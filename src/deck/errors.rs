use core::fmt;
use std::error::Error;

#[derive(Debug)]
#[derive(PartialEq)]
pub enum DeckCustomError {
    InvalidProof,
    InvalidPublicKey,
    InvalidCard,
    UserNotFound,
    MissingFields(String),
    GenericError(String),
    SerializationError(String),
    InvalidSeed,
    InvalidRevealToken,
}

impl fmt::Display for DeckCustomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeckCustomError::InvalidProof => write!(f, "invalid proof error"),
            DeckCustomError::MissingFields(msg) => write!(f, "The following fields are missing: {}", msg),
            DeckCustomError::GenericError(msg) => write!(f, "An error ocurred: {}", msg),
            DeckCustomError::InvalidPublicKey => write!(f, "invalid public key"),
            DeckCustomError::SerializationError(msg) => write!(f, "Serialization err: {}", msg),
            DeckCustomError::UserNotFound => write!(f, "User not found"),
            DeckCustomError::InvalidSeed => write!(f, "invalid seed"),
            DeckCustomError::InvalidCard => write!(f, "invalid card"),
            DeckCustomError::InvalidRevealToken=> write!(f, "invald token"),
        }
    }
}

impl From<mongodb::error::Error> for DeckCustomError {
    fn from(err: mongodb::error::Error) -> Self {
        DeckCustomError::GenericError(err.to_string())
    }
}

impl Error for DeckCustomError {}