use ark_crypto_primitives::encryption::elgamal::ElGamal;
use ark_ec::short_weierstrass_jacobian::{GroupAffine, GroupProjective};
use rocket::http::hyper::body::Buf;
use starknet_curve::{Affine, Fr, StarkwareParameters};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use hex::FromHex;

type Curve = starknet_curve::Projective;
type CardProtocol = barnett_smart_card_protocol::discrete_log_cards::DLCards<Curve>;
type Card = barnett_smart_card_protocol::discrete_log_cards::Card<Curve>;

type MaskedCard = barnett_smart_card_protocol::discrete_log_cards::MaskedCard<Curve>;
type RevealToken = barnett_smart_card_protocol::discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
use crate::deck::errors::DeckCustomError;


use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;



use proof_essentials::zkp::{
    arguments::shuffle,
    proofs::{chaum_pedersen_dl_equality, schnorr_identification},
    ArgumentOfKnowledge,
};
use proof_essentials::zkp::arguments::shuffle::proof::Proof;

// type ZKProofShuffle = shuffle::proof::Proof<Fr, Self::Enc, Self::Comm>;
type ZKShuffleProof =  Proof<Fr, proof_essentials::homomorphic_encryption::el_gamal::ElGamal<Curve>, proof_essentials::vector_commitment::pedersen::PedersenCommitment<Curve>>;

pub fn decode_public_key(public_key: String) ->Result<GroupAffine<StarkwareParameters>, ark_serialize::SerializationError>{
    let bytes = match Vec::from_hex(public_key){
        Ok(bytes) => bytes,
        Err(err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_result = ark_ec::short_weierstrass_jacobian::GroupAffine::deserialize_uncompressed(bytes.reader());
    restored_result
}

pub fn encode_public_key(pk :GroupAffine<StarkwareParameters>)->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    pk.serialize_uncompressed(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn encode_proof(proof:schnorr_identification::proof::Proof<Curve>)->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn decode_proof(proof: String)->Result<schnorr_identification::proof::Proof<Curve>,SerializationError>{
    let bytes = match Vec::from_hex(proof){
        Ok(bytes) => bytes,
        Err(err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_proof = schnorr_identification::proof::Proof::deserialize_uncompressed(bytes.reader());
    restored_proof
}



pub fn encode_masked_card(card :MaskedCard)->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    card.serialize_uncompressed(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn decode_masked_card(card_hex: String) ->Result<MaskedCard, ark_serialize::SerializationError>{
    let bytes = match Vec::from_hex(card_hex){
        Ok(bytes) => bytes,
        Err(err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_result = MaskedCard::deserialize(bytes.reader());
    restored_result
}

pub fn encode_masking_proof(proof: RemaskingProof)->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn decode_masking_proof(proof_hex: String) ->Result<RemaskingProof, ark_serialize::SerializationError>{
    let bytes = match Vec::from_hex(proof_hex){
        Ok(bytes) => bytes,
        Err(err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_result = RemaskingProof::deserialize(bytes.reader());
    restored_result
}

pub fn decode_shuffle_proof(proof_hex: String)->Result<ZKShuffleProof, SerializationError>{
    let bytes = match Vec::from_hex(proof_hex){
        Ok(bytes) => bytes,
        Err(err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_result = ZKShuffleProof::deserialize(bytes.reader());
    restored_result
}
pub fn encode_shuffle_proof(proof: &ZKShuffleProof) ->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn encode_revel_token(token :RevealToken)->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    token.serialize_uncompressed(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn decode_revel_token(token_hex :String)->Result<RevealToken, SerializationError>{
    let bytes = match Vec::from_hex(token_hex){
        Ok(bytes) => bytes,
        Err(err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_result = RevealToken::deserialize(bytes.reader());
    restored_result
}

pub fn encode_revel_proof(proof :RevealProof)->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn decode_revel_proof(proof_hex :String)->Result<RevealProof, SerializationError>{
    let bytes = match Vec::from_hex(proof_hex){
        Ok(bytes) => bytes,
        Err(err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_result = RevealProof::deserialize(bytes.reader());
    restored_result
}