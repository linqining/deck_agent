
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use rocket::http::hyper::body::Buf;
use starknet_curve::{Affine, StarkwareParameters};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};

type Curve = starknet_curve::Projective;
type CardProtocol = barnett_smart_card_protocol::discrete_log_cards::DLCards<Curve>;
type Card = barnett_smart_card_protocol::discrete_log_cards::Card<Curve>;

type MaskedCard = barnett_smart_card_protocol::discrete_log_cards::MaskedCard<Curve>;
type RevealToken = barnett_smart_card_protocol::discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
use crate::deck::errors::DeckCustomError;


use proof_essentials::zkp::{
    arguments::shuffle,
    proofs::{chaum_pedersen_dl_equality, schnorr_identification},
    ArgumentOfKnowledge,
};


pub fn decode_public_key(bytes: Vec<u8>) ->Result<GroupAffine<StarkwareParameters>, ark_serialize::SerializationError>{
    let restored_result = ark_ec::short_weierstrass_jacobian::GroupAffine::deserialize_uncompressed(bytes.reader());
    restored_result
}

pub fn encode_public_key(pk :GroupAffine<StarkwareParameters>, data :&mut Vec<u8>)->Result<(), SerializationError>{
     pk.serialize_uncompressed(data)
}

pub fn encode_proof(proof:schnorr_identification::proof::Proof<Curve>,data :&mut Vec<u8>)->Result<(), SerializationError>{
    proof.serialize_uncompressed(data)
}

pub fn decode_proof(bytes: &Vec<u8>)->Result<schnorr_identification::proof::Proof<Curve>,SerializationError>{
    let restored_proof = schnorr_identification::proof::Proof::deserialize_uncompressed(bytes.reader());
    restored_proof
}



pub fn encode_masked_card(pk :MaskedCard, data :&mut Vec<u8>)->Result<(), SerializationError>{
    pk.serialize_uncompressed(data)
}

pub fn decode_masked_card(bytes: Vec<u8>) ->Result<MaskedCard, ark_serialize::SerializationError>{
    let restored_result = MaskedCard::deserialize(bytes.reader());
    restored_result
}

pub fn encode_masking_proof(proof: RemaskingProof,data :&mut Vec<u8>)->Result<(), SerializationError>{
     proof.serialize_uncompressed(data)
}

pub fn decode_masking_proof(bytes: Vec<u8>) ->Result<RemaskingProof, ark_serialize::SerializationError>{
    let restored_result = RemaskingProof::deserialize(bytes.reader());
    restored_result
}