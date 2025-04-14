
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use rocket::http::hyper::body::Buf;
use starknet_curve::{Affine, StarkwareParameters};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use crate::deck::errors::DeckCustomError;
type Curve = starknet_curve::Projective;

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