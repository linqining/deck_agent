use ark_crypto_primitives::encryption::elgamal::ElGamal;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ec::short_weierstrass_jacobian::{GroupAffine, GroupProjective};
use rocket::http::hyper::body::Buf;
use starknet_curve::{Affine, Fr, StarkwareParameters};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use barnett_smart_card_protocol::BarnettSmartProtocol;
use barnett_smart_card_protocol::discrete_log_cards::DLCards;
use bincode::Options;
use hex::FromHex;

type Curve = starknet_curve::Projective;
type CardProtocol = barnett_smart_card_protocol::discrete_log_cards::DLCards<Curve>;
type Card = barnett_smart_card_protocol::discrete_log_cards::Card<Curve>;

type MaskedCard = barnett_smart_card_protocol::discrete_log_cards::MaskedCard<Curve>;
type RevealToken = barnett_smart_card_protocol::discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;

type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

type ZKProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;

type Parameters = <DLCards<ark_ec::short_weierstrass_jacobian::GroupProjective<StarkwareParameters>> as BarnettSmartProtocol>::Parameters;
type PublicKey = GroupAffine<StarkwareParameters>;
type PrivateKey = <ark_ec::short_weierstrass_jacobian::GroupAffine<StarkwareParameters> as AffineCurve>::ScalarField;




use proof_essentials::zkp::{
    arguments::shuffle,
    proofs::{chaum_pedersen_dl_equality, schnorr_identification},
    ArgumentOfKnowledge,
};
use proof_essentials::zkp::arguments::shuffle::proof::Proof;
use crate::deck::errors::DeckCustomError;

// type ZKProofShuffle = shuffle::proof::Proof<Fr, Self::Enc, Self::Comm>;
type ZKShuffleProof =  Proof<Fr, proof_essentials::homomorphic_encryption::el_gamal::ElGamal<Curve>, proof_essentials::vector_commitment::pedersen::PedersenCommitment<Curve>>;

pub fn decode_public_key(public_key: String) ->Result<GroupAffine<StarkwareParameters>, ark_serialize::SerializationError>{
    let bytes = match Vec::from_hex(public_key){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_result = PublicKey::deserialize_uncompressed(bytes.reader());
    restored_result
}

pub fn decode_deck_public_key(public_key: String) ->Result<GroupAffine<StarkwareParameters>, DeckCustomError>{
    let bytes = match Vec::from_hex(public_key){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(DeckCustomError::InvalidPublicKey)
    };
    let restored_result = match PublicKey::deserialize_uncompressed(bytes.reader()){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(DeckCustomError::InvalidPublicKey)
    };
   Ok(restored_result)
}

pub fn encode_public_key(pk :PublicKey)->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    pk.serialize_uncompressed(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn encode_masked_card(card :MaskedCard)->Result<String, DeckCustomError>{
    let mut bytes = Vec::new();
   match card.serialize(&mut bytes){
       Ok(()) => return Ok(hex::encode(&bytes)),
       Err(e)=> return Err(DeckCustomError::InvalidCard),
   }
}

pub fn decode_masked_card(card_hex: String) ->Result<MaskedCard, DeckCustomError>{
    let bytes = match Vec::from_hex(card_hex){
        Ok(bytes) => bytes,
        Err(err)    => return Err(DeckCustomError::InvalidCard)
    };
    let restored_result =match MaskedCard::deserialize(bytes.reader()){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(DeckCustomError::InvalidCard)
    };
    Ok(restored_result)
}

pub fn encode_masking_proof(proof: RemaskingProof)->Result<String, DeckCustomError>{
    let mut bytes = Vec::new();
    match proof.serialize_uncompressed(&mut bytes){
        Ok(_) => return Ok(hex::encode(&bytes)),
        Err(_err)   => return  Err(DeckCustomError::InvalidProof)
    }
}

pub fn decode_masking_proof(proof_hex: String) ->Result<RemaskingProof, ark_serialize::SerializationError>{
    let bytes = match Vec::from_hex(proof_hex){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_result = RemaskingProof::deserialize(bytes.reader());
    restored_result
}

pub fn decode_shuffle_proof(proof_hex: String)->Result<ZKShuffleProof, SerializationError>{
    let bytes = match Vec::from_hex(proof_hex){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(ark_serialize::SerializationError::InvalidData)
    };
    let restored_result = ZKShuffleProof::deserialize(bytes.reader());
    restored_result
}
pub fn encode_shuffle_proof(proof: &ZKShuffleProof) ->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    proof.serialize(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn encode_revel_token(token :RevealToken)->Result<String, DeckCustomError>{
    let mut bytes = Vec::new();
    if let Err(e) =  token.serialize(&mut bytes){
        return Err(DeckCustomError::InvalidRevealToken);
    }
    Ok(hex::encode(&bytes))
}

pub fn decode_revel_token(token_hex :String)->Result<RevealToken, DeckCustomError>{
    let bytes = match Vec::from_hex(token_hex){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(DeckCustomError::InvalidRevealToken)
    };
    let restored_result = match RevealToken::deserialize(bytes.reader()){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(DeckCustomError::InvalidRevealToken)
    };
    Ok(restored_result)
}

pub fn encode_revel_proof(proof :RevealProof)->Result<String, DeckCustomError>{

    let mut bytes = Vec::new();
    if let Err(_e)= proof.serialize(&mut bytes){
        return Err(DeckCustomError::InvalidProof);
    };
    Ok(hex::encode(&bytes))
}

pub fn decode_revel_proof(proof_hex :String)->Result<RevealProof, DeckCustomError>{
    let bytes = match Vec::from_hex(proof_hex){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(DeckCustomError::InvalidProof)
    };
    let restored_result = match RevealProof::deserialize(bytes.reader()){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(DeckCustomError::InvalidProof)
    };
    Ok(restored_result)
}

pub fn encode_initial_card(card :Card)->Result<String, SerializationError>{
    let mut bytes = Vec::new();
    card.serialize(&mut bytes)?;
    Ok(hex::encode(&bytes))
}

pub fn decode_initial_card(card_hex :String)->Result<Card, DeckCustomError>{
    let bytes = match Vec::from_hex(card_hex){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(DeckCustomError::InvalidCard)
    };
    let restored_result = match Card::deserialize(bytes.reader()){
        Ok(bytes) => bytes,
        Err(_err)    => return Err(DeckCustomError::InvalidCard)
    };
    Ok(restored_result)
}
//
// pub fn encode_params(params :Parameters)->Result<String, SerializationError>{
//     let mut bytes = Vec::new();
//     params.serialize(&mut bytes)?;
//
//     Ok(hex::encode(&bytes))
//
// }

// pub fn decode_params(params_hex :String)->Result<Parameters, SerializationError>{
//     let bytes = match Vec::from_hex(params_hex){
//         Ok(bytes) => bytes,
//         Err(err)    => return Err(ark_serialize::SerializationError::InvalidData)
//     };
//     Parameters::
// }


#[cfg(test)]
mod proof_test {
    use rocket::http::Status;
    use crate::serialize::serialize::{decode_proof, encode_proof};
    #[test]
    fn test_decode_proof(){
        let proof =String::from("b5a0c626c8d9e1a405079396000b9302f641cddb9f9b701bf5c9eabe7439110644ef911ac5275453b73c261fd4bc2551c381c8edf6c659cac74cadf00a670c02");
        let decode_proof = decode_proof(proof.clone()).unwrap();
        println!("decode_proof: {:?}", decode_proof.clone());
        let reencode_proof = encode_proof(decode_proof).unwrap();
        println!("reencode_proof: {:?}", reencode_proof);
        assert_eq!(proof, reencode_proof);
    }
}