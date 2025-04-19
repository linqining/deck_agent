use ark_ec::group::Group;
use ark_ec::ProjectiveCurve;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use barnett_smart_card_protocol::BarnettSmartProtocol;
use barnett_smart_card_protocol::discrete_log_cards::{ DLCards, Parameters};
use bincode::Options;
use super::{models::{ deck_case::deck::{
    SetUpDeckRequest,
    ComputeAggregateKeyRequest,VerifyKeyRequest,VerifyKeyResponse}}, errors::DeckCustomError, repository::UserDbTrait};
use rand_chacha::{ChaCha20Rng};
use rand_core::{RngCore, SeedableRng};
use rocket::data::ToByteUnit;
use rocket::futures::TryFutureExt;
use rocket::yansi::Paint;
use crate::deck::models::deck_case::deck::{SetUpDeckResponse,ComputeAggregateKeyResponse};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use asn1_der::typed::DerEncodable;
use starknet_curve::{Affine, StarkwareParameters};
use crate::key_export::key_export::{encode_public_key, decode_public_key, encode_proof, decode_proof};

use proof_essentials::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};
use rocket::http::hyper::body::Buf;
use serde::{Serialize, Deserialize};
use rand::thread_rng;
use crate::user::service::UserService;

type Curve = starknet_curve::Projective;
type CardProtocol = barnett_smart_card_protocol::discrete_log_cards::DLCards<Curve>;

pub struct DeckService {
    user_db: Box<dyn crate::user::repository::UserMemTrait>,
}

impl DeckService {
    pub fn new(user_db: Box<dyn crate::user::repository::UserMemTrait>) -> Self {
        DeckService { user_db }
    }
}


#[async_trait]
pub trait DeckServiceTrait: Send + Sync {
    async fn setup(&self,set_up: SetUpDeckRequest) -> Result<SetUpDeckResponse, DeckCustomError>;

    async fn compute_aggregate_key(&self,compute_agg_key: ComputeAggregateKeyRequest)->Result<ComputeAggregateKeyResponse,DeckCustomError>;
}

#[async_trait]
impl DeckServiceTrait for DeckService {
    async fn setup(&self,set_up: SetUpDeckRequest) -> Result<SetUpDeckResponse, DeckCustomError> {
        let mut missing_properties: Vec<&str> = vec![];
        if set_up.user_id.is_empty() {
            // TODO validate user access right to the agent service
            missing_properties.push("user_id");
        }

        if set_up.game_id.is_empty(){
            missing_properties.push("game_id");
        }

        if set_up.game_user_id.is_empty() {
            missing_properties.push("game_user_id");
        }
        if !missing_properties.is_empty() {
            return Err(DeckCustomError::MissingFields(
                missing_properties.join(", ").to_string(),
            ));
        }

        // let  rng = ChaCha20Rng::from_entropy();
        // let seed = rng.get_seed();
        // print!("seed{:?}",seed);
        //
        //
        // let serialized = bincode::serialize(&set_up.rng_seed).unwrap();
        // let deserialized: <ChaCha20Rng as SeedableRng>::Seed =
        //     match bincode::deserialize(&serialized) {
        //         Ok(v) => v,
        //         Err(_e)=> return Err(DeckCustomError::InvalidSeed)
        //     };
        // let mut restored_rng = ChaCha20Rng::from_seed(deserialized);

        let rng = &mut thread_rng();

        let params= match   CardProtocol::setup(rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };

        let (pk, sk) = match CardProtocol::player_keygen(rng, &params){
            Ok(tuple) =>  tuple,
            Err(_e)=> return Err(DeckCustomError::InvalidPublicKey)
        };

        //TODO 用户对局信息存起来


        let mut encoded_pk = Vec::new();
        if let Err(_e) = encode_public_key(pk,&mut encoded_pk){
            return Err(DeckCustomError::GenericError(String::from("Failed to serialize pk")))
        }
        // let restored_pk:GroupAffine<StarkwareParameters> = decode_public_key(encoded_pk).unwrap();
        // println!("{:?}", restored_pk);
        let  game_user_info = set_up.game_user_id.clone().into_bytes();

        let proof =match CardProtocol::prove_key_ownership( rng, &params, &pk, &sk, &game_user_info){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };
        println!("proof {:?}", proof);

        let mut encoded_proof = Vec::new();
        if let Err(_e) = encode_proof(proof,&mut encoded_proof){
            return Err(DeckCustomError::GenericError(String::from("Failed to serialize pk")))
        }
        //
        // let restored_proof= decode_proof(&encoded_proof).unwrap();
        // println!("restored_proof {:?}", restored_proof);
        //
        // println!("isequal {:?}", restored_proof.eq(&proof));

        Ok(SetUpDeckResponse{
            user_id:set_up.user_id,
            game_id:set_up.game_id,
            game_user_id: set_up.game_user_id,
            user_public_key:  encoded_pk,
            user_key_proof: encoded_proof,
        })
    }
    async fn compute_aggregate_key(&self,compute_agg_key_request: ComputeAggregateKeyRequest)->Result<ComputeAggregateKeyResponse,DeckCustomError> {
        let set_up_rng = &mut thread_rng();
        let parameters = match CardProtocol::setup(set_up_rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };

        let mut key_proof_info = Vec::with_capacity(compute_agg_key_request.players.len());
        for player in compute_agg_key_request.players {
            let public_key = match decode_public_key(player.public_key.clone()) {
                Ok(p) => p,
                Err(_e) => return Err(DeckCustomError::InvalidPublicKey)
            };

            let key_proof = match decode_proof(&player.proof) {
                Ok(p) => p,
                Err(_e) => return Err(DeckCustomError::InvalidProof)
            };
            key_proof_info.push((public_key, key_proof, player.game_user_id.clone().into_bytes()))
        }

        let joint_pk = match CardProtocol::compute_aggregate_key(&parameters, &key_proof_info){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };

        let mut encoded_pk = Vec::new();
        if let Err(_e) = encode_public_key(joint_pk,&mut encoded_pk){
            return Err(DeckCustomError::GenericError(String::from("Failed to serialize pk")))
        }
        Ok(ComputeAggregateKeyResponse{
            joined_key:encoded_pk,
        })
    }
}

#[cfg(test)]
mod unit_tests {


}