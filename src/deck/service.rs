use ark_ec::group::Group;
use ark_ec::ProjectiveCurve;
use barnett_smart_card_protocol::BarnettSmartProtocol;
use barnett_smart_card_protocol::discrete_log_cards::{ DLCards, Parameters};
use bincode::Options;
use super::{models::{ deck_case::deck::{ SetUpDeckRequest}}, errors::DeckCustomError, repository::UserDbTrait};
use rand_chacha::{ChaCha20Rng};
use rand_core::{ SeedableRng};
use rocket::data::ToByteUnit;
use rocket::futures::TryFutureExt;
use rocket::yansi::Paint;
use crate::deck::models::deck_case::deck::SetUpDeckResponse;
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use starknet_curve::{Affine, StarkwareParameters};

extern crate starknet_curve;
use proof_essentials::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};
use serde::{Serialize, Deserialize};
type Curve = starknet_curve::Projective;
type CardProtocol = barnett_smart_card_protocol::discrete_log_cards::DLCards<Curve>;

pub struct DeckService {
    user_db: Box<dyn UserDbTrait>,
}

impl DeckService {
    pub fn new(user_db: Box<dyn UserDbTrait>) -> Self {
        DeckService { user_db }
    }
}


#[async_trait]
pub trait DeckServiceTrait: Send + Sync {
    async fn setup(&self,set_up: SetUpDeckRequest) -> Result<SetUpDeckResponse, DeckCustomError>;
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

        let  rng = ChaCha20Rng::seed_from_u64(set_up.rng_seed);
        let seed = rng.get_seed();

        let serialized = bincode::serialize(&seed).unwrap();

        let deserialized: <ChaCha20Rng as SeedableRng>::Seed =
            match bincode::deserialize(&serialized) {
                Ok(v) => v,
                Err(_e)=> return Err(DeckCustomError::InvalidSeed)
            };
        let mut restored_rng = ChaCha20Rng::from_seed(deserialized);


        let params= match   CardProtocol::setup(&mut restored_rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidSeed)
        };

        let (pk, sk) = match CardProtocol::player_keygen(&mut restored_rng, &params){
            Ok(tuple) =>  tuple,
            Err(_e)=> return Err(DeckCustomError::InvalidSeed)
        };

        // let (pk, sk) =  CardProtocol::player_keygen(&mut restored_rng, &params).unwrap();

        let  game_user_info = set_up.game_user_id.clone().into_bytes();
        let _proof_key =match CardProtocol::prove_key_ownership(&mut restored_rng, &params, &pk, &sk, &game_user_info){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidSeed)
        };





        Ok(SetUpDeckResponse{
            user_id:set_up.user_id,
            game_id:set_up.game_id,
            game_user_id: set_up.game_user_id,
            user_public_key:  pk.to_string(),
            // user_key_proof: proof_bytes,
        })
    }
}

#[cfg(test)]
mod unit_tests {




}