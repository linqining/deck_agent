use ark_ec::group::Group;
use ark_ec::ProjectiveCurve;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use barnett_smart_card_protocol::BarnettSmartProtocol;
use barnett_smart_card_protocol::discrete_log_cards::{ DLCards, Parameters};
use bincode::Options;
use super::{models::{ deck_case::deck::{
    SetUpDeckRequest,
    ComputeAggregateKeyRequest}}, errors::DeckCustomError, repository::UserDbTrait};
use rand_chacha::{ChaCha20Rng};
use rand_core::{RngCore, SeedableRng};
use rocket::data::ToByteUnit;
use rocket::futures::TryFutureExt;
use rocket::yansi::Paint;
use crate::deck::models::deck_case::deck::{SetUpDeckResponse, ComputeAggregateKeyResponse, GenerateDeckRequest, GenerateDeckResponse, InitialDeck, MaskedCardAndProofDTO as CardDTO, ShuffleRequest, ShuffleResponse, VerifyShuffleRequest, VerifyShuffleResponse, ShuffledDeck};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use asn1_der::typed::DerEncodable;
use starknet_curve::{Affine, StarkwareParameters};
use crate::serialize::serialize::{encode_public_key, decode_public_key, encode_proof, decode_proof, decode_masked_card, encode_masked_card, encode_masking_proof, decode_shuffle_proof, encode_shuffle_proof};

use proof_essentials::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};
use rocket::http::hyper::body::Buf;
use serde::{Serialize, Deserialize};
use rand::thread_rng;
use crate::user::service::UserService;
use ark_std::{rand::Rng, One};
type Scalar = starknet_curve::Fr;
use std::collections::HashMap;


type Curve = starknet_curve::Projective;
type CardProtocol = barnett_smart_card_protocol::discrete_log_cards::DLCards<Curve>;
type Card = barnett_smart_card_protocol::discrete_log_cards::Card<Curve>;

type MaskedCard = barnett_smart_card_protocol::discrete_log_cards::MaskedCard<Curve>;
type RevealToken = barnett_smart_card_protocol::discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;

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

    async fn generate_deck(&self, generate_deck_request: GenerateDeckRequest) -> Result<GenerateDeckResponse, DeckCustomError>;

    async fn shuffle (&self, shuffle_request: ShuffleRequest) -> Result<ShuffleResponse, DeckCustomError>;

    async fn verify_shuffle(&self, verify_shuffle_request: VerifyShuffleRequest) -> Result<VerifyShuffleResponse, DeckCustomError>;
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
        let rng = &mut thread_rng();
        let parameters = match CardProtocol::setup(rng, 2, 26){
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

    // TODO verify deck proof
    async fn generate_deck(&self, generate_deck_request: GenerateDeckRequest) -> Result<GenerateDeckResponse, DeckCustomError>{
        // Each player should run this computation and verify that all players agree on the initial deck
        let rng = &mut thread_rng();

        let card_mapping = encode_cards(rng, 2*26);

        let parameters = match CardProtocol::setup(rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };
        let join_key = match decode_public_key(generate_deck_request.joined_key.clone()){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidPublicKey)
        };

        let deck_and_proofs:Vec<(MaskedCard, RemaskingProof)>   = match card_mapping
            .keys()
            .map(|card| <DLCards<ark_ec::short_weierstrass_jacobian::GroupProjective<StarkwareParameters>> as BarnettSmartProtocol>::mask(rng, &parameters, &join_key, &card, &Scalar::one()))
            .collect::<Result<Vec<_>, _>>(){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };


        let deck_dto = match    InitialDeck::new(deck_and_proofs){
            Ok(p)=>p,
            Err(e)=>return Err(DeckCustomError::SerializationError(e.to_string()))
        };

        Ok(GenerateDeckResponse{
            deck:deck_dto,
        })
    }
    async fn shuffle(&self, shuffle_request: ShuffleRequest) -> Result<ShuffleResponse, DeckCustomError> {
        let joined_key = match decode_public_key(shuffle_request.joined_key.clone()){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidPublicKey)
        };
        let pmrng1 =&mut  thread_rng();
        let maskrng1 =&mut  thread_rng();
        let shufflerng1 = &mut thread_rng();
        let rng = &mut thread_rng();
        let parameters = match CardProtocol::setup(rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };

        let deck= match shuffle_request.deck.into_masked_card(){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };

        let permutation = Permutation::new(pmrng1, 2 * 26);
        let masking_factors: Vec<Scalar> = sample_vector(maskrng1, 2 * 26);
        let (a_shuffled_deck, a_shuffle_proof) = match CardProtocol::shuffle_and_remask(
            shufflerng1,
            &parameters,
            &joined_key,
            &deck,
            &masking_factors,
            &permutation,
        ){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };
        let mut encoded_proof = Vec::new();
        if let Err(e)= a_shuffle_proof.serialize_uncompressed(&mut encoded_proof){
            return Err(DeckCustomError::SerializationError(e.to_string()))
        };


        if let Err(er)= encode_shuffle_proof(&a_shuffle_proof,&mut encoded_proof){
            return Err(DeckCustomError::SerializationError(String::from("Failed to shuffle proof")))
        }

        let shuffle_deck_dto = match ShuffledDeck::new(a_shuffled_deck){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };

        Ok(ShuffleResponse{
            deck: shuffle_deck_dto,
            shuffle_proof:encoded_proof,
        })
    }

    async fn verify_shuffle(&self,verify_shuffle_request: VerifyShuffleRequest) -> Result<VerifyShuffleResponse, DeckCustomError> {
       let proof = match  decode_shuffle_proof(verify_shuffle_request.proof){
           Ok(p) => p,
           Err(_e)=> return Err(DeckCustomError::InvalidProof)
       };
        let rng = &mut thread_rng();
        let parameters = match CardProtocol::setup(rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };

        let joined_key = match decode_public_key(verify_shuffle_request.joined_key.clone()){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidPublicKey)
        };

        let origin_deck= match verify_shuffle_request.origin_deck.into_masked_card(){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };

        let shuffled_deck= match verify_shuffle_request.shuffled_deck.into_masked_card(){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };

        if  let Err(e)= CardProtocol::verify_shuffle(&parameters,&joined_key,&origin_deck,&shuffled_deck, &proof){
            return Err(DeckCustomError::InvalidProof)
        };
        Ok(VerifyShuffleResponse{
        })
    }
}

use crate::card::classic_card::{Suite,ClassicPlayingCard,Value};
use ark_ff::{to_bytes, UniformRand};
use proof_essentials::vector_commitment::pedersen::PedersenCommitment;
use proof_essentials::zkp::arguments::shuffle;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};

fn encode_cards<R: Rng>(rng: &mut R, num_of_cards: usize) -> HashMap<Card, ClassicPlayingCard> {
    let mut map: HashMap<Card, ClassicPlayingCard> = HashMap::new();
    let plaintexts = (0..num_of_cards)
        .map(|_| Card::rand(rng))
        .collect::<Vec<_>>();

    let mut i = 0;
    for value in Value::VALUES.iter().copied() {
        for suite in Suite::VALUES.iter().copied() {
            let current_card = ClassicPlayingCard::new(value, suite);
            map.insert(plaintexts[i], current_card);
            i += 1;
        }
    }

    map
}

#[cfg(test)]
mod unit_tests {


}