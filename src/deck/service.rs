use ark_ec::{AffineCurve, ProjectiveCurve};
use barnett_smart_card_protocol::BarnettSmartProtocol;
use barnett_smart_card_protocol::discrete_log_cards::{ DLCards};
use bincode::Options;
use super::{models::{ deck_case::deck::{
    SetUpDeckRequest,
    ComputeAggregateKeyRequest,MaskRequest}}, errors::DeckCustomError, repository::UserDbTrait};
use rand_chacha::{ChaCha20Rng};
use rand_core::{CryptoRngCore, RngCore, SeedableRng};
use rocket::data::ToByteUnit;
use rocket::futures::TryFutureExt;
use rocket::yansi::Paint;
use crate::deck::models::deck_case::deck::{SetUpDeckResponse, MaskResponse, ComputeAggregateKeyResponse, GenerateDeckRequest, GenerateDeckResponse, InitialDeck, MaskedCardAndProofDTO as CardDTO, ShuffleRequest, ShuffleResponse, VerifyShuffleRequest, VerifyShuffleResponse, ShuffledDeck, RevealCardsRequest, RevealCardsResponse, OpenCardsRequest, OpenCardsResponse, RevealedDeck, PeekCardsRequest, PeekCardsResponse, ReceiveAndRevealTokenRequest, ReceiveAndRevealTokenResponse, InitialDeckRequest, InitialDeckResponse, InitialCard, Proof, MaskDeck};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use asn1_der::typed::DerEncodable;
use starknet_curve::{Affine, StarkwareParameters};
use crate::serialize::serialize::{encode_public_key, decode_public_key, decode_deck_public_key, decode_masked_card, encode_masked_card, encode_masking_proof, decode_shuffle_proof, encode_shuffle_proof, encode_initial_card, decode_initial_card};

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
use std::sync::Mutex;

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
use crate::game_user::repository::GameUserMemTrait;
use hex::FromHex;
type ZKProof = schnorr_identification::proof::Proof<Curve>;

pub struct DeckService {
    user_db: Mutex<HashMap<String, GameUser>>,
}

impl DeckService {
    pub fn new(user_db: Box<dyn GameUserMemTrait>) -> Self {
        DeckService { user_db:Mutex::new(HashMap::new())}
    }
}


#[async_trait]
pub trait DeckServiceTrait: Send + Sync {
    // return a initial game cards
    async fn initial_deck(&self,initial_deck: InitialDeckRequest)->Result<InitialDeckResponse, DeckCustomError>;

    async fn setup(&self,set_up: SetUpDeckRequest) -> Result<SetUpDeckResponse, DeckCustomError>;

    async fn compute_aggregate_key(&self,compute_agg_key: ComputeAggregateKeyRequest)->Result<ComputeAggregateKeyResponse,DeckCustomError>;

    async fn mask(&self, mask_req: MaskRequest)->Result<MaskResponse,DeckCustomError>;
    async fn shuffle (&self, shuffle_request: ShuffleRequest) -> Result<ShuffleResponse, DeckCustomError>;

    async fn verify_shuffle(&self, verify_shuffle_request: VerifyShuffleRequest) -> Result<VerifyShuffleResponse, DeckCustomError>;


    // user receive their and need to reveal others card at the same time
    async fn receive_and_reveal_token(&self, receive_and_reveal_token_request: ReceiveAndRevealTokenRequest)->Result<ReceiveAndRevealTokenResponse, DeckCustomError>;
    async fn reveal_cards(&self,reveal_cards_request:  RevealCardsRequest)->Result<RevealCardsResponse, DeckCustomError>;

    async fn peek_cards(&self,peek_cards_request: PeekCardsRequest) -> Result<PeekCardsResponse, DeckCustomError>;

    async fn open_cards(&self,open_cards_request: OpenCardsRequest)->Result<OpenCardsResponse, DeckCustomError>;
}

#[async_trait]
impl DeckServiceTrait for DeckService {
    async fn initial_deck(&self,initial_deck: InitialDeckRequest)->Result<InitialDeckResponse, DeckCustomError>{
        // Each player should run this computation and verify that all players agree on the initial deck
        let mut  rng = ChaCha20Rng::from_entropy();
        let seed = rng.clone().get_seed();
        let seed_hex = hex::encode(&seed);
        let mut rng = thread_rng();
        let card_mapping = encode_cards(&mut rng, 2*26);
        let mut initial_cards  =  Vec::with_capacity(card_mapping.len());
        for card in card_mapping {
            let mut encoded_card = Vec::new();
            if let Err(e) = card.0.serialize_uncompressed(&mut encoded_card){
                return Err(DeckCustomError::GenericError(String::from("Internal")))
            };
            let card_hex = match encode_initial_card(card.0){
                Ok(c) => c,
                Err(e) => return Err(DeckCustomError::GenericError(String::from("Internal")))
            };
            initial_cards.push(InitialCard{
                classic_card: card.1,
                card: card_hex,
            });
        }
        Ok(
            InitialDeckResponse{
                cards: initial_cards,
                seed_hex: seed_hex,
            }
        )
    }

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
        let mut restored_rng = restore_rnd(set_up.seed_hex)?;
        let params= match   CardProtocol::setup(&mut restored_rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };
        let rng = &mut thread_rng();
        let (pk, sk) = match CardProtocol::player_keygen(rng, &params){
            Ok(tuple) =>  tuple,
            Err(_e)=> return Err(DeckCustomError::InvalidPublicKey)
        };
        let game_user = GameUser::new(set_up.game_user_id.clone(),set_up.user_id.clone(),pk,sk);

        //TODO 用户对局信息存起来
        let pub_key = match encode_public_key(pk){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Failed to serialize pk")))
        };
        let  game_user_info = set_up.game_user_id.clone().into_bytes();

        let proof =match CardProtocol::prove_key_ownership(rng, &params, &pk, &sk, &game_user_info){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };
        let proof_third = IdentityProof::new(proof);
        self.user_db.lock().unwrap().insert(set_up.game_user_id.clone(), game_user);
        Ok(SetUpDeckResponse{
            user_id:set_up.user_id,
            game_id:set_up.game_id,
            game_user_id: set_up.game_user_id,
            user_public_key:  pub_key,
            user_key_proof: Proof{
                commit: proof_third.commit,
                opening:proof_third.opening,
            },
        })
    }
    async fn compute_aggregate_key(&self,compute_agg_key_request: ComputeAggregateKeyRequest)->Result<ComputeAggregateKeyResponse,DeckCustomError> {
        let mut restored_rng = restore_rnd(compute_agg_key_request.seed_hex)?;
        let parameters = match CardProtocol::setup(&mut restored_rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };

        let mut key_proof_info = Vec::with_capacity(compute_agg_key_request.players.len());
        for player in compute_agg_key_request.players {
            let public_key = match decode_public_key(player.public_key.clone()) {
                Ok(p) => p,
                Err(_e) => return Err(DeckCustomError::InvalidPublicKey)
            };


            let key_proof=IdentityProof{
                commit:player.user_key_proof.commit.clone(),
                opening:player.user_key_proof.opening.clone(),
            }.to_curve()?;

            // 验证对方公钥
            if  let Err(e) = CardProtocol::verify_key_ownership(&parameters,&public_key,&player.game_user_id.clone().into_bytes(),&key_proof){
                return Err(DeckCustomError::InvalidProof)
            }
            key_proof_info.push((public_key, key_proof, player.game_user_id.clone().into_bytes()))
        }
        let joint_pk = match CardProtocol::compute_aggregate_key(&parameters, &key_proof_info){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };

        let public_key = match encode_public_key(joint_pk){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Failed to serialize pk")))
        };
        Ok(ComputeAggregateKeyResponse{
            joined_key:public_key,
        })
    }

    async fn mask(&self, mask_req: MaskRequest)->Result<MaskResponse,DeckCustomError>{
        let mut restored_rng = restore_rnd(mask_req.seed_hex)?;
        let parameters = match CardProtocol::setup(&mut restored_rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };
        let joint_pk = decode_deck_public_key(mask_req.joined_key.clone())?;
        let rng = &mut thread_rng();
        let mut masked_cards  =  Vec::with_capacity(mask_req.cards.len());
        for card in mask_req.cards {
            let initial_card = decode_initial_card(card)?;
            let masked_result =  <DLCards<ark_ec::short_weierstrass_jacobian::GroupProjective<StarkwareParameters>> as BarnettSmartProtocol>::mask(rng, &parameters, &joint_pk, &initial_card, &Scalar::one());
            let one_masked_card = match masked_result{
                Ok(p)=>p,
                Err(_e) => return Err(DeckCustomError::InvalidCard)
            };
            masked_cards.push(one_masked_card);
        }

        let shuffle_deck = match MaskDeck::new(masked_cards){
            Ok(d) => d,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };
        // shuffle_deck.into_masked_card();
        Ok(MaskResponse{
            cards:shuffle_deck.cards,
        })
    }

    async fn shuffle(&self, shuffle_request: ShuffleRequest) -> Result<ShuffleResponse, DeckCustomError> {
        let mut restored_rng = restore_rnd(shuffle_request.seed_hex)?;
        let parameters = match CardProtocol::setup(&mut restored_rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };
        let joint_pk = decode_deck_public_key(shuffle_request.joined_key.clone())?;

        let pmrng =&mut  thread_rng();
        let maskrng =&mut  thread_rng();
        let shufflerng = &mut thread_rng();

        let mut deck = Vec::with_capacity(shuffle_request.cards.len());

        for card in shuffle_request.cards {
            let maked_card = decode_masked_card(card)?;
            deck.push(maked_card);
        }

        let permutation = Permutation::new(pmrng, 2 * 26);
        let masking_factors: Vec<Scalar> = sample_vector(maskrng, 2 * 26);
        let (a_shuffled_deck, a_shuffle_proof) = match CardProtocol::shuffle_and_remask(
            shufflerng,
            &parameters,
            &joint_pk,
            &deck,
            &masking_factors,
            &permutation,
        ){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };


        let proof_hex = match encode_shuffle_proof(&a_shuffle_proof){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };

        let shuffle_deck_dto = match ShuffledDeck::new(a_shuffled_deck){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };

        Ok(ShuffleResponse{
            deck: shuffle_deck_dto,
            shuffle_proof:proof_hex,
        })
    }

    async fn verify_shuffle(&self,verify_shuffle_request: VerifyShuffleRequest) -> Result<VerifyShuffleResponse, DeckCustomError> {
       let proof = match  decode_shuffle_proof(verify_shuffle_request.proof){
           Ok(p) => p,
           Err(_e)=> return Err(DeckCustomError::InvalidProof)
       };

        let mut restored_rng = restore_rnd(verify_shuffle_request.seed_hex)?;
        let parameters = match CardProtocol::setup(&mut restored_rng, 2, 26){
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

        if  let Err(_e)= CardProtocol::verify_shuffle(&parameters,&joined_key,&origin_deck,&shuffled_deck, &proof){
            return Err(DeckCustomError::InvalidProof)
        };
        Ok(VerifyShuffleResponse{})
    }

    async fn receive_and_reveal_token(&self, receive_and_reveal_token_request: ReceiveAndRevealTokenRequest)->Result<ReceiveAndRevealTokenResponse, DeckCustomError>{
        let game_user_id = receive_and_reveal_token_request.game_user_id.clone();
        let reveal_response = self.reveal_cards(RevealCardsRequest{
            game_user_id,
            shuffled_deck: receive_and_reveal_token_request.shuffled_deck,
        }).await?;

        let mut  user_db = self.user_db.lock().unwrap(); // 守卫生命周期开始
        let get_user_result = user_db.get(&receive_and_reveal_token_request.game_user_id.clone());
        let mut user = match get_user_result{
            Some(game_user) => game_user.clone(),
            None => return Err(DeckCustomError::UserNotFound),
        };
        for card_dto in receive_and_reveal_token_request.received_cards{
            let masked_card = match decode_masked_card(card_dto.masked_card){
                Ok(p) => p,
                Err(_e)=> return Err(DeckCustomError::InvalidProof)
            };
            user.cards.push(masked_card);
        }
        user_db.insert(receive_and_reveal_token_request.game_user_id.clone(),user);
        Ok(ReceiveAndRevealTokenResponse{
            revealed_deck:reveal_response.revealed_deck,
        })
    }


    async fn reveal_cards(&self,reveal_cards_request:  RevealCardsRequest)->Result<RevealCardsResponse, DeckCustomError>{
        let shuffled_deck= match reveal_cards_request.shuffled_deck.into_masked_card(){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::InvalidProof)
        };
        let game_user_id = reveal_cards_request.game_user_id.clone();

        let user_db = self.user_db.lock().unwrap(); // 守卫生命周期开始
        let get_user_result = user_db.get(&game_user_id);      // 守卫未释放，引用有效
        let user = match get_user_result{
            Some(game_user) => game_user,
            None => return Err(DeckCustomError::UserNotFound),
        };
        let user_private_key = user.private_key.clone();
        let user_public_key = user.public_key.clone();
        let rng = &mut thread_rng();
        let parameters = match CardProtocol::setup(rng, 2, 26){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        };
        let mut reveal_cards  =  Vec::with_capacity(shuffled_deck.len());

        for masked_card in shuffled_deck{
            let reveal_card = match CardProtocol::compute_reveal_token(rng,&parameters,&user_private_key,&user_public_key,&masked_card){
                Ok(p) => p,
                Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
            };
            reveal_cards.push((masked_card,reveal_card.0,reveal_card.1));
        }
        let deck =match  RevealedDeck::new(reveal_cards){
            Ok(p) => p,
            Err(_e)=> return Err(DeckCustomError::SerializationError(String::from("Internal")))
        };
        Ok(RevealCardsResponse{
            revealed_deck: deck,
        })
    }


    async fn peek_cards(&self,peek_cards_request: PeekCardsRequest) -> Result<PeekCardsResponse, DeckCustomError>{
        todo!()
    }


    async fn open_cards(&self,open_cards_request: OpenCardsRequest)->Result<OpenCardsResponse, DeckCustomError>{
        todo!();
        // let rng = &mut thread_rng();
        // let parameters = match CardProtocol::setup(rng, 2, 26){
        //     Ok(p) => p,
        //     Err(_e)=> return Err(DeckCustomError::GenericError(String::from("Internal")))
        // };
        //
        // let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card)?;
        // let opened_card = card_mappings.get(&unmasked_card);
        // let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;
        //
        // Ok(*opened_card)
    }
}

use crate::card::classic_card::{Suite,ClassicPlayingCard,Value};
use ark_ff::{to_bytes, UniformRand};
use asn1_der::e;
use proof_essentials::vector_commitment::pedersen::PedersenCommitment;
use proof_essentials::zkp::arguments::shuffle;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use crate::game_user::models::game_user::GameUser;
use crate::serialize::proof::{IdentityProof};
use crate::user::errors::CustomError;
use crate::user::models::user::User;

fn restore_rnd(seed_hex:String)->Result<ChaCha20Rng,DeckCustomError>{
    let  seed = match Vec::from_hex(seed_hex){
        Ok(seed) => seed,
        Err(_e) => return Err(DeckCustomError::InvalidSeed)
    };
    if seed.len()!=32{
        return Err(DeckCustomError::InvalidSeed)
    }
    let array_data: [u8; 32] = seed.try_into()
        .expect("Vec<u8> 的长度必须为 32");
    let  restored_rng = ChaCha20Rng::from_seed(array_data);
    Ok(restored_rng)
}

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

// pub fn peek_at_card(
//     &mut self,
//     parameters: &CardParameters,
//     reveal_tokens: &mut Vec<(RevealToken, RevealProof, PublicKey)>,
//     card_mappings: &HashMap<Card, ClassicPlayingCard>,
//     card: &MaskedCard,
// ) -> Result<(), anyhow::Error> {
//     let i = self.cards.iter().position(|&x| x == *card);
//
//     let i = i.ok_or(GameErrors::CardNotFound)?;
//
//     //TODO add function to create that without the proof
//     let rng = &mut thread_rng();
//     let own_reveal_token = self.compute_reveal_token(rng, parameters, card)?;
//     reveal_tokens.push(own_reveal_token);
//
//     let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card)?;
//     let opened_card = card_mappings.get(&unmasked_card);
//     let opened_card = opened_card.ok_or(GameErrors::InvalidCard)?;
//     self.opened_cards[i] = Some(*opened_card);
//     Ok(())
// }

#[cfg(test)]
mod unit_tests {


}