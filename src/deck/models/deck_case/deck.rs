use std::collections::HashMap;
use std::ffi::c_void;
use std::io::{Read, Write};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize, SWFlags, SerializationError};
use barnett_smart_card_protocol::BarnettSmartProtocol;
use barnett_smart_card_protocol::discrete_log_cards::DLCards;
use proof_essentials::homomorphic_encryption::el_gamal;
use proof_essentials::vector_commitment::pedersen;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use serde::{Serialize, Deserialize};

use crate::card::classic_card::ClassicPlayingCard;

use ark_bn254::g1::Parameters as G1Parameters;

type Curve = ark_bn254::G1Projective;
type CardProtocol = barnett_smart_card_protocol::discrete_log_cards::DLCards<Curve>;
// type Card = barnett_smart_card_protocol::discrete_log_cards::Card<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
use crate::deck::errors::DeckCustomError;
use crate::deck::models::deck::Deck;
use crate::game_user::models::game_user::GameUser;
use crate::serialize::proof::{IdentityProof, PedersenProof};
use crate::serialize::serialize::{decode_masked_card, decode_masking_proof, decode_revel_proof, decode_revel_token, encode_masked_card, encode_masking_proof, encode_revel_token};

type MaskedCard = barnett_smart_card_protocol::discrete_log_cards::MaskedCard<Curve>;
type RevealToken = barnett_smart_card_protocol::discrete_log_cards::RevealToken<Curve>;
type Card = barnett_smart_card_protocol::discrete_log_cards::Card<Curve>;

type Parameters = <DLCards<ark_ec::short_weierstrass_jacobian::GroupProjective<G1Parameters>> as BarnettSmartProtocol>::Parameters;



#[derive(Debug, Serialize, Deserialize)]
pub struct InitialDeckRequest {
    // pub m:usize,
    // pub n:usize,
}

// #[derive(Debug, Serialize, Deserialize)]
// pub struct InitParams{
//     pub m: u32,
//     pub n: u32,
//     pub enc_parameters: String,
//     pub commit_parameters: String,
//     pub generator: String,
// }
//
// impl InitParams {
//     pub fn new(params :Parameters )->Result<Self,SerializationError>{
//         let mut cards:Vec<crate::deck::models::deck_case::deck::MaskedCardAndProofDTO> = Vec::with_capacity(deck_and_proofs.len());
//         for deck_and_proof in deck_and_proofs {
//             let card_hex = encode_masked_card(deck_and_proof.0)?;
//             let proof_hex = encode_masking_proof(deck_and_proof.1)?;
//             cards.push(crate::deck::models::deck_case::deck::MaskedCardAndProofDTO {
//                 masked_card: card_hex,
//                 proof:proof_hex,
//             })
//         }
//
//         Ok(InitialDeck {
//             cards:cards,
//         })
//     }
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct InitialCard{
    pub classic_card: ClassicPlayingCard,
    pub card: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitialDeckResponse {
    pub cards: Vec<InitialCard>,
    pub seed_hex: String,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct SetUpDeckRequest{
    pub user_id: String, // user_id provide by the agent service
    pub game_id: String,
    pub game_user_id: String, // user identity among this round
    pub seed_hex: String,
    // pub m:usize,
    // pub n:usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClearRequest{
    pub user_id: String, // user_id provide by the agent service
    pub game_id: String,
    pub game_user_id: String, // user identity among this round
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClearResponse {
}

#[derive(Debug,Clone, Serialize, Deserialize)]
pub struct Proof{
    pub commit: String,
    pub opening: String,
}

#[derive(Debug,Clone, Serialize, Deserialize)]
pub struct PedersenProofDTO{
    pub a: String,
    pub b: String,
    pub r: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetUpDeckResponse{
    pub user_id:String,
    pub game_id:String,
    pub game_user_id:String,
    pub user_public_key:String,
    pub user_key_proof:Proof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Player{
    pub game_id:String,
    pub game_user_id:String,
    pub public_key: String,
    pub user_key_proof: Proof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeAggregateKeyRequest {
    pub players: Vec<Player>,
    pub seed_hex: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeAggregateKeyResponse{
    pub joined_key: String, // if accept other player's proof, return the joined key of all player
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateDeckRequest{
    pub joined_key: String,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct InitCardAndProofDTO {
    pub masked_card: String,
    pub proof: String,
}
#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct InitialDeck {
    pub cards: Vec<InitCardAndProofDTO>,
}

impl InitialDeck {
    pub fn new(deck_and_proofs :Vec<(MaskedCard, RemaskingProof)> )->Result<Self,DeckCustomError>{
        let mut cards:Vec<InitCardAndProofDTO> = Vec::with_capacity(deck_and_proofs.len());
        for deck_and_proof in deck_and_proofs {
            let card_hex = encode_masked_card(deck_and_proof.0)?;
            let proof_hex = encode_masking_proof(deck_and_proof.1)?;
            cards.push(InitCardAndProofDTO {
                masked_card: card_hex,
                proof:proof_hex,
            })
        }

        Ok(InitialDeck {
            cards:cards,
        })
    }
    pub fn into_masked_card(&self)-> Result<Vec<(MaskedCard, RemaskingProof)>,DeckCustomError>{
        let card_length = self.cards.len();
        let mut cards =Vec::with_capacity(card_length);
        for card in self.cards.clone().into_iter(){
            let masked_card = decode_masked_card(card.masked_card)?;
            let proof = decode_masking_proof(card.proof).unwrap();
            cards.push((masked_card, proof));
        }
        Ok(cards)
    }
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct MaskedCardDTO {
    pub masked_card: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShuffledDeck {
    pub cards: Vec<MaskedCardDTO>,
}

impl ShuffledDeck {
    pub fn new(masked_cards :Vec<MaskedCard>)->Result<Self,DeckCustomError>{
        let mut cards:Vec<crate::deck::models::deck_case::deck::MaskedCardDTO> = Vec::with_capacity(masked_cards.len());
        for masked_card in masked_cards{
            let card_hex = encode_masked_card(masked_card)?;
            cards.push(crate::deck::models::deck_case::deck::MaskedCardDTO {
                masked_card: card_hex,
            });
        }
        Ok(ShuffledDeck {
            cards:cards,
        })
    }

    pub fn into_masked_card(&self)-> Result<Vec<MaskedCard>,DeckCustomError>{
        let card_length = self.cards.len();
        let mut cards =Vec::with_capacity(card_length);
        for card in self.cards.clone().into_iter(){
            let masked_card = decode_masked_card(card.masked_card)?;
            cards.push(masked_card);
        }
        Ok(cards)
    }
}




#[derive(Debug, Serialize, Deserialize)]
pub struct OpenedCards {
    pub cards: Vec<ClassicPlayingCard>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateDeckResponse{
    pub deck: InitialDeck,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShuffleRequest{
    pub seed_hex: String,
    pub joined_key: String,
    pub cards: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ShuffleResponse{
    pub shuffle_proof: String,
    pub cards: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyShuffleRequest{
    pub joined_key: String,
    pub seed_hex: String,
    pub proof: String,
    pub origin_cards:  Vec<String>,
    pub shuffled_cards:  Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyShuffleResponse{

}


#[derive(Debug, Serialize, Deserialize)]
pub struct RevealCardsRequest{
    pub game_user_id:String,
    pub shuffled_deck: ShuffledDeck,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RevealCardsResponse{
    pub revealed_deck: RevealedDeck,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct RevealTokenRequest {
    pub game_user_id: String,
    pub seed_hex: String,
    pub reveal_cards: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RevealTokenDTO{
    pub token: String,
    pub proof: PedersenProofDTO,
    pub public_key: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RevealTokenResponse {
    pub token_map: HashMap<String, RevealTokenDTO>,
}



#[derive(Debug, Serialize, Deserialize)]
pub struct OpenCardsRequest{
    pub shuffled_deck: ShuffledDeck,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct OpenCardsResponse{
    pub opened_cards: OpenedCards,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevealedDeck {
    pub cards: Vec<RevealedCardAndProofDTO>,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct RevealedCardAndProofDTO {
    pub masked_card: MaskedCardDTO, // origin card
    pub reveal_token: String,
    pub proof:String,
}

impl RevealedDeck {
    pub fn new(deck_and_proofs :Vec<(MaskedCard,RevealToken, RevealProof)> )->Result<Self,DeckCustomError>{
        let mut cards:Vec<crate::deck::models::deck_case::deck::RevealedCardAndProofDTO> = Vec::with_capacity(deck_and_proofs.len());
        for deck_and_proof in deck_and_proofs {
            let card_hex = match encode_masked_card(deck_and_proof.0){
                Ok(revealed_card) => revealed_card,
                Err(_e) => return Err(DeckCustomError::InvalidCard),
            };

            let revel_token_hex = encode_revel_token(deck_and_proof.1)?;

            let proof_hex = encode_masking_proof(deck_and_proof.2)?;

            cards.push(RevealedCardAndProofDTO {
                masked_card: MaskedCardDTO{
                    masked_card: card_hex,
                },
                reveal_token: revel_token_hex,
                proof:proof_hex,
            })
        }

        Ok(RevealedDeck {
            cards:cards,
        })
    }
    pub fn into_masked_card(&self)-> Result<Vec<(RevealToken, RevealProof)>,DeckCustomError>{
        let card_length = self.cards.len();
        let mut cards =Vec::with_capacity(card_length);
        for card in self.cards.clone(){
            let reveal_token =  decode_revel_token(card.reveal_token)?;
            let reveal_proof = decode_revel_proof(card.proof)?;
            cards.push((reveal_token, reveal_proof));
        }
        Ok(cards)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeekCardInput{
    pub card: String,
    pub reveal_tokens:Vec<RevealTokenDTO>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeekCardsRequest {
    pub game_user_id: String,
    pub seed_hex: String,
    pub peek_cards: Vec<PeekCardInput>,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct PeekCardsResponse {
    pub card_map: HashMap<String,String>
}


#[derive(Debug, Serialize, Deserialize)]
pub struct MaskRequest{
    pub seed_hex: String,
    pub joined_key: String,
    pub cards: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct MaskedCardAndProofDTO {
    pub masked_card: String,
    pub proof:PedersenProofDTO,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MaskResponse{
    pub cards: Vec<MaskedCardAndProofDTO>,
}


#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct MaskDeck {
    pub cards: Vec<MaskedCardAndProofDTO>,
}

impl MaskDeck {
    pub fn new(deck_and_proofs :Vec<(MaskedCard, RemaskingProof)> )->Result<Self,DeckCustomError>{
        let mut cards:Vec<MaskedCardAndProofDTO> = Vec::with_capacity(deck_and_proofs.len());
        for deck_and_proof in deck_and_proofs {
            let card_hex = encode_masked_card(deck_and_proof.0)?;
            let proof = PedersenProof::new(deck_and_proof.1);
            cards.push(MaskedCardAndProofDTO {
                masked_card: card_hex,
                proof: PedersenProofDTO{
                    a:proof.a,
                    b:proof.b,
                    r:proof.r,
                },
            })
        }
        Ok(MaskDeck {
            cards:cards,
        })
    }
    pub fn into_masked_card(&self)-> Result<Vec<(MaskedCard, RemaskingProof)>,DeckCustomError>{
        let card_length = self.cards.len();
        let mut cards =Vec::with_capacity(card_length);
        for card in self.cards.clone().into_iter(){
            let masked_card = decode_masked_card(card.masked_card.clone())?;

            let pp = PedersenProof{
                a: card.proof.a,
                b:card.proof.b,
                r:card.proof.r,
            };

            let proof = pp.to_curve()?;
            cards.push((masked_card, proof));
        }
        Ok(cards)
    }
}

