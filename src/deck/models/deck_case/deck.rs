use std::ffi::c_void;
use std::io::{Read, Write};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize, SWFlags, SerializationError};
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use serde::{Serialize, Deserialize};
use crate::card::classic_card::ClassicPlayingCard;

type Curve = starknet_curve::Projective;
type CardProtocol = barnett_smart_card_protocol::discrete_log_cards::DLCards<Curve>;
// type Card = barnett_smart_card_protocol::discrete_log_cards::Card<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
use crate::deck::errors::DeckCustomError;
use crate::serialize::serialize::{decode_masked_card, decode_masking_proof, encode_masked_card, encode_masking_proof};

type MaskedCard = barnett_smart_card_protocol::discrete_log_cards::MaskedCard<Curve>;
type RevealToken = barnett_smart_card_protocol::discrete_log_cards::RevealToken<Curve>;

#[derive(Debug, Serialize, Deserialize)]
pub struct SetUpDeckRequest{
    pub user_id: String, // user_id provide by the agent service
    pub game_id: String,
    pub game_user_id: String, // user identity among this round
    // pub m:usize,
    // pub n:usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetUpDeckResponse{
    pub user_id:String,
    pub game_id:String,
    pub game_user_id:String,
    pub user_public_key:Vec<u8>,
    pub user_key_proof:Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Player{
    pub game_id:String,
    pub game_user_id:String,
    name: Vec<u8>,
    pub public_key: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeAggregateKeyRequest {
    pub players: Vec<Player>
}


#[derive(Debug, Serialize, Deserialize)]
pub struct ComputeAggregateKeyResponse{
    pub joined_key: Vec<u8>, // if accept other player's proof, return the joined key of all player
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateDeckRequest{
    pub joined_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct MaskedCardAndProofDTO {
    pub masked_card: Vec<u8>,
    pub proof:Vec<u8>,
}
#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct InitialDeck {
    pub cards: Vec<MaskedCardAndProofDTO>,
}

impl InitialDeck {
    pub fn new(deck_and_proofs :Vec<(MaskedCard, RemaskingProof)> )->Result<Self,SerializationError>{
        let mut cards:Vec<crate::deck::models::deck_case::deck::MaskedCardAndProofDTO> = Vec::with_capacity(deck_and_proofs.len());
        for deck_and_proof in deck_and_proofs {
            let mut encoded_card = Vec::new();
            encode_masked_card(deck_and_proof.0,&mut encoded_card)?;
            let mut encoded_proof = Vec::new();
            encode_masking_proof(deck_and_proof.1,&mut encoded_proof)?;
            cards.push(crate::deck::models::deck_case::deck::MaskedCardAndProofDTO {
                masked_card: encoded_card,
                proof:encoded_proof,
            })
        }

        Ok(InitialDeck {
            cards:cards,
        })
    }
    pub fn into_masked_card(&self)-> Result<Vec<(MaskedCard, RemaskingProof)>,ark_serialize::SerializationError>{
        let card_length = self.cards.len();
        let mut cards =Vec::with_capacity(card_length);
        for card in self.cards.clone().into_iter(){
            let masked_card = decode_masked_card(card.masked_card)?;
            let proof = decode_masking_proof(card.proof)?;
            cards.push((masked_card, proof));
        }
        Ok(cards)
    }
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct MaskedCardDTO {
    pub masked_card: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShuffledDeck {
    pub cards: Vec<MaskedCardDTO>,
}

impl ShuffledDeck {
    pub fn new(masked_cards :Vec<MaskedCard>)->Result<Self,SerializationError>{
        let mut cards:Vec<crate::deck::models::deck_case::deck::MaskedCardDTO> = Vec::with_capacity(masked_cards.len());
        for masked_card in masked_cards{
            let mut encoded_masked_card = Vec::new();
            encode_masked_card(masked_card, &mut encoded_masked_card)?;
            cards.push(crate::deck::models::deck_case::deck::MaskedCardDTO {
                masked_card: encoded_masked_card,
            });
        }
        Ok(ShuffledDeck {
            cards:cards,
        })
    }

    pub fn into_masked_card(&self)-> Result<Vec<MaskedCard>,ark_serialize::SerializationError>{
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
    pub deck: ShuffledDeck,
    pub joined_key: Vec<u8>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ShuffleResponse{
    pub deck: ShuffledDeck,
    pub shuffle_proof: Vec<u8>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyShuffleRequest{
    pub proof: Vec<u8>,
    pub joined_key: Vec<u8>,
    pub origin_deck: ShuffledDeck,
    pub shuffled_deck: ShuffledDeck,
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
pub struct ReceiveAndRevealTokenRequest{
    pub game_user_id:String,
    pub received_cards: Vec<MaskedCardDTO>,
    pub shuffled_deck: ShuffledDeck,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ReceiveAndRevealTokenResponse{
    pub revealed_deck: RevealedDeck,
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
    pub revealed_card: Vec<u8>,
    pub proof:Vec<u8>,
}

impl RevealedDeck {
    pub fn new(deck_and_proofs :Vec<(MaskedCard,RevealToken, RevealProof)> )->Result<Self,SerializationError>{
        let mut cards:Vec<crate::deck::models::deck_case::deck::RevealedCardAndProofDTO> = Vec::with_capacity(deck_and_proofs.len());
        for deck_and_proof in deck_and_proofs {
            let mut masked_card = Vec::new();
            encode_masked_card(deck_and_proof.0, &mut masked_card)?;

            let mut revealed_card = Vec::new();
            deck_and_proof.1.serialize_uncompressed(&mut revealed_card)?;

            let mut encoded_proof = Vec::new();
            encode_masking_proof(deck_and_proof.2,&mut encoded_proof)?;

            cards.push(RevealedCardAndProofDTO {
                masked_card: MaskedCardDTO{
                    masked_card: masked_card,
                },
                revealed_card: revealed_card,
                proof:encoded_proof,
            })
        }

        Ok(RevealedDeck {
            cards:cards,
        })
    }
    pub fn into_masked_card(&self)-> Result<Vec<(RevealToken, RevealProof)>,ark_serialize::SerializationError>{
        let card_length = self.cards.len();
        let mut cards =Vec::with_capacity(card_length);
        for card in self.cards.clone(){
            let revealed_card = RevealToken::deserialize(&*card.revealed_card)?;
            let revealed_proof = RevealProof::deserialize(&*card.proof)?;
            cards.push((revealed_card, revealed_proof));
        }
        Ok(cards)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeekCardsRequest {
    pub cards: Vec<RevealedCardAndProofDTO>,
}

#[derive(Debug, Serialize, Deserialize,Clone)]
pub struct PeekCardsResponse {
}

