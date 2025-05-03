use ark_ec::AffineCurve;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use starknet_curve::StarkwareParameters;
use ark_bn254::g1::Parameters as G1Parameters;

type PublicKey = GroupAffine<G1Parameters>;
type PrivateKey = <ark_ec::short_weierstrass_jacobian::GroupAffine<G1Parameters> as AffineCurve>::ScalarField;

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

#[derive(Clone)]
pub struct GameUser {
    pub game_user_id:String,
    pub user_id: String,
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
    pub cards: Vec<MaskedCard>,
}

impl GameUser {
    pub fn new(game_user_id:String,user_id:String,public_key: PublicKey,private_key: PrivateKey) -> Self {
        Self{
            game_user_id:game_user_id,
            user_id:user_id,
            public_key:public_key,
            private_key:private_key,
            cards: Vec::new(),
        }
    }
}