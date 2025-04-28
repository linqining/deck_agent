use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_serialize::{CanonicalSerialize, SerializationError,CanonicalDeserialize};
use proof_essentials::zkp::proofs::schnorr_identification;
use rocket::http::hyper::body::Buf;
use hex::FromHex;
use starknet_curve::StarkwareParameters;
use ark_ec::short_weierstrass_jacobian::{GroupAffine, GroupProjective};
use ark_serialize::Write;
use ark_serialize::Read;
use ark_ff::{bytes::{FromBytes, ToBytes}};
use crate::deck::errors::DeckCustomError;

type Curve = starknet_curve::Projective;
type ZKProof = schnorr_identification::proof::Proof<Curve>;
type Affine = starknet_curve::Affine;
type Scalar = <ark_ec::short_weierstrass_jacobian::GroupAffine<StarkwareParameters> as AffineCurve>::ScalarField;




#[derive(Clone, Debug)]
pub struct ProofThird {
    pub commit:String,
    pub opening:String,
}

impl ProofThird {
    pub fn new(proof: ZKProof) -> Self{
        let mut proof_bytes = Vec::new();
        proof.random_commit.write(&mut proof_bytes).unwrap();

        let mut opening_bytes = Vec::new();
        proof.opening.write(&mut opening_bytes).unwrap();
        Self{
            commit: hex::encode(&proof_bytes),
            opening: hex::encode(&opening_bytes),
        }
    }

    pub fn to_curve(&self)-> Result<ZKProof, DeckCustomError>  {
        let mut commit_bytes = match Vec::from_hex(&self.commit) {
            Ok(bytes) => bytes,
            Err(err)    => return Err(DeckCustomError::InvalidProof)
        };

        let affine_commit  = match Curve::read(&mut commit_bytes.reader()){
            Ok(affine_commit) => affine_commit,
            Err(err)    => return Err(DeckCustomError::InvalidProof)
        };

        let mut opening_bytes = match Vec::from_hex(&self.opening) {
            Ok(bytes) => bytes,
            Err(err)    => return Err(DeckCustomError::InvalidProof)
        };

        let opening: Scalar = match Scalar::read(&mut opening_bytes.reader()){
            Ok(opening) => opening,
            Err(err)    => return Err(DeckCustomError::InvalidProof)
        };
        Ok(ZKProof{
            random_commit:affine_commit,
            opening:opening,
        })
    }
}



