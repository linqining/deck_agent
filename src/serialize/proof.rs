use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_serialize::{CanonicalSerialize, SerializationError,CanonicalDeserialize};
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
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
type ZKProofMasking = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type Affine = starknet_curve::Affine;
type Scalar = <ark_ec::short_weierstrass_jacobian::GroupAffine<StarkwareParameters> as AffineCurve>::ScalarField;




#[derive(Clone, Debug)]
pub struct IdentityProof {
    pub commit:String,
    pub opening:String,
}

impl IdentityProof {
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
        let  commit_bytes = match Vec::from_hex(&self.commit) {
            Ok(bytes) => bytes,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };

        let affine_commit  = match Curve::read(&mut commit_bytes.reader()){
            Ok(affine_commit) => affine_commit,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };

        let  opening_bytes = match Vec::from_hex(&self.opening) {
            Ok(bytes) => bytes,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };

        let opening: Scalar = match Scalar::read(&mut opening_bytes.reader()){
            Ok(opening) => opening,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };
        Ok(ZKProof{
            random_commit:affine_commit,
            opening:opening,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PedersenProof {
    pub a:String,
    pub b:String,
    pub r:String,
}

impl PedersenProof {
    pub fn new(proof: ZKProofMasking) -> Self{
        let mut a_bytes = Vec::new();
        proof.a.write(&mut a_bytes).unwrap();
        let mut b_bytes = Vec::new();
        proof.b.write(&mut b_bytes).unwrap();

        let mut r_bytes = Vec::new();
        proof.r.write(&mut r_bytes).unwrap();
        Self{
            a: hex::encode(&a_bytes),
            b:hex::encode(&b_bytes),
            r:hex::encode(&r_bytes),
        }
    }

    pub fn to_curve(&self)-> Result<ZKProofMasking, DeckCustomError>  {
        let  a_bytes = match Vec::from_hex(&self.a) {
            Ok(bytes) => bytes,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };
        let  b_bytes = match Vec::from_hex(&self.b) {
            Ok(bytes) => bytes,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };
        let  r_bytes = match Vec::from_hex(&self.r) {
            Ok(bytes) => bytes,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };

        let a  = match Curve::read(&mut a_bytes.reader()){
            Ok(affine_commit) => affine_commit,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };
        let b  = match Curve::read(&mut b_bytes.reader()){
            Ok(affine_commit) => affine_commit,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };

        let r: Scalar = match Scalar::read(&mut r_bytes.reader()){
            Ok(opening) => opening,
            Err(_err)    => return Err(DeckCustomError::InvalidProof)
        };

        Ok(ZKProofMasking{
            a:a,
            b:b,
            r:r,
        })
    }
}




