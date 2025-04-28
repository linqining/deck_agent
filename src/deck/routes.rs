use rocket::response::status;
use rocket::{ State, http::Status};
use rocket::serde::json::Json;

use crate::deck::models::deck_case::deck::{ComputeAggregateKeyRequest, ComputeAggregateKeyResponse, InitialDeckRequest, InitialDeckResponse, SetUpDeckRequest, SetUpDeckResponse};
use crate::user::service::UserServiceTrait;
use crate::core::api_response::ErrorResponse;
use crate::deck::errors::DeckCustomError;
use crate::deck::service::{DeckService, DeckServiceTrait};
use crate::user::errors::CustomError;



#[post("/deck/setup", data = "<setup>")]
pub async fn setup(deck_service: &State<Box<dyn DeckServiceTrait>>, setup: Json<SetUpDeckRequest>) -> Result<status::Custom<Json<SetUpDeckResponse>>, status::Custom<Json<ErrorResponse>>> {
    let new_setup = SetUpDeckRequest {
        ..setup.into_inner()
    };

    let setup_result = deck_service.setup(new_setup).await;

    let setup_response = match setup_result {
        Ok(response) => response,
        Err(err) => {
            match err {
                DeckCustomError::GenericError(msg) => return Err(status::Custom(Status::InternalServerError, Json(ErrorResponse { message: msg }))),
                DeckCustomError::MissingFields(msg) => return Err(status::Custom(Status::BadRequest, Json(ErrorResponse { message: format!("The following properties are required: {}", msg) }))),
                DeckCustomError::InvalidPublicKey => return Err(status::Custom(Status::BadRequest,Json(ErrorResponse{message: format!("invalid public key")}))),
                DeckCustomError::InvalidProof=>return Err(status::Custom(Status::BadRequest,Json(ErrorResponse{message: format!("invalid proof")}))),
                _ => return Err(status::Custom(Status::InternalServerError, Json(ErrorResponse { message: err.to_string() }))),
            }
        }
    };

    Ok(status::Custom(Status::Created, Json(SetUpDeckResponse {
        ..setup_response
    })))
}

#[get("/deck/initialize")]
pub async fn initialize(deck_service: &State<Box<dyn DeckServiceTrait>>, ) -> Result<status::Custom<Json<InitialDeckResponse>>, status::Custom<Json<ErrorResponse>>> {
    let initial_result = deck_service.initial_deck(InitialDeckRequest{}).await;
    let initialize_response = match initial_result {
        Ok(response) => response,
        Err(err) => {
            match err {
                DeckCustomError::GenericError(msg) => return Err(status::Custom(Status::InternalServerError, Json(ErrorResponse { message: msg }))),
                DeckCustomError::MissingFields(msg) => return Err(status::Custom(Status::BadRequest, Json(ErrorResponse { message: format!("The following properties are required: {}", msg) }))),
                DeckCustomError::InvalidPublicKey => return Err(status::Custom(Status::BadRequest,Json(ErrorResponse{message: format!("invalid public key")}))),
                DeckCustomError::InvalidProof=>return Err(status::Custom(Status::BadRequest,Json(ErrorResponse{message: format!("invalid proof")}))),
                _ => return Err(status::Custom(Status::InternalServerError, Json(ErrorResponse { message: err.to_string() }))),
            }
        }
    };

    Ok(status::Custom(Status::Created, Json(InitialDeckResponse {
        ..initialize_response
    })))
}

#[post("/deck/compute_aggregate_key", data = "<compute_aggregate>")]
pub async fn compute_aggregate_key(deck_service: &State<Box<dyn DeckServiceTrait>>,compute_aggregate: Json<ComputeAggregateKeyRequest> ) -> Result<status::Custom<Json<ComputeAggregateKeyResponse>>, status::Custom<Json<ErrorResponse>>> {
    let new_compute_agg = ComputeAggregateKeyRequest {
        ..compute_aggregate.into_inner()
    };
    let compute_agg_response = deck_service.compute_aggregate_key(new_compute_agg).await;
    let setup_response = match compute_agg_response {
        Ok(response) => response,
        Err(err) => {
            match err {
                DeckCustomError::GenericError(msg) => return Err(status::Custom(Status::InternalServerError, Json(ErrorResponse { message: msg }))),
                DeckCustomError::MissingFields(msg) => return Err(status::Custom(Status::BadRequest, Json(ErrorResponse { message: format!("The following properties are required: {}", msg) }))),
                DeckCustomError::InvalidPublicKey => return Err(status::Custom(Status::BadRequest,Json(ErrorResponse{message: format!("invalid public key")}))),
                DeckCustomError::InvalidProof=>return Err(status::Custom(Status::BadRequest,Json(ErrorResponse{message: format!("invalid proof")}))),
                _ => return Err(status::Custom(Status::InternalServerError, Json(ErrorResponse { message: err.to_string() }))),
            }
        }
    };

    Ok(status::Custom(Status::Created, Json(ComputeAggregateKeyResponse {
        ..setup_response
    })))
}

#[cfg(test)]
mod e2e_tests {
    use crate::serialize::serialize::{decode_proof, encode_proof};
    #[test]

    fn test_decode_proof(){
        let proof =String::from("ed2e42a6c7081979ea7f0ceba9b8f8fff958e94a1e6a62a91f48389064f3948297e271c46326c4701348e947f8aaff57326e54e89cda87d23b6ba4371d39e305");
        let decode_proof = decode_proof(proof.clone()).unwrap();
        let reencode_proof = encode_proof(decode_proof).unwrap();
        println!("reencode_proof: {:?}", reencode_proof);
        assert_eq!(proof.clone(), reencode_proof.clone());
    }

}