use barnett_smart_card_protocol::Reveal;
use rocket::response::status;
use rocket::{ State, http::Status};
use rocket::futures::stream::Peek;
use rocket::serde::json::Json;

use crate::deck::models::deck_case::deck::{ClearRequest, ClearResponse, ComputeAggregateKeyRequest, ComputeAggregateKeyResponse, InitialDeckRequest, InitialDeckResponse, MaskRequest, MaskResponse, PeekCardsRequest, PeekCardsResponse, RevealTokenRequest, RevealTokenResponse, SetUpDeckRequest, SetUpDeckResponse, ShuffleRequest, ShuffleResponse, VerifyShuffleRequest, VerifyShuffleResponse};
use crate::user::service::UserServiceTrait;
use crate::core::api_response::ErrorResponse;
use crate::deck::errors::DeckCustomError;
use crate::deck::service::{ DeckServiceTrait};



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

#[post("/deck/clear", data = "<clear>")]
pub async fn clear(deck_service: &State<Box<dyn DeckServiceTrait>>, clear: Json<ClearRequest>) -> Result<status::Custom<Json<ClearResponse>>, status::Custom<Json<ErrorResponse>>> {
    let new_clear = ClearRequest {
        ..clear.into_inner()
    };

    let clear_result = deck_service.clear(new_clear).await;

    let clear_response = match clear_result {
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

    Ok(status::Custom(Status::Created, Json(ClearResponse {
        ..clear_response
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


#[post("/deck/mask", data = "<mask_req>")]
pub async fn mask(deck_service: &State<Box<dyn DeckServiceTrait>>,mask_req: Json<MaskRequest> ) -> Result<status::Custom<Json<MaskResponse>>, status::Custom<Json<ErrorResponse>>> {
    let mask_request = MaskRequest {
        ..mask_req.into_inner()
    };
    let mask_response = deck_service.mask(mask_request).await;
    let mask_response = match mask_response {
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

    Ok(status::Custom(Status::Created, Json(MaskResponse {
        ..mask_response
    })))
}

#[post("/deck/shuffle", data = "<shuffle_req>")]
pub async fn shuffle(deck_service: &State<Box<dyn DeckServiceTrait>>,shuffle_req: Json<ShuffleRequest> ) -> Result<status::Custom<Json<ShuffleResponse>>, status::Custom<Json<ErrorResponse>>> {
    let shuffle_request = ShuffleRequest {
        ..shuffle_req.into_inner()
    };
    let shuffle_response = deck_service.shuffle(shuffle_request).await;
    let shuffle_response = match shuffle_response {
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

    Ok(status::Custom(Status::Created, Json(ShuffleResponse {
        ..shuffle_response
    })))
}

#[post("/deck/verify_shuffle", data = "<verify_shuffle_req>")]
pub async fn verify_shuffle(deck_service: &State<Box<dyn DeckServiceTrait>>,verify_shuffle_req: Json<VerifyShuffleRequest> ) -> Result<status::Custom<Json<VerifyShuffleResponse>>, status::Custom<Json<ErrorResponse>>> {
    let verify_shuffle_request = VerifyShuffleRequest {
        ..verify_shuffle_req.into_inner()
    };
    let verify_shuffle_response = deck_service.verify_shuffle(verify_shuffle_request).await;
    let verify_shuffle_response = match verify_shuffle_response {
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

    Ok(status::Custom(Status::Ok, Json(VerifyShuffleResponse {
        ..verify_shuffle_response
    })))
}

#[post("/deck/reveal_token", data = "<revel_token_req>")]
pub async fn reveal_token(deck_service: &State<Box<dyn DeckServiceTrait>>,revel_token_req: Json<RevealTokenRequest> ) -> Result<status::Custom<Json<RevealTokenResponse>>, status::Custom<Json<ErrorResponse>>> {
    let reveal_token_request = RevealTokenRequest {
        ..revel_token_req.into_inner()
    };
    let reveal_token_response = deck_service.reveal_token(reveal_token_request).await;
    let reveal_token_response = match reveal_token_response {
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

    Ok(status::Custom(Status::Ok, Json(RevealTokenResponse {
        ..reveal_token_response
    })))
}

#[post("/deck/peek_cards", data = "<peek_cards_req>")]
pub async fn peek_cards(deck_service: &State<Box<dyn DeckServiceTrait>>,peek_cards_req: Json<PeekCardsRequest> ) -> Result<status::Custom<Json<PeekCardsResponse>>, status::Custom<Json<ErrorResponse>>> {
    let peek_cards_request = PeekCardsRequest {
        ..peek_cards_req.into_inner()
    };
    let peek_card_response = deck_service.peek_cards(peek_cards_request).await;
    let peek_card_response = match peek_card_response {
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

    Ok(status::Custom(Status::Ok, Json(PeekCardsResponse {
        ..peek_card_response
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