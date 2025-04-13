use rocket::response::status;
use rocket::{ State, http::Status};
use rocket::serde::json::Json;

use crate::deck::models::deck_case::deck::{ SetUpDeckRequest, SetUpDeckResponse};
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
                DeckCustomError::InvalidSeed => return Err(status::Custom(Status::BadRequest,Json(ErrorResponse{message: format!("invalid seed")}))),
                _ => return Err(status::Custom(Status::InternalServerError, Json(ErrorResponse { message: err.to_string() }))),
            }
        }
    };

    Ok(status::Custom(Status::Created, Json(SetUpDeckResponse {
        ..setup_response
    })))
}

#[delete("/user/<id>")]
pub async fn delete(user_service: &State<Box<dyn UserServiceTrait>>, id: &str) -> Result<status::Custom<()>, status::Custom<Json<ErrorResponse>>> {
    let delete_result = user_service.delete(id).await;

    if let Err(err) = delete_result {
        match err {
            CustomError::GenericError(msg) => return Err(status::Custom(Status::InternalServerError, Json(ErrorResponse { message: msg }))),
            CustomError::MissingFields(msg) => return Err(status::Custom(Status::BadRequest, Json(ErrorResponse { message: format!("The following properties are required: {}", msg) }))),
            _ => return Err(status::Custom(Status::InternalServerError, Json(ErrorResponse { message: err.to_string() }))),
        }
    }

    Ok(status::Custom(Status::Ok, ()))
}

#[cfg(test)]
mod e2e_tests {
    use crate::user::db::mongo::user_mongo::UserMongo;
    use crate::user::service::UserService;

    use super::*;
    use rocket::local::asynchronous::Client;
    use rocket::http::{Status, ContentType};
    use rocket::tokio;

    const MONGO_URI_TEST: &str = "mongodb://localhost:27018";
    const DB_NAME: &str = "dev";

    #[tokio::test]
    async fn test_create_user() {
        let user_mongo = UserMongo::new(MONGO_URI_TEST, DB_NAME).await.unwrap();

        let user_service: Box<dyn UserServiceTrait> = Box::new(UserService::new(Box::new(user_mongo)));

        let rocket = rocket::build()
            .manage(user_service)
            .mount("/", routes![create]);
        let client = Client::untracked(rocket).await.unwrap();

        let request = CreateUserRequest {
            name: "Test User".into(),
            email: "test@example.com".into(),
            plain_password: "password".into(),
        };

        let response = client.post("/user")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&request).unwrap())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Created);

        let response_body: CreateUserResponse = serde_json::from_str(&
            response.into_string().await.unwrap()).unwrap();
        
        assert_ne!(response_body.id, "");
    }

    #[tokio::test]
    async fn test_create_user_bad_request() {
        let user_mongo = UserMongo::new(MONGO_URI_TEST, DB_NAME).await.unwrap();
        let user_service: Box<dyn UserServiceTrait> = Box::new(UserService::new(Box::new(user_mongo)));

        let rocket = rocket::build()
            .manage(user_service)
            .mount("/", routes![create]);
        let client = Client::untracked(rocket).await.unwrap();

        let request = CreateUserRequest {
            name: "".into(),
            email: "test@example.com".into(),
            plain_password: "password".into(),
        };

        let response = client
            .post("/user")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&request).unwrap())
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::BadRequest);

        let response_body = response.into_string().await.unwrap();
        assert!(response_body.contains("The following properties are required"));
    }

    #[tokio::test]
    async fn test_get_user() {
        let user_mongo = UserMongo::new(MONGO_URI_TEST, DB_NAME).await.unwrap();

        let user_service: Box<dyn UserServiceTrait> = Box::new(UserService::new(Box::new(user_mongo)));

        let rocket = rocket::build()
            .manage(user_service)
            .mount("/", routes![create])
            .mount("/", routes![get_by_id]);
        let client = Client::untracked(rocket).await.unwrap();

        let create_request = CreateUserRequest {
            name: "Test User".into(),
            email: "test@example.com".into(),
            plain_password: "password".into(),
        };

        let create_response = client
            .post("/user")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&create_request).unwrap())
            .dispatch()
            .await;

        assert_eq!(create_response.status(), Status::Created);

        let create_response_body: CreateUserResponse =
            serde_json::from_str(&create_response.into_string().await.unwrap()).unwrap();
        
        let created_user_id = create_response_body.id;

        let get_response = client
            .get(format!("/user/{}", created_user_id))
            .dispatch()
            .await;

        assert_eq!(get_response.status(), Status::Ok);

        let get_response_body: GetUserResponse =
            serde_json::from_str(&get_response.into_string().await.unwrap()).unwrap();
        assert_eq!(get_response_body.id, created_user_id);
        assert_ne!(get_response_body.name, "");
        assert_ne!(get_response_body.email, "");
    }

    #[tokio::test]
    async fn test_get_user_not_found() {
        let user_mongo = UserMongo::new(MONGO_URI_TEST, DB_NAME).await.unwrap();

        let user_service: Box<dyn UserServiceTrait> = Box::new(UserService::new(Box::new(user_mongo)));

        let rocket = rocket::build()
            .manage(user_service)
            .mount("/", routes![get_by_id]);
        let client = Client::untracked(rocket).await.unwrap();

        let get_response = client
            .get("/user/6596be2aed81fa8f5b037c9f")
            .dispatch()
            .await;

        assert_eq!(get_response.status(), Status::NotFound);
    }

    #[tokio::test]
    async fn test_delete_user() {
        let user_mongo = UserMongo::new(MONGO_URI_TEST, DB_NAME).await.unwrap();
        let user_service: Box<dyn UserServiceTrait> = Box::new(UserService::new(Box::new(user_mongo)));

        let rocket = rocket::build()
            .manage(user_service)
            .mount("/", routes![create])
            .mount("/", routes![delete]);
        let client = Client::untracked(rocket).await.expect("valid rocket instance");

        let create_request = CreateUserRequest {
            name: "Test User".into(),
            email: "test@example.com".into(),
            plain_password: "password".into(),
        };

        let create_response = client
            .post("/user")
            .header(ContentType::JSON)
            .body(serde_json::to_string(&create_request).unwrap())
            .dispatch()
            .await;

        assert_eq!(create_response.status(), Status::Created);

        let create_response_body: CreateUserResponse =
            serde_json::from_str(&create_response.into_string().await.unwrap()).unwrap();
        
        let created_user_id = create_response_body.id;

        let response = client.delete(format!("/user/{}", created_user_id)).dispatch().await;

        assert_eq!(response.status(), Status::Ok);
    }
}