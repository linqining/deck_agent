mod deck;
mod key_export;

#[macro_use]
extern crate rocket;

pub mod user {
    pub mod models {
        pub mod user;
        pub mod use_case;
    }
    pub mod routes;
    pub mod service;
    pub mod errors;
    pub mod repository;
    pub mod db {
        pub mod mock;
        pub mod mongo;
    }
}

pub mod core {
    pub mod api_response;
}

use user::db::mongo::user_mongo::UserMongo;
use dotenv::dotenv;
// use std::env;
use user::service::{
    UserService, 
    UserServiceTrait};
use deck::service::{
    DeckService,
    DeckServiceTrait,
};

#[launch]
async fn rocket() -> _ {
    dotenv().ok();

    // let mongo_uri = env::var("MONGO_DB_URI").expect("MONGO_URI not found in environment variables");
    // let mongo_db_name = env::var("MONGO_DB_NAME").expect("MONGO_DB_NAME not found in environment variables");
    let mongo_uri = String::from("mongodb://localhost:27017");
    let mongo_db_name = String::from("user");
    let mongo_repo = UserMongo::new(&mongo_uri, &mongo_db_name).await.unwrap();
    let user_service: Box<dyn UserServiceTrait> = Box::new(UserService::new(Box::new(mongo_repo)));
    let deck_service: Box<dyn DeckServiceTrait> = Box::new(DeckService::new());

    rocket::build()
        .manage(user_service)
        .mount("/", routes![user::routes::get_by_id])
        .mount("/", routes![user::routes::create])
        .mount("/", routes![user::routes::delete])
        .manage(deck_service)
        .mount("/",routes![deck::routes::setup])
}
