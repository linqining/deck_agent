mod deck;
mod serialize;
mod card;
mod game_user;

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
    pub mod mem{
        pub mod user_memory;
    }
}

pub mod core {
    pub mod api_response;
}

use std::future::IntoFuture;
use user::mem::user_memory::UserMem;
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
use crate::game_user::mem::game_user_mem::GameUserMem;

#[launch]
async fn rocket() -> _ {
    dotenv().ok();

    // let mongo_uri = env::var("MONGO_DB_URI").expect("MONGO_URI not found in environment variables");
    // let mongo_db_name = env::var("MONGO_DB_NAME").expect("MONGO_DB_NAME not found in environment variables");
    let mongo_uri = String::from("mongodb://localhost:27017");
    let mongo_db_name = String::from("user");
    let mongo_repo = UserMongo::new(&mongo_uri, &mongo_db_name).await.unwrap();
    let user_repo = Box::new(mongo_repo);
    // TODO 暂时占用，后面再处理
    let user_mongo_repo = UserMongo::new(&mongo_uri, &mongo_db_name).await.unwrap();


    let game_user_mem_repo = Box::new(GameUserMem::new());

    let user_service: Box<dyn UserServiceTrait> = Box::new(UserService::new(Box::new(user_mongo_repo)));
    let deck_service: Box<dyn DeckServiceTrait> = Box::new(DeckService::new(game_user_mem_repo));

    rocket::build()
        .manage(user_service)
        .mount("/", routes![user::routes::get_by_id])
        .mount("/", routes![user::routes::create])
        .mount("/", routes![user::routes::delete])
        .manage(deck_service)
        .mount("/",routes![deck::routes::initialize])
        .mount("/",routes![deck::routes::setup])
        .mount("/",routes![deck::routes::compute_aggregate_key])
        .mount("/",routes![deck::routes::mask])
}
