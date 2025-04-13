use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Deck {
    pub id: Option<String>,
    pub email: String,
    pub password: String,
    pub name: String,
}
