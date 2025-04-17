use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize,Clone)]
pub struct User {
    pub id: Option<String>,
    pub email: String,
    pub password: String,
    pub name: String,
}
