use crate::user::errors::CustomError;

use super::models::game_user::GameUser;

#[cfg(test)]
use mockall::automock;

// #[cfg_attr(test, automock)]
// #[async_trait]
// pub trait UserDbTrait: Sync + Send {
//     async fn get_by_id(&self, id: &str) -> Result<GetUserResponse, CustomError>;
//     async fn create(&self, user: User) -> Result<String, CustomError>;
//     async fn delete(&self, id: &str) -> Result<(), CustomError>;
// }
#[cfg_attr(test,  )]
pub trait GameUserMemTrait: Sync + Send {
     fn get_by_id(&self, id: &str) -> Result<& GameUser, CustomError>;
     fn create(&mut self, game_user: GameUser) -> Result<String, CustomError>;
     fn delete(&mut self, id: &str) -> Result<(), CustomError>;
}

