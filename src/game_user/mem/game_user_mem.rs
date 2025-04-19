use std::collections::HashMap;
use crate::game_user::models::game_user::GameUser;
use crate::user::errors::CustomError;
use crate::user::models::use_case::user::GetUserResponse;
use crate::user::models::user::User;
use crate::game_user::repository::GameUserMemTrait;

pub struct GameUserMem {
    store: HashMap<String, GameUser>,
}

impl GameUserMem {
    pub  fn new() -> Self {
        GameUserMem {
            store:HashMap::new(),
        }
    }
}

impl GameUserMemTrait for GameUserMem {
    fn get_by_id(&self,game_user_id: &str) -> Result<&GameUser, CustomError> {
        let user = match self.store.get(game_user_id){
            Some(game_user) => game_user,
            None => return Err(CustomError::UserNotFound),
        };
        Ok(user)
    }

    fn create(&mut self, user: GameUser) -> Result<String, CustomError> {
        if user.game_user_id.is_empty(){
            return Err(CustomError::GenericError(String::from("user game_user_id empty")));
        }
        let game_user_id = user.game_user_id.clone();
        self.store.insert(user.game_user_id.clone(), user);
        Ok(game_user_id)
    }

    fn delete(&mut self, id: &str) -> Result<(), CustomError> {
        self.store.remove(id);
        Ok(())
    }
}



