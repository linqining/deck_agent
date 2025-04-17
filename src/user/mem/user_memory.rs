use std::collections::HashMap;
use rocket::yansi::Paint;
use crate::user::{errors::CustomError, models::{user::User, use_case::user::GetUserResponse}};
use crate::user::repository::UserMemTrait;

pub struct UserMem {
    store: HashMap<String, User>,
}

impl UserMem {
    pub  fn new() -> Self {
        UserMem{
            store:HashMap::new(),
        }
    }
}

impl UserMemTrait for UserMem {
     fn get_by_id(&self, id: &str) -> Result<GetUserResponse, CustomError> {
        let user = match self.store.get(id){
            Some(user) => user.clone(),
            None => return Err(CustomError::UserNotFound),
        };
        Ok(GetUserResponse{id:user.id.as_ref().unwrap().clone(),name:String::from(""),email:String::from("")})
    }

     fn create(&mut self, user: User) -> Result<String, CustomError> {
        if user.id.is_none() {
            return Err(CustomError::GenericError(String::from("user id empty")));
        }
        let user_id = user.id.as_ref().unwrap().to_string();
        self.store.insert(user_id.clone(), user);
        Ok(user_id)
    }

     fn delete(&mut self, id: &str) -> Result<(), CustomError> {
        self.store.remove(id);
        Ok(())
    }
}



