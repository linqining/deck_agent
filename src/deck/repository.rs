use crate::user::models::user::User;
use crate::user::errors::CustomError;


#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait UserDbTrait: Sync + Send {
    async fn create(&self, user: User) -> Result<String, CustomError>;
    async fn delete(&self, id: &str) -> Result<(), CustomError>;
}
