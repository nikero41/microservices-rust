use crate::errors::AuthError;

mod memory;

pub use memory::MemoryUsers;

pub trait UserStore {
    fn create_user(&mut self, username: String, password: String) -> Result<(), AuthError>;
    fn user_exists(&self, username: &str) -> bool;
    fn authenticate(&self, username: &str, password: &str) -> Result<String, AuthError>;
    fn delete_user(&mut self, user_uuid: String) -> Result<(), AuthError>;
}
