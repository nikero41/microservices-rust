use crate::{errors::AuthError, users::UserStore};
use pbkdf2::{
    Pbkdf2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use uuid::Uuid;

use std::collections::HashMap;

#[derive(Clone)]
pub struct User {
    user_uuid: String,
    username: String,
    password: String,
}

#[derive(Default)]
pub struct MemoryUsers {
    uuid_to_user: HashMap<String, User>,
    username_to_user: HashMap<String, User>,
}

impl UserStore for MemoryUsers {
    fn create_user(&mut self, username: String, password: String) -> Result<(), AuthError> {
        if self.username_to_user.contains_key(&username) {
            return Err(AuthError::UsernameAlreadyExists);
        }

        let salt = SaltString::generate(&mut OsRng);

        let hashed_password = Pbkdf2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::InternalError(e.to_string()))?
            .to_string();

        let user_uuid = Uuid::new_v4();

        let user = User {
            user_uuid: user_uuid.to_string(),
            username: username.clone(),
            password: hashed_password,
        };

        self.username_to_user.insert(username, user.clone());
        self.uuid_to_user.insert(user_uuid.to_string(), user);

        Ok(())
    }

    fn user_exists(&self, username: &str) -> bool {
        self.username_to_user.contains_key(username)
    }

    fn authenticate(&self, username: &str, password: &str) -> Result<String, AuthError> {
        let user = self
            .username_to_user
            .get(username)
            .ok_or(AuthError::InvalidCredentials)?;

        let parsed_hash = PasswordHash::new(&user.password)
            .map_err(|e| AuthError::InternalError(e.to_string()))?;

        match Pbkdf2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(_) => Ok(user.user_uuid.clone()),
            Err(_) => Err(AuthError::InvalidCredentials),
        }
    }

    fn delete_user(&mut self, user_uuid: String) -> Result<(), AuthError> {
        let user = self.uuid_to_user.remove(&user_uuid);
        if let Some(user) = user {
            match self.username_to_user.remove(&user.username) {
                Some(_) => Ok(()),
                None => Err(AuthError::InvalidRequest),
            }
        } else {
            Err(AuthError::InvalidRequest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_user() {
        let mut user_service = MemoryUsers::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert_eq!(user_service.uuid_to_user.len(), 1);
        assert_eq!(user_service.username_to_user.len(), 1);
    }

    #[test]
    fn should_fail_creating_user_with_existing_username() {
        let mut user_service = MemoryUsers::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        let result = user_service.create_user("username".to_owned(), "password".to_owned());

        matches!(result, Err(AuthError::UsernameAlreadyExists));
    }

    #[test]
    fn authenticate_should_succeed() {
        let mut user_service = MemoryUsers::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert!(user_service.authenticate("username", "password").is_ok());
    }

    #[test]
    fn authenticate_should_fail_with_incorrect_password() {
        let mut user_service = MemoryUsers::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        let result = user_service.authenticate("username", "incorrect password");

        matches!(result, Err(AuthError::InvalidCredentials));
    }

    #[test]
    fn user_exists_should_return_true_if_username_exists() {
        let mut user_service = MemoryUsers::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");
        assert!(user_service.user_exists("username"));
    }

    #[test]
    fn user_exists_should_return_false_if_username_does_not_exist() {
        let user_service = MemoryUsers::default();
        assert!(!user_service.user_exists("missing-user"));
    }

    #[test]
    fn should_delete_user() {
        let mut user_service = MemoryUsers::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        let user_uuid = user_service.authenticate("username", "password").unwrap();

        user_service.delete_user(user_uuid).unwrap();

        assert_eq!(user_service.uuid_to_user.len(), 0);
        assert_eq!(user_service.username_to_user.len(), 0);
    }
}
