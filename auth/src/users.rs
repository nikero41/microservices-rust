use pbkdf2::{
    Pbkdf2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
// use rand_core::OsRng;
use uuid::Uuid;

use std::collections::HashMap;

pub trait Users {
    fn create_user(&mut self, username: String, password: String) -> Result<(), String>;
    fn get_user_uuid(&self, username: &str, password: &str) -> Option<String>;
    fn delete_user(&mut self, user_uuid: String);
}

#[derive(Clone)]
pub struct User {
    user_uuid: String,
    username: String,
    password: String,
}

#[derive(Default)]
pub struct UsersImpl {
    uuid_to_user: HashMap<String, User>,
    username_to_user: HashMap<String, User>,
}

impl Users for UsersImpl {
    fn create_user(&mut self, username: String, password: String) -> Result<(), String> {
        if self.username_to_user.contains_key(&username) {
            return Err("Username already exists".to_string());
        }

        let salt = SaltString::generate(&mut OsRng);

        let hashed_password = Pbkdf2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("Failed to hash password.\n{e:?}"))?
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

    fn get_user_uuid(&self, username: &str, password: &str) -> Option<String> {
        let user = self.username_to_user.get(username)?;

        let hashed_password = user.password.clone();
        let parsed_hash = PasswordHash::new(&hashed_password).ok()?;

        Pbkdf2
            .verify_password(password.as_bytes(), &parsed_hash)
            .ok()
            .map(|_| user.user_uuid.clone())
    }

    fn delete_user(&mut self, user_uuid: String) {
        let user = self.uuid_to_user.remove(&user_uuid);
        if let Some(user) = user {
            self.username_to_user.remove(&user.username);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_user() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert_eq!(user_service.uuid_to_user.len(), 1);
        assert_eq!(user_service.username_to_user.len(), 1);
    }

    #[test]
    fn should_fail_creating_user_with_existing_username() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        let result = user_service.create_user("username".to_owned(), "password".to_owned());

        assert!(result.is_err());
    }

    #[test]
    fn should_retrieve_user_uuid() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert!(user_service.get_user_uuid("username", "password").is_some());
    }

    #[test]
    fn should_fail_to_retrieve_user_uuid_with_incorrect_password() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert!(
            user_service
                .get_user_uuid("username", "incorrect password")
                .is_none()
        );
    }

    #[test]
    fn should_delete_user() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        let user_uuid = user_service.get_user_uuid("username", "password").unwrap();

        user_service.delete_user(user_uuid);

        assert_eq!(user_service.uuid_to_user.len(), 0);
        assert_eq!(user_service.username_to_user.len(), 0);
    }
}
