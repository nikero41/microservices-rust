use std::sync::Mutex;

use crate::errors::AuthError;
use crate::{sessions::Sessions, users::Users};

use tonic::{Request, Response, Status};

use authentication::auth_server::Auth;
use authentication::{
    SignInRequest, SignInResponse, SignOutRequest, SignOutResponse, SignUpRequest, SignUpResponse,
    StatusCode,
};

pub mod authentication {
    tonic::include_proto!("authentication");
}

pub use authentication::auth_server::AuthServer;
pub use tonic::transport::Server;

pub struct AuthService {
    users_service: Box<Mutex<dyn Users + Send + Sync>>,
    sessions_service: Box<Mutex<dyn Sessions + Send + Sync>>,
}

impl AuthService {
    pub fn new(
        users_service: Box<Mutex<dyn Users + Send + Sync>>,
        sessions_service: Box<Mutex<dyn Sessions + Send + Sync>>,
    ) -> Self {
        Self {
            users_service,
            sessions_service,
        }
    }
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn sign_in(
        &self,
        request: Request<SignInRequest>,
    ) -> Result<Response<SignInResponse>, Status> {
        let request = request.into_inner();
        println!("SIGN-IN: {}", request.username);

        let result = self
            .users_service
            .lock()
            .unwrap()
            .authenticate(&request.username, &request.password);

        match result {
            Ok(user_uuid) => {
                let session_token = self.sessions_service.lock().unwrap().create(&user_uuid);

                Ok(Response::new(SignInResponse {
                    status_code: StatusCode::Success.into(),
                    user_uuid,
                    session_token,
                }))
            }
            Err(_) => Ok(Response::new(SignInResponse {
                status_code: StatusCode::Failure.into(),
                ..Default::default()
            })),
        }
    }

    async fn sign_up(
        &self,
        request: Request<SignUpRequest>,
    ) -> Result<Response<SignUpResponse>, Status> {
        let request = request.into_inner();
        println!("SIGN-UP: {}", request.username);

        let result = self
            .users_service
            .lock()
            .unwrap()
            .user_exists(&request.username);

        if result {
            return Ok(Response::new(SignUpResponse {
                status_code: StatusCode::Failure.into(),
            }));
        }

        let result = self
            .users_service
            .lock()
            .unwrap()
            .create_user(request.username.clone(), request.password.clone());

        let response = match result {
            Ok(_) => SignUpResponse {
                status_code: StatusCode::Success.into(),
            },
            Err(AuthError::UsernameAlreadyExists) => SignUpResponse {
                status_code: StatusCode::Failure.into(),
            },
            Err(AuthError::InvalidCredentials | AuthError::InvalidRequest) => SignUpResponse {
                status_code: StatusCode::Failure.into(),
            },
            Err(AuthError::InternalError(e)) => return Err(Status::internal(e)),
        };

        Ok(Response::new(response))
    }

    async fn sign_out(
        &self,
        request: Request<SignOutRequest>,
    ) -> Result<Response<SignOutResponse>, Status> {
        let request = request.into_inner();
        println!("SIGN-OUT");

        self.sessions_service
            .lock()
            .unwrap()
            .delete(&request.session_token);

        Ok(Response::new(SignOutResponse {
            status_code: StatusCode::Success.into(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use crate::{sessions::SessionsImpl, users::UsersImpl};

    use super::*;

    #[tokio::test]
    async fn sign_in_should_fail_if_user_not_found() {
        let users_service = Box::new(Mutex::new(UsersImpl::default()));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignInRequest {
            username: "123456".to_owned(),
            password: "654321".to_owned(),
        });

        let result = auth_service.sign_in(request).await.unwrap().into_inner();

        assert_eq!(result.status_code, StatusCode::Failure.into());
        assert!(result.user_uuid.is_empty());
        assert!(result.session_token.is_empty());
    }

    #[tokio::test]
    async fn sign_in_should_fail_if_incorrect_password() {
        let mut users_service = UsersImpl::default();

        users_service
            .create_user("123456".to_owned(), "654321".to_owned())
            .expect("should create user");

        let users_service = Box::new(Mutex::new(users_service));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignInRequest {
            username: "123456".to_owned(),
            password: "wrong password".to_owned(),
        });

        let result = auth_service.sign_in(request).await.unwrap().into_inner();

        assert_eq!(result.status_code, StatusCode::Failure.into());
        assert!(result.user_uuid.is_empty());
        assert!(result.session_token.is_empty());
    }

    #[tokio::test]
    async fn sign_in_should_succeed() {
        let mut users_service = UsersImpl::default();

        users_service.create_user("123456".to_owned(), "654321".to_owned()).expect("should create user");

        let users_service = Box::new(Mutex::new(users_service));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignInRequest {
            username: "123456".to_owned(),
            password: "654321".to_owned(),
        });

        let result = auth_service.sign_in(request).await.unwrap().into_inner();

        assert_eq!(result.status_code, StatusCode::Success.into());
        assert!(!result.user_uuid.is_empty());
        assert!(!result.session_token.is_empty());
    }

    #[tokio::test]
    async fn sign_up_should_fail_if_username_and_password_exists() {
        let mut users_service = UsersImpl::default();

        let _ = users_service.create_user("123456".to_owned(), "654321".to_owned());

        let users_service = Box::new(Mutex::new(users_service));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignUpRequest {
            username: "123456".to_owned(),
            password: "654321".to_owned(),
        });

        let result = auth_service.sign_up(request).await.unwrap();

        assert_eq!(result.into_inner().status_code, StatusCode::Failure.into());
    }

    #[tokio::test]
    async fn sign_up_should_fail_if_username_exists() {
        let mut users_service = UsersImpl::default();

        users_service.create_user("123456".to_owned(), "654321".to_owned()).expect("should create user");

        let users_service = Box::new(Mutex::new(users_service));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignUpRequest {
            username: "123456".to_owned(),
            password: "7654321".to_owned(),
        });

        let result = auth_service.sign_up(request).await.unwrap();

        assert_eq!(result.into_inner().status_code, StatusCode::Failure.into());
    }

    #[tokio::test]
    async fn sign_up_should_succeed() {
        let users_service = Box::new(Mutex::new(UsersImpl::default()));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignUpRequest {
            username: "123456".to_owned(),
            password: "654321".to_owned(),
        });

        let result = auth_service.sign_up(request).await.unwrap();

        assert_eq!(result.into_inner().status_code, StatusCode::Success.into());
    }

    #[tokio::test]
    async fn sign_out_should_succeed() {
        let users_service = Box::new(Mutex::new(UsersImpl::default()));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignOutRequest {
            session_token: "".to_owned(),
        });

        let result = auth_service.sign_out(request).await.unwrap();

        assert_eq!(result.into_inner().status_code, StatusCode::Success.into());
    }
}
