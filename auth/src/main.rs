use std::sync::Mutex;

mod auth;
mod sessions;
mod users;

use auth::*;
use sessions::{Sessions, SessionsImpl};
use users::{Users, UsersImpl};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::0]:50051".parse()?;

    let users_service: Box<Mutex<dyn Users + Send + Sync + 'static>> =
        Box::new(Mutex::new(UsersImpl::default()));
    let sessions_service: Box<Mutex<dyn Sessions + Send + Sync + 'static>> =
        Box::new(Mutex::new(SessionsImpl::default()));

    let auth_service = AuthService::new(users_service, sessions_service);

    Server::builder()
        .add_service(AuthServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
