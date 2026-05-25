use std::sync::Mutex;

mod auth;
mod errors;
mod sessions;
mod users;

use auth::*;
use sessions::MemorySessions;
use users::MemoryUsers;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::0]:50051".parse()?;

    let users_service = Box::new(Mutex::new(MemoryUsers::default()));
    let sessions_service = Box::new(Mutex::new(MemorySessions::default()));

    let auth_service = AuthService::new(users_service, sessions_service);

    Server::builder()
        .add_service(AuthServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
