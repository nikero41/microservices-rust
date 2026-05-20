use std::env;
use authentication::auth_client::AuthClient;
use authentication::{SignInRequest, SignOutRequest, SignUpRequest};
use tokio::time::{Duration, sleep};
use tonic::Request;
use uuid::Uuid;

pub mod authentication {
    tonic::include_proto!("authentication");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_hostname = env::var("AUTH_SERVICE_HOST_NAME").unwrap_or("[::0]".to_owned());

    let mut client = AuthClient::connect(format!("http://{}:50051", auth_hostname)).await?;

    loop {
        let username = Uuid::new_v4().to_string();
        let password = Uuid::new_v4().to_string();

        let request = Request::new(SignUpRequest {
            username: username.clone(),
            password: password.clone(),
        });
        let response = client.sign_up(request).await?.into_inner();
        println!("SIGN UP RESPONSE STATUS: {:?}", response.status_code());

        let request = Request::new(SignInRequest { username, password }); // Create a new `SignInRequest`.
        let response = client.sign_in(request).await?.into_inner();
        println!("SIGN IN RESPONSE STATUS: {:?}", response.status_code());

        let request = Request::new(SignOutRequest {
            session_token: response.session_token,
        });
        let response = client.sign_out(request).await?.into_inner();
        println!("SIGN OUT RESPONSE STATUS: {:?}", response.status_code());

        println!("--------------------------------------",);

        sleep(Duration::from_secs(3)).await;
    }
}
