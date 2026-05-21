use clap::{Parser, Subcommand};
use std::env;

use authentication::auth_client::AuthClient;
use authentication::{SignInRequest, SignOutRequest, SignUpRequest};
use tonic::transport::Channel;
use tonic::{Request, Response};

use crate::authentication::SignOutResponse;

pub mod authentication {
    tonic::include_proto!("authentication");
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    SignIn {
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
    },
    SignUp {
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: String,
    },
    SignOut {
        #[arg(short, long)]
        session_token: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_ip = env::var("AUTH_SERVICE_IP").unwrap_or("[::0]".to_owned());
    let mut client: AuthClient<Channel> =
        AuthClient::connect(format!("http://{}:50051", auth_ip)).await?;

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::SignIn { username, password }) => {
            let request = Request::new(SignInRequest {
                username: username.to_owned(),
                password: password.to_owned(),
            });

            let response = client.sign_in(request).await?.into_inner();

            println!("{:?}", response);
        }
        Some(Commands::SignUp { username, password }) => {
            let request = Request::new(SignUpRequest {
                username: username.to_owned(),
                password: password.to_owned(),
            });

            let response = client.sign_up(request).await?;

            println!("{:?}", response.into_inner());
        }
        Some(Commands::SignOut { session_token }) => {
            let request: Request<SignOutRequest> = Request::new(SignOutRequest {
                session_token: session_token.to_owned(),
            });

            let response: Response<SignOutResponse> = client.sign_out(request).await?;

            println!("{:?}", response.into_inner());
        }
        None => {}
    }

    Ok(())
}
