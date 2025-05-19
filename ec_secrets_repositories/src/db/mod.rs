use crate::repositories::{keys::KeyRepository, users::UserRepository, vault::VaultRepository};
use dotenvy::dotenv;
use mongodb::{Client, options::ClientOptions};
use std::sync::Arc;

pub async fn connect() -> mongodb::error::Result<(
    Arc<UserRepository>,
    Arc<VaultRepository>,
    Arc<KeyRepository>,
)> {
    dotenv().ok();

    let database_url = std::env::var_os("ECS_DATABASE_URL")
        .expect("[ECS_DATABASE_URL] must be set...")
        .into_string()
        .unwrap();

    let database_name = std::env::var_os("ECS_DATABASE_NAME")
        .expect("[ECS_DATABASE_NAME] must be set...")
        .into_string()
        .unwrap();

    let client_options = ClientOptions::parse(database_url).await?;
    let client = Client::with_options(client_options)?;

    dbg!("Successfully initialized vault database...");

    let user_repo = Arc::new(UserRepository::new(&client, &database_name, "users"));

    let vault_repo = Arc::new(VaultRepository::new(&client, &database_name, "vault"));

    let keys_repo = Arc::new(KeyRepository::new(&client, &database_name, "keys"));

    Ok((user_repo, vault_repo, keys_repo))
}
