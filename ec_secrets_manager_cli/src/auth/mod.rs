#![allow(dead_code)]

use pasetors::{
    Public,
    claims::{Claims, ClaimsValidationRules},
    public,
    token::UntrustedToken,
    version4::V4,
};
use prettytable::{Cell, Row, Table};
use std::{fs, io::Write};
use tempfile::NamedTempFile;

use ec_secrets_shared_library::{
    db::connect,
    models::{User, UserCredentials},
    repositories::{keys::KeyRepository, users::UserRepository, vault::VaultRepository},
    utils::auth::{authorize_user, decode_keys},
};

pub struct AuthenticatedUser {
    token_file: Option<NamedTempFile>,
    claims: Option<Claims>,
    user_repo: UserRepository,
    key_repo: KeyRepository,
    vault_repo: VaultRepository,
}

impl AuthenticatedUser {
    pub async fn new() -> Self {
        let repos = connect()
            .await
            .expect("\x1b[0;31m Error connecting to repositories \x1b[0m");

        Self {
            claims: None,
            key_repo: repos.2,
            user_repo: repos.0,
            token_file: None,
            vault_repo: repos.1,
        }
    }

    pub async fn login(&mut self, creds: UserCredentials) -> Result<(), String> {
        self.token_file = Some(NamedTempFile::new().map_err(|error| error.to_string())?);

        let user_doc = self
            .user_repo
            .get_user_by_email(&creds.email)
            .await
            .map_err(|err| err.to_string())?;

        if let Some(user_doc) = user_doc {
            let user = User {
                id: user_doc.id.to_string(),
                email: user_doc.email.clone(),
                password: user_doc.password.clone(),
                created_at: user_doc.created_at.to_rfc3339(),
            };
            let token = authorize_user(&user, &creds, &self.key_repo).await?;
            self.token_file.as_mut().map(|token_file| {
                token_file
                    .write_all(token.as_bytes())
                    .map_err(|error| error.to_string())
            });
        } else {
            return Err("Invalid login credentials".to_owned());
        }

        Ok(())
    }

    pub async fn validate_token(&mut self) -> Result<(), String> {
        let Some(token_path) = &self.token_file else {
            return Err("User is not authenticated".into());
        };

        let token = fs::read_to_string(token_path).map_err(|error| error.to_string())?;

        let untrusted_token = UntrustedToken::<Public, V4>::try_from(token.as_str())
            .map_err(|error| error.to_string())?;

        let keys = decode_keys(&self.key_repo).await.map_err(|error| error)?;

        let validation_rules = ClaimsValidationRules::new();

        let trusted_token =
            public::verify(&keys.1, &untrusted_token, &validation_rules, None, None)
                .map_err(|error| error.to_string())?;

        if let Some(claims) = trusted_token.payload_claims() {
            self.claims = Some(claims.clone());
            Ok(())
        } else {
            Err("Token has no playload".into())
        }
    }

    pub async fn get_users(&mut self) -> Result<(), String> {
        if self.token_file.is_none() {
            return Err(format!("Please authenticate before running this command"));
        }

        self.validate_token().await.map_err(|error| error)?;

        let users = self
            .user_repo
            .list_users()
            .await
            .map_err(|error| error.to_string())?;

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Id"),
            Cell::new("Email"),
            Cell::new("CreatedAt"),
        ]));

        users.iter().for_each(|user| {
            table.add_row(Row::new(vec![
                Cell::new(user.id.to_string().as_str()),
                Cell::new(user.email.as_str()),
                Cell::new(user.created_at.to_string().as_str()),
            ]));
        });
        table.printstd();
        Ok(())
    }
}
