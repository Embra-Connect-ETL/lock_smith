#![allow(dead_code)]

use home;
use pasetors::{
    Public,
    claims::{Claims, ClaimsValidationRules},
    public,
    token::UntrustedToken,
    version4::V4,
};
use prettytable::{Cell, Row, Table};
use std::fs;

use ec_secrets_shared_library::{
    db::connect,
    models::{User, UserCredentials},
    repositories::{keys::KeyRepository, users::UserRepository, vault::VaultRepository},
    utils::auth::{authorize_user, decode_keys},
};

pub struct AuthenticatedUser {
    claims: Option<Claims>,
    user_repo: Option<UserRepository>,
    key_repo: Option<KeyRepository>,
    vault_repo: Option<VaultRepository>,
}

impl AuthenticatedUser {
    pub async fn new() -> Self {
        Self {
            claims: None,
            key_repo: None,
            user_repo: None,
            vault_repo: None,
        }
    }

    pub async fn get_repos(&mut self) -> Result<(), String> {
        let repos = connect().await.map_err(|error| error.to_string())?;

        self.key_repo = Some(repos.2);
        self.user_repo = Some(repos.0);
        self.vault_repo = Some(repos.1);
        Ok(())
    }
    pub async fn login(&mut self, creds: UserCredentials) -> Result<(), String> {
        self.get_repos().await.map_err(|error| error)?;
        let Some(user_repo) = &self.user_repo else {
            return Err("Failed to connect to database".to_owned());
        };

        let user_doc = user_repo
            .get_user_by_email(&creds.email)
            .await
            .map_err(|error| error.to_string())?;

        if let Some(user_doc) = user_doc {
            let user = User {
                id: user_doc.id.to_string(),
                email: user_doc.email.clone(),
                password: user_doc.password.clone(),
                created_at: user_doc.created_at.to_rfc3339(),
            };
            let Some(key_repo) = &self.key_repo else {
                return Err("Failed to connect to database".to_owned());
            };
            let token = authorize_user(&user, &creds, key_repo).await?;
            let Some(home_dir) = home::home_dir() else {
                return Err("Error acccessing the home directory".to_owned());
            };
            let token_file = home_dir.join(".lock_smith.config");
            fs::write(token_file, token).map_err(|error| error.to_string())?;
        } else {
            return Err("Invalid login credentials".to_owned());
        }

        Ok(())
    }

    pub async fn validate_token(&mut self) -> Result<(), String> {
        self.get_repos().await.map_err(|error| error)?;
        let Some(home_dir) = home::home_dir() else {
            return Err("Error acccessing the home directory".to_owned());
        };
        let token_file = home_dir.join(".lock_smith.config");

        let token = fs::read_to_string(token_file).map_err(|error| error.to_string())?;

        let untrusted_token = UntrustedToken::<Public, V4>::try_from(token.as_str())
            .map_err(|error| error.to_string())?;

        let Some(key_repo) = &self.key_repo else {
            return Err("Failed to connect to database".to_owned());
        };

        let keys = decode_keys(key_repo).await.map_err(|error| error)?;

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

    pub async fn get_users(&mut self, id: Option<&str>) -> Result<(), String> {
        self.validate_token().await.map_err(|error| error)?;

        let Some(user_repo) = &self.user_repo else {
            return Err("Failed to connect to database".to_owned());
        };

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Id"),
            Cell::new("Email"),
            Cell::new("CreatedAt"),
        ]));

        if let Some(id) = id {
            user_repo
                .get_user_by_id(id)
                .await
                .map_err(|error| error.to_string())?
                .map(|user| {
                    table.add_row(Row::new(vec![
                        Cell::new(user.id.to_string().as_str()),
                        Cell::new(user.email.as_str()),
                        Cell::new(user.created_at.to_string().as_str()),
                    ]));
                });
        } else {
            let users = user_repo
                .list_users()
                .await
                .map_err(|error| error.to_string())?;

            users.iter().for_each(|user| {
                table.add_row(Row::new(vec![
                    Cell::new(user.id.to_string().as_str()),
                    Cell::new(user.email.as_str()),
                    Cell::new(user.created_at.to_string().as_str()),
                ]));
            });
        }
        table.printstd();
        Ok(())
    }
}
