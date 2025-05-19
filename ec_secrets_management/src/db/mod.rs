#![allow(unused)]
use ec_secrets_repositories::db::connect;
use rocket::fairing::AdHoc;

/*-------------
Custom modules
---------------*/
use ec_secrets_repositories::repositories::{
    keys::KeyRepository, users::UserRepository, vault::VaultRepository,
};

pub fn init() -> AdHoc {
    AdHoc::on_ignite(
        "Establish connection with Database cluster",
        |rocket| async {
            match connect().await {
                Ok((user_repository, vault_repository, key_repository)) => rocket
                    .manage(user_repository)
                    .manage(vault_repository)
                    .manage(key_repository),
                Err(error) => {
                    panic!("Cannot connect to instance:: {:?}", error)
                }
            }
        },
    )
}
