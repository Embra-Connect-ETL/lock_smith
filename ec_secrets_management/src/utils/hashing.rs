#![allow(unused)]
/*-------------
Custom modules
-------------*/
use ec_secrets_repositories::models::{User, UserCredentials};

/*-----------------
3rd party modules
-----------------*/
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/*------------------------------------
Standard password hashing via bcrypt.
--------------------------------------*/
pub fn hash_password(password: String) -> Result<String, String> {
    hash(password, DEFAULT_COST).map_err(|e| e.to_string())
}
