#![warn(dead_code)]

use ec_secrets_shared_library::{db::connect, models::{User, UserCredentials}, utils::auth::authorize_user};

async fn login(creds: UserCredentials) -> Result<(), String> {
    let (user_repo, _, key_repo) = connect().await.map_err(|err| err.to_string())?;
    let user_doc = user_repo
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
        let _token = authorize_user(&user, &creds, &key_repo).await?;
        println!("\x1b[0;32m Login successful \x1b[0m");
    } else {
        return Err("Invalid login credentials".to_owned());
    }

    Ok(())
}
