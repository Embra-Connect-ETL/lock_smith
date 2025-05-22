use clap::{Arg, Command};
use ec_secrets_manager_cli::auth::AuthenticatedUser;
use ec_secrets_shared_library::models::UserCredentials;

#[tokio::main]
async fn main() {
    let mut authenticated_user = AuthenticatedUser::new().await;
    let matches = Command::new("ec_lock_smith")
        .version("1.0")
        .about("Embra Connect Lock Smith CLI")
        .arg_required_else_help(true)
        .subcommand(
            Command::new("login")
                .about("authenticates user to the embra connect secrets manager service")
                .arg_required_else_help(true)
                .arg(
                    Arg::new("email")
                        .short('e')
                        .long("email")
                        .required(true)
                        .help("The user's email"),
                )
                .arg(
                    Arg::new("password")
                        .short('p')
                        .long("password")
                        .required(true)
                        .help("The user's password"),
                ),
        )
        .subcommand(
            Command::new("users")
                .about("allow users to execute user management capabilities of lock smith")
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("list user account in lock smith")
                        .arg(
                            Arg::new("id")
                                .short('i')
                                .long("id")
                                .required(false)
                                .help("user account id"),
                        ),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        Some(("login", sub_matches)) => {
            let creds = UserCredentials {
                email: sub_matches.get_one::<String>("email").unwrap().to_string(),
                password: sub_matches
                    .get_one::<String>("password")
                    .unwrap()
                    .to_string(),
            };
            authenticated_user
                .login(creds)
                .await
                .unwrap_or_else(|err| println!("\x1b[0;31m Login failed: {err} \x1b[0m"));
            println!("\x1b[0;32m Login Successful \x1b[0m");
        }
        Some(("users", submatches)) => match submatches.subcommand() {
            Some(("list", submatches)) => {
                let id: Option<&str> = submatches.get_one::<String>("id").map(|id| id.as_str());
                authenticated_user
                    .get_users(id)
                    .await
                    .unwrap_or_else(|error| {
                        println!("\x1b[0;31m Error gettig users: {error} \x1b[0m")
                    });
            }
            _ => {}
        },
        _ => {}
    }
}
