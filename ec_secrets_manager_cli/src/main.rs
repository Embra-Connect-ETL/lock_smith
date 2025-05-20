use clap::{Arg, Command};

#[tokio::main]
async fn main() {
    let matches = Command::new("ec_secrets_cli")
        .version("1.0")
        .about("Embra Connect Secrets Manager CLI")
        .subcommand(
            Command::new("login")
                .about("authenticates user to the embra connect secrets manager echo system")
                .arg_required_else_help(true)
                .arg(
                    Arg::new("email")
                        .short('u')
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
        .get_matches();

    match matches.subcommand() {
        Some(("login", _sub_matches)) => {}
        _ => {}
    }
}
