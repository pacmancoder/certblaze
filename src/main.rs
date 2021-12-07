use anyhow::Context;
use log::{error, info, warn};
use std::{
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
};
use structopt::StructOpt;

#[derive(StructOpt)]
struct Args {
    /// Set working directory for storing certificate (cert.pem/key.pem) and
    /// certblaze state
    #[structopt(long, env = "CERTBLAZE_WORKING_DIRECTORY")]
    working_directory: PathBuf,
    #[structopt(flatten)]
    challenge_server_params: ChallengeServerParams,
    #[structopt(subcommand)]
    command: AppCommand,
}

#[derive(StructOpt)]
struct ChallengeServerParams {
    /// Port to run challenge server on. Set to 8080 by default
    #[structopt(long, default_value = "8080", env = "CERTBLAZE_CHALLENGE_SERVER_PORT")]
    challenge_port: u16,
    /// Address to bind for challenge server
    #[structopt(
        long,
        default_value = "0.0.0.0",
        env = "CERTBLAZE_CHALLENGE_SERVER_ADDRESS"
    )]
    challenge_address: String,
}

#[derive(StructOpt)]
enum AppCommand {
    /// Initialize working directory with given params
    Init {
        /// New Let's Encrypt user email
        #[structopt(long)]
        email: String,
        /// Domain to process
        #[structopt(long)]
        domain: String,
    },
    /// Run in a daemon(service) mode; working directory should be initialized
    Run,
    /// Force renew certificate
    Renew,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct User {
    email: String,
    private_key: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct Certificate {
    domain: String,
    times_issued: usize,
    issued_at: Option<chrono::DateTime<chrono::Utc>>,
    last_token: Option<String>,
    last_proof: Option<String>,
    last_private_key: Option<String>,
    last_certificate: Option<String>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct State {
    user: User,
    certificate: Certificate,
}

struct ChallangeServerController {
    server: Arc<tiny_http::Server>,
    challenge: Arc<Mutex<(String, String)>>,
}

impl ChallangeServerController {
    fn new_challenge(&self, token: String, proof: String) -> Result<(), anyhow::Error> {
        let mut locked = self.challenge.lock().expect("BUG: Mutex is poisoned");
        *locked = (token, proof);
        Ok(())
    }
}

impl Drop for ChallangeServerController {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

fn start_challenge_server(
    params: &ChallengeServerParams,
) -> Result<ChallangeServerController, anyhow::Error> {
    let addr = format!("{}:{}", params.challenge_address, params.challenge_port);
    info!("[Challenge server] Running challenge server on {}", addr);
    let server = tiny_http::Server::http(addr)
        .map(Arc::new)
        .map_err(|e| anyhow::anyhow!("Failed to start challenge server: {}", e))?;

    let challenge = Arc::new(Mutex::new((
        "FAKE_TOKEN".to_owned(),
        "FAKE_PROOF".to_owned(),
    )));

    let cloned_server = server.clone();
    let cloned_challenge = challenge.clone();

    std::thread::spawn(move || {
        let server = cloned_server;
        let challenge = cloned_challenge;

        for request in server.incoming_requests() {
            let source_host = format!("{}", request.remote_addr());
            let (token, proof) = {
                let locked = challenge.lock().expect("BUG: Mutex is poisoned");
                (locked.0.clone(), locked.1.clone())
            };

            let challenge_path = format!(".well-known/acme-challenge/{}", token);
            if request.url().contains(&challenge_path) {
                let response = tiny_http::Response::from_data(proof.as_bytes().to_vec())
                    .with_header(tiny_http::Header {
                        field: "Content-Type".parse().unwrap(),
                        value: "application/octet-stream".parse().unwrap(),
                    });

                if let Err(err) = request.respond(response) {
                    error!(
                        "[Challenge server] ERROR: Failed to send challenge response - {}",
                        err
                    );
                } else {
                    info!(
                        "[Challenge server] OK: Send challenge response to {}",
                        source_host
                    );
                }
            } else {
                let content = format!("404 NOT FOUND `{}`", request.url());
                let response = tiny_http::Response::from_data(content.as_bytes().to_vec())
                    .with_status_code(tiny_http::StatusCode(404))
                    .with_header(tiny_http::Header {
                        field: "Content-Type".parse().unwrap(),
                        value: "text/plain;charset=UTF-8".parse().unwrap(),
                    });

                if let Err(err) = request.respond(response) {
                    error!(
                        "[Challenge server] ERROR: Failed to send error status - {}",
                        err
                    );
                }
            };
        }

        info!("[Challenge server] Challenge server has been closed");
    });

    let controller = ChallangeServerController { server, challenge };

    Ok(controller)
}

fn run() -> Result<(), anyhow::Error> {
    let args = Args::from_args();

    let working_directory = args.working_directory;

    let acme_directory = acme_micro::Directory::from_url(acme_micro::DirectoryUrl::LetsEncrypt)
        .with_context(|| "Failed to open Let's Encrypt ACME directory")?;

    match args.command {
        AppCommand::Init { email, domain } => {
            let mut state = if state_file_path(&working_directory).exists() {
                warn!("Found existing state...");
                load_state(&working_directory)?
            } else {
                info!("Initializing state...");
                init_state(&working_directory, &acme_directory, email, domain)?
            };

            renew_certificate(
                &mut state,
                &working_directory,
                &acme_directory,
                &args.challenge_server_params,
            )?;
        }
        AppCommand::Run => {
            let (stop_signal_tx, stop_signal_rx) = mpsc::channel::<()>();
            ctrlc::set_handler(move || {
                let _ = stop_signal_tx.send(());
            })
            .with_context(|| "Failed to set Ctrl+C signal")?;

            let mut state = load_state(&working_directory)?;

            loop {
                let check_interval = chrono::Duration::days(1);

                if is_renew_required(&state) {
                    renew_certificate(
                        &mut state,
                        &working_directory,
                        &acme_directory,
                        &args.challenge_server_params,
                    )?;
                }

                info!(
                    "Waiting {} day(s) before next renew check...",
                    check_interval.num_days()
                );
                match stop_signal_rx.recv_timeout(check_interval.to_std().unwrap()) {
                    Ok(()) => {
                        warn!("Detected Ctrl+C signal, exiting...");
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        error!("Ctrl+C handler had been killed, exiting...");
                        break;
                    }
                }
            }
        }
        AppCommand::Renew => {
            let mut state = load_state(&working_directory)?;
            force_renew_certificate(
                &mut state,
                &working_directory,
                &acme_directory,
                &args.challenge_server_params,
            )?;
        }
    }

    Ok(())
}

fn main() {
    const DEFAULT_LOG_FILTER: &str = concat!("off,", env!("CARGO_PKG_NAME"), "=info");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(DEFAULT_LOG_FILTER))
        .init();

    if let Err(err) = run() {
        error!("{:#}", err);
        std::process::exit(1);
    }
}

fn init_state(
    working_directory: &Path,
    acme_directory: &acme_micro::Directory,
    email: String,
    domain: String,
) -> Result<State, anyhow::Error> {
    let account = acme_directory
        .register_account(email_to_contact(&email))
        .with_context(|| "Failed to register Let's Encrypt account")?;

    let private_key = account
        .acme_private_key_pem()
        .with_context(|| "Failed to load account private key")?;

    let state = State {
        user: User { email, private_key },
        certificate: Certificate {
            domain,
            times_issued: 0,
            issued_at: None,
            last_proof: None,
            last_token: None,
            last_private_key: None,
            last_certificate: None,
        },
    };

    save_state(working_directory, &state).with_context(|| "Failed to save initialized state")?;

    Ok(state)
}

fn load_state(working_directory: &Path) -> Result<State, anyhow::Error> {
    let state_file_path = state_file_path(working_directory);
    let content = std::fs::read(&state_file_path).with_context(|| "Failed to read state file")?;
    let state = toml::from_slice(&content).with_context(|| "Failed to decode state file")?;
    Ok(state)
}

fn save_state(working_directory: &Path, state: &State) -> Result<(), anyhow::Error> {
    let state_file_path = state_file_path(working_directory);
    let data = toml::to_vec(state).with_context(|| "Failed to serialize state")?;
    std::fs::write(state_file_path, data).with_context(|| "Failed to write state file")?;
    Ok(())
}

fn email_to_contact(email: &str) -> Vec<String> {
    vec![format!("mailto:{}", email)]
}

fn is_renew_required(state: &State) -> bool {
    let renew_interval = chrono::Duration::days(60);

    let issued_at = if let Some(issued_at) = state.certificate.issued_at {
        issued_at
    } else {
        return true;
    };

    let now = chrono::Utc::now();

    // Take clock skew into account
    if now < issued_at {
        return false;
    }

    (now - issued_at) >= renew_interval
}

fn renew_certificate(
    state: &mut State,
    working_directory: &Path,
    acme_directory: &acme_micro::Directory,
    challenge_server_params: &ChallengeServerParams,
) -> Result<(), anyhow::Error> {
    if !is_renew_required(state) {
        info!("Current certificate is valid!");
        return Ok(());
    }
    force_renew_certificate(
        state,
        working_directory,
        acme_directory,
        challenge_server_params,
    )
}

fn force_renew_certificate(
    state: &mut State,
    working_directory: &Path,
    acme_directory: &acme_micro::Directory,
    challenge_server_params: &ChallengeServerParams,
) -> Result<(), anyhow::Error> {
    info!("Issuing new certificate...");

    let account = acme_directory
        .load_account(&state.user.private_key, email_to_contact(&state.user.email))
        .with_context(|| "Failed to laod account")?;

    let challenge_server = start_challenge_server(challenge_server_params)?;

    let mut new_order = account.new_order(&state.certificate.domain, &[])?;
    let order_csr = loop {
        if let Some(order_csr) = new_order.confirm_validations() {
            info!("Domain ownership has been validated!");
            break order_csr;
        }
        let authentications = new_order
            .authorizations()
            .with_context(|| "Failed to get CSR order authorizations")?;
        let challenge = authentications
            .get(0)
            .map(|a| a.http_challenge())
            .flatten()
            .with_context(|| "Http challenge is missing")?;
        let token = challenge.http_token().to_owned();
        let proof = challenge
            .http_proof()
            .with_context(|| "Failed to get http proof")?;
        challenge_server.new_challenge(token.clone(), proof.clone())?;
        state.certificate.last_token = Some(token);
        state.certificate.last_proof = Some(proof);
        state.certificate.times_issued += 1;
        info!("Validating domain ownership...");
        challenge
            .validate(std::time::Duration::from_secs(5))
            .with_context(|| "Failed to falidate auth challenge")?;
        new_order
            .refresh()
            .with_context(|| "Failed to refresh CSR order")?;
    };

    let certificate_key = acme_micro::create_p384_key()?;
    let certificate_order = order_csr
        .finalize_pkey(certificate_key, std::time::Duration::from_secs(5))
        .with_context(|| "Failed to finalize certificate")?;
    let certificate = certificate_order
        .download_cert()
        .with_context(|| "Failed to download certificate")?;

    // We can shutdown our challenge server as soon as we finished with validation
    drop(challenge_server);

    state.certificate.last_private_key = Some(certificate.private_key().to_owned());
    state.certificate.last_certificate = Some(certificate.certificate().to_owned());
    state.certificate.issued_at = Some(chrono::Utc::now());

    info!("Saving certificate files...");

    let cert_file_path = cert_file_path(working_directory);
    std::fs::write(cert_file_path, certificate.certificate())
        .with_context(|| "Failed to write cert file")?;
    let key_file_path = key_file_path(working_directory);
    std::fs::write(key_file_path, certificate.private_key())
        .with_context(|| "Failed to write key file")?;

    info!("Saving state...");
    save_state(working_directory, state).with_context(|| "Failed to save state")?;

    info!(
        "Certificate for `{}` has been successfully issued",
        state.certificate.domain
    );

    Ok(())
}

fn state_file_path(working_directory: &Path) -> PathBuf {
    working_directory.join("certblaze_state.toml")
}

fn cert_file_path(working_directory: &Path) -> PathBuf {
    working_directory.join("cert.pem")
}

fn key_file_path(working_directory: &Path) -> PathBuf {
    working_directory.join("key.pem")
}
