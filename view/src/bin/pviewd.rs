#![allow(clippy::clone_on_copy)]
use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use clap::Parser;
use penumbra_crypto::keys::{SeedPhrase, SpendKey};
use penumbra_crypto::FullViewingKey;
use penumbra_custody::policy::{AuthPolicy, PreAuthorizationPolicy};
use penumbra_custody::soft_kms::{self, SoftKms};
use penumbra_proto::client::v1alpha1::oblivious_query_service_client::ObliviousQueryServiceClient;
use penumbra_proto::client::v1alpha1::ChainParametersRequest;
use penumbra_proto::custody::v1alpha1::custody_protocol_service_server::CustodyProtocolServiceServer;
use penumbra_proto::view::v1alpha1::view_protocol_service_server::ViewProtocolServiceServer;
use penumbra_view::ViewService;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::env;
use std::str::FromStr;
use tonic::transport::Server;
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClientConfig {
    /// Optional KMS config for custody mode
    pub kms_config: Option<soft_kms::Config>,
    /// FVK for both view and custody modes
    pub fvk: FullViewingKey,
}

#[derive(Debug, Parser)]
#[clap(
    name = "pviewd",
    about = "The Penumbra view daemon.",
    version = env!("VERGEN_GIT_SEMVER"),
)]
struct Opt {
    /// Command to run.
    #[clap(subcommand)]
    cmd: Command,
    /// The path used to store the state database.
    #[clap(short, long, default_value = "pviewd-db.sqlite")]
    sqlite_path: Utf8PathBuf,
    /// The address of the pd+tendermint node.
    #[clap(short, long, default_value = "testnet.penumbra.zone")]
    node: String,
    /// The port to use to speak to pd's gRPC server.
    #[clap(long, default_value = "8080")]
    pd_port: u16,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    Init {
        /// The full viewing key to initialize the view service with.
        full_viewing_key: String,
        // The seed phrase providing spend capability
        seed_phrase: Option<String>,
    },
    /// Start the view service.
    #[clap(subcommand, display_order = 100)]
    Start(StartCmd),
}
#[derive(Debug, clap::Subcommand)]
pub enum StartCmd {
    /// Initialize the view service without spend capability
    View {
        /// Bind the view service to this host.
        #[clap(long, default_value = "127.0.0.1")]
        host: String,
        /// Bind the view gRPC server to this port.
        #[clap(long, default_value = "8081")]
        view_port: u16,
    },
    /// Initialize the custody service with a seed phrase
    Custody {
        /// Bind the view service to this host.
        #[clap(long, default_value = "127.0.0.1")]
        host: String,
        /// Bind the view gRPC server to this port.
        #[clap(long, default_value = "8081")]
        view_port: u16,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let opt = Opt::parse();

    match opt.cmd {
        Command::Init {
            full_viewing_key,
            seed_phrase,
        } => {
            // Initialize client and storage

            let mut client = ObliviousQueryServiceClient::connect(format!(
                "http://{}:{}",
                opt.node, opt.pd_port
            ))
            .await?;

            let params = client
                .chain_parameters(tonic::Request::new(ChainParametersRequest {
                    chain_id: String::new(),
                }))
                .await?
                .into_inner()
                .try_into()?;

            penumbra_view::Storage::initialize(
                opt.sqlite_path.as_path(),
                FullViewingKey::from_str(full_viewing_key.as_ref())
                    .context("The provided string is not a valid FullViewingKey")?,
                params,
            )
            .await?;

            // Create config file

            let kms_config: Option<soft_kms::Config> = match seed_phrase {
                Some(seed_phrase) => {
                    let spend_key =
                        SpendKey::from_seed_phrase(SeedPhrase::from_str(seed_phrase.as_str())?, 0);

                    let pak = ed25519_consensus::SigningKey::new(rand_core::OsRng);
                    let pvk = pak.verification_key();

                    let auth_policy = vec![
                        AuthPolicy::OnlyIbcRelay,
                        AuthPolicy::DestinationAllowList {
                            allowed_destination_addresses: vec![
                                spend_key
                                    .incoming_viewing_key()
                                    .payment_address(Default::default())
                                    .0,
                            ],
                        },
                        AuthPolicy::PreAuthorization(PreAuthorizationPolicy::Ed25519 {
                            required_signatures: 1,
                            allowed_signers: vec![pvk],
                        }),
                    ];
                    Some(soft_kms::Config {
                        spend_key: spend_key.clone(),
                        auth_policy,
                    })
                }
                None => None,
            };

            let client_config: ClientConfig;

            client_config.kms_config = kms_config;
            client_config.fvk = FullViewingKey::from_str(full_viewing_key.as_ref())?;

            let encoded = toml::to_string_pretty(&client_config).unwrap();

            // Write config to directory

            Ok(())
        }

        Command::Start(start_cmd) => match start_cmd {
            StartCmd::View { host, view_port } => {
                tracing::info!(?opt.sqlite_path, ?host, ?view_port, ?opt.node, ?opt.pd_port, "starting pviewd");

                let storage = penumbra_view::Storage::load(opt.sqlite_path).await?;

                let service = ViewService::new(storage, opt.node, opt.pd_port).await?;

                tokio::spawn(
                    Server::builder()
                        .accept_http1(true)
                        .add_service(tonic_web::enable(ViewProtocolServiceServer::new(service)))
                        .serve(
                            format!("{}:{}", host, view_port)
                                .parse()
                                .expect("this is a valid address"),
                        ),
                )
                .await??;

                Ok(())
            }
            StartCmd::Custody { host, view_port } => {
                tracing::info!(?opt.sqlite_path, ?host, ?view_port, ?opt.node, ?opt.pd_port, "starting pviewd");

                let storage = penumbra_view::Storage::load(opt.sqlite_path).await?;

                let service = ViewService::new(storage, opt.node, opt.pd_port).await?;

                let spend_key = SpendKey::from_seed_phrase(seed_phrase.parse().unwrap(), 0);

                let soft_kms = SoftKms::new(spend_key.clone().into());

                let custody_svc = CustodyProtocolServiceServer::new(soft_kms);

                tokio::spawn(
                    Server::builder()
                        .accept_http1(true)
                        .add_service(tonic_web::enable(ViewProtocolServiceServer::new(service)))
                        .add_service(tonic_web::enable(custody_svc))
                        .serve(
                            format!("{}:{}", host, view_port)
                                .parse()
                                .expect("this is a valid address"),
                        ),
                )
                .await??;

                Ok(())
            }
        },
    }
}
