use anyhow::{ensure, Context, Result};
use clap::Parser;
use nezora_supply::blockchain::{
    peer_network::{PeerMessage, PEER_NETWORK_NAME, PEER_PROTOCOL_VERSION},
    peer_node::{accept_peer, bind_listener, connect_peer},
    peer_sync::serve_peer_session,
    persistence::load_chain,
    Chain, ConsensusParams,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::{self, OpenOptions},
    io,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

#[derive(Debug, Parser)]
#[command(name = "nezora-node", version, about = "Nezora P2P test node")]
struct Args {
    #[arg(long, conflicts_with = "connect")]
    listen: Option<SocketAddr>,

    #[arg(long)]
    connect: Option<SocketAddr>,

    /// Directory for this node's persistent identity
    #[arg(long, default_value = "data")]
    data_dir: PathBuf,

    /// Local blockchain file. If absent, the node starts with an empty chain.
    #[arg(long, default_value = "data/chain.json")]
    chain: PathBuf,
}

fn load_or_create_node_id(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        let bytes = fs::read(path).context("reading node ID")?;
        ensure!(bytes.len() == 32, "node ID must be exactly 32 bytes");
        return Ok(bytes.try_into().expect("length checked"));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("creating node data directory")?;
    }

    let mut node_id = [0u8; 32];
    OsRng.fill_bytes(&mut node_id);

    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .context("setting node ID file permissions")?;
            io::Write::write_all(&mut file, &node_id).context("writing node ID")?;
            file.sync_all().context("syncing node ID")?;
            Ok(node_id)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let bytes = fs::read(path).context("reading concurrently-created node ID")?;
            ensure!(bytes.len() == 32, "node ID must be exactly 32 bytes");
            Ok(bytes.try_into().expect("length checked"))
        }
        Err(error) => Err(error).context("creating node ID file"),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    ensure!(
        args.listen.is_some() || args.connect.is_some(),
        "Specify either --listen or --connect"
    );

    let node_id = load_or_create_node_id(&args.data_dir.join("node_id"))?;

    let params = ConsensusParams::default();
    let chain = if args.chain.exists() {
        load_chain(&args.chain, &params)
            .with_context(|| format!("loading chain {}", args.chain.display()))?
    } else {
        Chain::default()
    };

    let local_version = PeerMessage::Version {
        network: PEER_NETWORK_NAME.to_string(),
        protocol_version: PEER_PROTOCOL_VERSION,
        node_id,
        height: chain.height(),
        tip_hash: chain.tip_hash(),
    };

    println!("Nezora P2P Test Node");
    println!("Node ID: {}", hex::encode(node_id));
    println!("Data directory: {}", args.data_dir.display());
    println!("Chain file: {}", args.chain.display());
    println!("Local chain height: {}", chain.height());
    println!("Local tip hash: {}", hex::encode(chain.tip_hash()));

    let (mut stream, remote) = if let Some(address) = args.listen {
        let listener = bind_listener(address)?;
        println!("Listening on {address}");
        accept_peer(&listener, &local_version)?
    } else {
        let address = args.connect.expect("connect address required");
        println!("Connecting to {address}");
        connect_peer(address, &local_version)?
    };

    println!("P2P HANDSHAKE SUCCESSFUL");
    if let PeerMessage::Version {
        node_id,
        height,
        tip_hash,
        ..
    } = remote
    {
        println!("Remote node ID: {}", hex::encode(node_id));
        println!("Remote chain height: {height}");
        println!("Remote tip hash: {}", hex::encode(tip_hash));
    }

    println!("P2P message service is active. Waiting for peer requests...");
    serve_peer_session(&mut stream, &chain).context("P2P peer session ended")?;

    Ok(())
}
