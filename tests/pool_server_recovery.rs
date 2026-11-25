use nezora_supply::blockchain::pool_network::{PoolTcpRequest, PoolTcpResponse, PoolTcpServer};
use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpStream},
    thread,
};

fn send_ping(address: SocketAddr) -> PoolTcpResponse {
    let mut stream = TcpStream::connect(address).expect("connect after interrupted client");
    let mut request = serde_json::to_vec(&PoolTcpRequest::Ping {}).expect("encode ping");
    request.push(b'\n');
    stream.write_all(&request).expect("send ping");

    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .expect("read ping response");
    serde_json::from_str(response.trim()).expect("decode ping response")
}

#[test]
fn server_accepts_next_client_after_previous_client_disconnects() {
    let server = PoolTcpServer::bind_loopback(0).expect("bind loopback server");
    let address = server.local_addr().expect("get server address");

    let server_thread = thread::spawn(move || {
        let interrupted_connection = server.serve_one();
        assert!(
            interrupted_connection.is_err(),
            "incomplete client frame should be rejected"
        );

        // The listener should remain usable after the failed client connection.
        server
            .serve_one()
            .expect("server should accept the next client");
    });

    // Connect and immediately close without sending a complete newline frame.
    drop(TcpStream::connect(address).expect("connect interrupted client"));

    let response = send_ping(address);
    server_thread.join().expect("join server thread");

    assert_eq!(
        response,
        PoolTcpResponse::Pong {
            protocol: "nezora-pool".to_owned(),
            version: 1,
        }
    );
}
