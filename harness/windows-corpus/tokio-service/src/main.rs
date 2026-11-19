use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn service_banner() -> &'static str {
    "tokio-service 0.1.0"
}

async fn serve_once(listener: TcpListener) -> std::io::Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let mut payload = Vec::new();
    stream.read_to_end(&mut payload).await?;
    let reply = format!("{}: {}", service_banner(), String::from_utf8_lossy(&payload));
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await
}

async fn roundtrip(msg: &str) -> std::io::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(serve_once(listener));

    let mut client = TcpStream::connect(addr).await?;
    client.write_all(msg.as_bytes()).await?;
    client.shutdown().await?;

    let mut response = String::new();
    client.read_to_string(&mut response).await?;
    server.await.map_err(std::io::Error::other)??;
    Ok(response)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("{}", service_banner());
        return Ok(());
    }
    let reply = roundtrip("ping").await?;
    println!("{reply}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_echoes_banner_and_payload() {
        let reply = roundtrip("hello-iocp").await.expect("tokio TCP roundtrip");
        assert_eq!(reply, format!("{}: hello-iocp", service_banner()));
    }
}
