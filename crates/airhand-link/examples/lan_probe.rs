//! 临时诊断工具：连一个局域网直连的被控端，读消息，看能否收到 Hello / 视频帧。
//! `cargo run -p airhand-link --example lan_probe -- 127.0.0.1:4900 admin admin`
use airhand_link::controller::FromHost;
use airhand_link::secure::{Identity, controller_intro};
use airhand_proto::session::{QualitySettings, StreamView};
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let addr: std::net::SocketAddr = args.get(1).cloned().unwrap_or("127.0.0.1:4900".into()).parse().unwrap();
    let account = args.get(2).cloned().unwrap_or("admin".into());
    let password = args.get(3).cloned().unwrap_or("admin".into());

    let me = Identity::generate();
    let intro = controller_intro(
        "probe",
        "test",
        QualitySettings::default(),
        false,
        vec![StreamView::display(0)],
        false,
    );
    let endpoint = airhand_link::controller::lan::endpoint().unwrap();
    let est = match airhand_link::controller::lan::connect(&endpoint, addr, &account, &password, &me, &intro).await {
        Ok(e) => e,
        Err(e) => {
            eprintln!("connect failed: {e:#}");
            return;
        }
    };
    println!("CONNECTED, session={}", est.session_id);
    let mut recv = est.receiver;
    for i in 0..30 {
        match tokio::time::timeout(Duration::from_secs(3), recv.recv()).await {
            Ok(Ok(FromHost::Control(m))) => println!("[{i}] Control: {m:?}"),
            Ok(Ok(FromHost::Video { stream, packet, .. })) => {
                println!("[{i}] VIDEO stream={stream} len={}", packet.len())
            }
            Ok(Ok(FromHost::VideoEvent(s, v))) => println!("[{i}] VideoEvent stream={s} {v:?}"),
            Ok(Ok(FromHost::Pong(t))) => println!("[{i}] Pong {t}"),
            Ok(Ok(FromHost::Audio(_))) => println!("[{i}] Audio"),
            Ok(Err(e)) => {
                eprintln!("[{i}] recv err: {e:#}");
                break;
            }
            Err(_) => {
                println!("[{i}] timeout");
                break;
            }
        }
    }
}
