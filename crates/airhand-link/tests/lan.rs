//! 局域网直连的端到端测试：被控端 [`airhand_link::host::lan::LanHub`] 监听，控制端
//! [`airhand_link::controller::lan`] 拨号，走真的 QUIC（回环）完成端到端握手，覆盖认证成功、密码错、
//! 以及暴力猜码限流（冷却）三种路径。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use airhand_link::host::lan::LanHub;
use airhand_link::lan::{Limiter, psk};
use airhand_link::secure::{Gate, Identity, PairingAttempt, controller_intro};
use airhand_link::host::{
    Acks, Admitted, MicSink, Platform, Request, Senders, Start, serve_lan,
};
use airhand_link::controller::FromHost;
use airhand_proto::handshake::PublicKey;
use airhand_proto::media::{self, VideoHeader};
use airhand_proto::session::{Codec, QualitySettings, StreamView};
use anyhow::Result;
use bytes::Bytes;
use tokio::sync::mpsc;

/// 一个被控端：账号 `admin` / 密码 `admin`，以及一个最小的 [`Gate`]。
struct LanGate {
    me: Identity,
    account: String,
    psk: [u8; 32],
}

impl LanGate {
    fn new(account: &str, password: &str) -> Self {
        Self {
            me: Identity::generate(),
            account: account.to_string(),
            psk: psk(account, password),
        }
    }
}

impl Gate for LanGate {
    fn identity(&self) -> Identity {
        self.me.clone()
    }
    fn begin_pairing(&self) -> Option<Box<dyn PairingAttempt + '_>> {
        None
    }
    fn is_known(&self, _key: &PublicKey) -> bool {
        false
    }
    fn lan_psk(&self, account: &str) -> Option<[u8; 32]> {
        (account == self.account).then_some(self.psk)
    }
}

/// 最小的 [`Platform`]：握手一通过就马上结束会话（我们只测认证，不测画面）。
struct Stub;

impl Acks for Stub {
    fn ack(&self, _stream: u8, _seq: u32, _arrived: u64) {}
}

impl MicSink for Stub {
    fn packet(&self, _packet: Vec<u8>) {}
}

impl Platform for Stub {
    type Event = ();

    fn acks(&self) -> Arc<dyn Acks> {
        Arc::new(Stub)
    }
    fn mic(&self) -> Option<Arc<dyn MicSink>> {
        Some(Arc::new(Stub))
    }
    async fn start(&mut self, _start: Start) -> Result<()> {
        Ok(())
    }
    async fn request(&mut self, _req: Request) -> Result<()> {
        Ok(())
    }
    async fn next_event(&mut self) -> () {
        std::future::pending().await
    }
    async fn event(&mut self, _event: ()) -> Result<()> {
        Ok(())
    }
    async fn stop(self) {}
}

/// 起一个被控端 listener，返回它的地址和（限流器、gate 的克隆）。`session` 驱动用 [`serve_lan`]。
/// 返回的 [`OwnedTask`] 是 accept 循环，调用方要一直持有到测试结束（丢掉就停）。
async fn spawn_host(
    limiter: Arc<Limiter>,
    gate: Arc<LanGate>,
) -> (SocketAddr, airhand_link::tasks::OwnedTask<()>) {
    let listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let session = {
        let gate = gate.clone();
        Arc::new(move |conn| {
            let gate = gate.clone();
            let fut = async move {
                // 会话一开始就结束：这里只验证端到端握手，不跑画面。
                // 把 serve_lan 的结果原样返回：认证失败（密码错）时 LanHub 据此记限流失败
                serve_lan(
                    conn,
                    &*gate,
                    2,
                    2,
                    |_: &Admitted, _: Senders| Stub,
                )
                .await
            };
            Box::pin(fut) as std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
        })
    };
    let (hub, task) = LanHub::start(listen, limiter, session).unwrap();
    (hub.local_addr(), task)
}

/// 控制端拨号一次，返回握手结果（`Established` 或错误）。
async fn dial(
    addr: SocketAddr,
    account: &str,
    password: &str,
) -> Result<airhand_link::controller::Established> {
    let me = Identity::generate();
    let intro = controller_intro(
        "ctl",
        "test",
        QualitySettings::default(),
        false,
        vec![StreamView::display(0)],
        false,
    );
    let endpoint = quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into()).unwrap();
    airhand_link::controller::lan::connect(&endpoint, addr, account, password, &me, &intro).await
}

/// 认证成功：账号密码对，两边端到端握手完成，安全码一致（不经过中转）。
#[tokio::test]
async fn correct_password_establishes_a_session() {
    let limiter = Arc::new(Limiter::new(Default::default()));
    let gate = Arc::new(LanGate::new("admin", "admin"));
    let (addr, _accept) = spawn_host(limiter, gate).await;

    let est = dial(addr, "admin", "admin").await.expect("auth should succeed");
    assert_eq!(est.session_id, 1);
    assert!(!est.safety.is_empty());
}

/// 认证失败：密码错，控制端得到 `LanAuthFailed`（不区分账号不存在，防枚举）。
#[tokio::test]
async fn wrong_password_is_refused() {
    let limiter = Arc::new(Limiter::new(Default::default()));
    let gate = Arc::new(LanGate::new("admin", "admin"));
    let (addr, _accept) = spawn_host(limiter.clone(), gate).await;

    let err = match dial(addr, "admin", "wrong").await {
        Err(e) => e,
        Ok(_) => panic!("auth must fail"),
    };
    let problem = err.downcast_ref::<airhand_link::Problem>();
    assert_eq!(
        problem,
        Some(&airhand_link::Problem::LanAuthFailed),
        "unexpected error: {err:#}"
    );
}

/// 暴力猜码限流：连续 5 次密码错之后进入冷却，第 6 次（即使密码对）也被拒。
/// 冷却 5 分钟，这里验证「冷却期内拒绝」的路径（真实等待 5 分钟由 limiter 单测覆盖）。
#[tokio::test]
async fn too_many_failures_cool_down() {
    let limiter = Arc::new(Limiter::new(Default::default()));
    let gate = Arc::new(LanGate::new("admin", "admin"));
    let (addr, _accept) = spawn_host(limiter.clone(), gate).await;

    // 5 次密码错
    for _ in 0..5 {
        let err = match dial(addr, "admin", "wrong").await {
            Err(e) => e,
            Ok(_) => panic!("auth must fail"),
        };
        assert_eq!(
            err.downcast_ref::<airhand_link::Problem>(),
            Some(&airhand_link::Problem::LanAuthFailed)
        );
    }
    // 进入冷却：即使密码对也被拒（连接层直接 refuse，控制端拿不到 Established）
    assert!(dial(addr, "admin", "admin").await.is_err());
}

/// 会话一开始就往第 0 路画面发一帧关键帧的 [`Platform`]：验证局域网直连的画面（不只是握手）能传到控制端。
struct SendVideo {
    video: Option<mpsc::Sender<Bytes>>,
}

impl Acks for SendVideo {
    fn ack(&self, _stream: u8, _seq: u32, _arrived: u64) {}
}

impl MicSink for SendVideo {
    fn packet(&self, _packet: Vec<u8>) {}
}

impl Platform for SendVideo {
    type Event = ();

    fn acks(&self) -> Arc<dyn Acks> {
        Arc::new(SendVideo { video: None })
    }
    fn mic(&self) -> Option<Arc<dyn MicSink>> {
        Some(Arc::new(SendVideo { video: None }))
    }
    async fn start(&mut self, _start: Start) -> Result<()> {
        // 一帧 H264 关键帧（负载只是占位字节，控制端只校验头、按 seq 合并，不解码）
        let h = VideoHeader {
            seq: 1,
            stream: 0,
            key: true,
            codec: Codec::H264,
            width: 8,
            height: 8,
            capture_us: 0,
            reference: None,
        };
        let frame = Bytes::from(media::frame(&h.encode(), &[&[1u8, 2, 3, 4]]));
        if let Some(v) = &self.video {
            let _ = v.send(frame).await;
        }
        Ok(())
    }
    async fn request(&mut self, _req: Request) -> Result<()> {
        Ok(())
    }
    async fn next_event(&mut self) -> () {
        std::future::pending().await
    }
    async fn event(&mut self, _event: ()) -> Result<()> {
        Ok(())
    }
    async fn stop(self) {}
}

/// 起一个会发画面帧的被控端 listener（[`spawn_host`] 的变体）。
async fn spawn_host_with_video(
    limiter: Arc<Limiter>,
    gate: Arc<LanGate>,
) -> (SocketAddr, airhand_link::tasks::OwnedTask<()>) {
    let listen: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let session = {
        let gate = gate.clone();
        Arc::new(move |conn| {
            let gate = gate.clone();
            let fut = async move {
                serve_lan(
                    conn,
                    &*gate,
                    2,
                    2,
                    |_: &Admitted, senders: Senders| SendVideo {
                        video: senders.video.first().cloned(),
                    },
                )
                .await
            };
            Box::pin(fut) as std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
        })
    };
    let (hub, task) = LanHub::start(listen, limiter, session).unwrap();
    (hub.local_addr(), task)
}

/// 画面真的能从被控端传到控制端（局域网直连，不只是握手）。
#[tokio::test]
async fn video_frames_reach_the_controller() {
    let limiter = Arc::new(Limiter::new(Default::default()));
    let gate = Arc::new(LanGate::new("admin", "admin"));
    let (addr, _accept) = spawn_host_with_video(limiter, gate).await;

    let est = dial(addr, "admin", "admin").await.expect("auth should succeed");
    let mut recv = est.receiver;

    // 先读到 Hello（会话开始时被控端必发），再等画面帧
    let mut saw_video = false;
    for _ in 0..8 {
        match tokio::time::timeout(std::time::Duration::from_secs(5), recv.recv())
            .await
            .expect("timed out waiting for the host")
            .expect("the host ended the session")
        {
            FromHost::Video { stream, packet, .. } => {
                assert_eq!(stream, 0);
                let h = VideoHeader::decode(&packet).expect("bad video header");
                assert_eq!((h.seq, h.key, h.codec), (1, true, Codec::H264));
                saw_video = true;
                break;
            }
            _ => continue,
        }
    }
    assert!(saw_video, "no video frame reached the controller");
}
