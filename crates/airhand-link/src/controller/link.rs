//! 控制端一个会话的链路：服务器批准之后，在控制通道上做完端到端握手、开好本端的通道、建好接收端。
//! [`super::ControllerService`] 用它，测试和调试工具也可以直接用（自己决定发什么、怎么处理收到的）。

use std::sync::Arc;

use airhand_proto::SessionLane;
use airhand_proto::handshake::PublicKey;
use anyhow::Result;
use quinn::{Connection, RecvStream, SendStream};

use super::receiver::HostReceiver;
use crate::lanes::{Feed, Inbox, LaneStreams, Registration, Router, Via, first_stream, open_lane};
use crate::merge::Merge;
use crate::paths::{DatagramSender, Paths};
use crate::secure::{FileKeys, Initiated, Initiator, STEP_TIMEOUT, Sealer};
use crate::tasks::OwnedTask;

/// 握手做完了、本端的通道开好了的会话（见模块说明）
pub struct Established {
    pub session_id: u64,
    /// 被控端的公钥、安全码（见 `airhand_proto::handshake`）
    pub peer: PublicKey,
    pub safety: String,
    /// 本端的控制通道（写的一半）和它的加密端（已经发出了确认，计数接着往下数）
    pub control: (SendStream, Sealer),
    /// 本端的大块通道
    pub bulk: (SendStream, Sealer),
    /// 会话的两条路：现在只有中转，直连通了由直连任务接上（见 [`crate::direct`]）
    pub paths: Paths,
    /// 发控制数据报（Ping、画面确认）
    pub datagrams: DatagramSender,
    /// 麦克风声音数据报的加密端，见 `airhand_proto::session` 的“麦克风”。
    pub mic: Sealer,
    /// 被控端发来的东西（被控端的探测在里面就弹回去了）
    pub receiver: HostReceiver,
    /// 直连上来的流、数据报交给这个会话
    pub feed: Feed,
    /// 剪贴板里的文件：每次取用的密钥，被控端开过来的文件流（见 [`crate::files`]）
    pub files: (FileKeys, LaneStreams),
    /// 在中转连接上的登记：丢掉之后不再收这个会话的东西
    pub registration: Registration,
    /// 分发对方流的 [`Router`] 任务。中转模式下由连服务器的任务持有（见 [`crate::controller::connect_once`]），
    /// 这里是 `None`；局域网直连模式的 [`crate::controller::lan::establish`] 里现建现用，握手一结束就没有别的
    /// 持有者了，必须放进这里随会话存活，否则之后被控端发来的每一帧视频流（每帧一条单向流）没人收、画面黑屏。
    pub router_task: Option<OwnedTask<()>>,
}

/// 服务器批准了会话 `session_id`（发起时的握手是 `initiator`）：等被控端在控制通道上回答、做完握手、开好通道。
/// 失败时的错误是 [`crate::Problem`]（对方身份变了、要配对码……，见 [`Initiator::finish`]）或者网络错误
pub async fn establish(
    router: &Arc<Router>,
    conn: &Connection,
    session_id: u64,
    initiator: Initiator,
) -> Result<Established> {
    let (mut inbox, registration) = router.register(session_id);
    let mut control_in = first_stream(&mut inbox.control, STEP_TIMEOUT).await?;
    let mut control = open_lane(conn, session_id, SessionLane::Control).await?;
    let done = initiator.finish(&mut control_in, &mut control).await?;
    finish_established(
        session_id,
        conn,
        registration,
        inbox,
        control_in,
        control,
        done,
        // 中转模式下 Router 任务由连服务器的任务持有（见 [`crate::controller::connect_once`]）
        None,
    )
    .await
}
/// 局域网直连（[`crate::controller::lan`]）：与 [`establish`] 的区别只在握手的第一条消息
/// （[`airhand_proto::handshake::HandshakeInit`]）没有服务器转交，而是控制端写在它自己的控制通道上。
/// `init` 是 [`crate::secure::initiate`] 返回的第一条消息（已经由调用方写好会话头之后交给这里）。
/// `router_task`：分发这条连接上对方流的 [`Router`] 任务。局域网直连的 Router 是现建现用的，握手结束后
/// 必须随会话存活，否则之后被控端发来的视频帧流没人收（见 [`Established::router_task`]）。
pub async fn establish_lan(
    router: &Arc<Router>,
    conn: &Connection,
    session_id: u64,
    init: &[u8],
    initiator: Initiator,
    router_task: OwnedTask<()>,
) -> Result<Established> {
    use crate::wire::write_frame;
    let (mut inbox, registration) = router.register(session_id);
    // 控制端自己的控制通道：先写下握手的第一条消息（HandshakeInit 的 CBOR，包一层长度前缀），
    // 再在它上面做完剩下的握手
    let mut control = open_lane(conn, session_id, SessionLane::Control).await?;
    write_frame(&mut control, init).await?;
    let mut control_in = first_stream(&mut inbox.control, STEP_TIMEOUT).await?;
    let done = initiator.finish(&mut control_in, &mut control).await?;
    finish_established(
        session_id,
        conn,
        registration,
        inbox,
        control_in,
        control,
        done,
        Some(router_task),
    )
    .await
}

/// 握手完成之后共同的部分：开本端的通道、建接收端（见 [`Established`]）。
async fn finish_established(
    session_id: u64,
    conn: &Connection,
    registration: Registration,
    mut inbox: Inbox,
    control_in: RecvStream,
    control: SendStream,
    done: Initiated,
    router_task: Option<OwnedTask<()>>,
) -> Result<Established> {
    let bulk = open_lane(conn, session_id, SessionLane::Bulk).await?;
    let mut secured = done.secured;
    let paths = Paths::new(conn.clone());
    let datagrams = DatagramSender::new(session_id, paths.clone(), secured.datagrams.sealer);
    let mut control_merge = Merge::new(SessionLane::Control, done.opener, inbox.control);
    control_merge.add(control_in, Via::Relay)?;
    // 画面的每一路（见 airhand_proto::session 的"多屏"）：各自的帧流和密钥
    let video = std::mem::take(&mut secured.video)
        .into_iter()
        .zip(inbox.video.drain(..))
        .enumerate()
        .map(|(stream, (keys, streams))| {
            Merge::new(SessionLane::Video(stream as u8), keys.opener, streams)
        })
        .collect();
    let receiver = HostReceiver::new(
        control_merge,
        Merge::new(SessionLane::Bulk, secured.bulk.opener, inbox.bulk),
        video,
        (inbox.audio, secured.audio.opener),
        (inbox.datagrams, secured.datagrams.opener),
        datagrams.clone(),
    );
    Ok(Established {
        session_id,
        peer: secured.peer,
        safety: secured.safety,
        control: (control, done.sealer),
        bulk: (bulk, secured.bulk.sealer),
        paths,
        datagrams,
        mic: secured.audio.sealer,
        receiver,
        feed: inbox.feed,
        files: (secured.files, inbox.files),
        registration,
        router_task,
    })
}
