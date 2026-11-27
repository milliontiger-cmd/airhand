//! 控制端的局域网直连（协议见 `airhand_proto::handshake` 的 `Pattern::Lan` 与 [`crate::lan`]）。
//!
//! 控制端输入 `IP:端口 + 账号 + 密码`，从本机的 endpoint 拨号（QUIC，`LAN_ALPN`），在自己的控制通道上先写下
//! 握手的第一条消息（[`HandshakeInit`]，账号明文 + Noise 消息），然后与中转一样在控制通道上做完握手
//! （[`crate::controller::establish_lan`]）。之后与 [`super::ControllerService`] 的会话完全一样
//! （[`super::Established`] 直接喂给 [`super::session`]）。
//!
//! 认证在 Noise 握手里（账号密码派生的 PSK，见 [`crate::lan::psk`]）：密码绝不上明文线，账号以明文随 `HandshakeInit` 出现
//! （定位用，不是秘密）。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint};

use airhand_proto::handshake::ControllerIntro;

use super::link::{Established, establish_lan};
use crate::direct::tls::{self, Cert, SERVER_NAME};
use crate::lan;
use crate::lanes::Router;
use crate::secure::{self, Identity, LanCredential};

/// 拨号 + 握手最多等这么久
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// 控制端拨号用的 QUIC [`Endpoint`]（客户端，任何服务器证书都接受，端到端安全在 Noise PSK 里）。
pub fn endpoint() -> Result<Endpoint> {
    let socket = crate::udp::bind("[::]:0".parse().unwrap(), true)
        .context("can't bind the LAN controller socket")?;
    Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("can't create the LAN endpoint")
}

/// 局域网直连会话共用的会话 ID（见 [`crate::host::lan::LAN_SESSION_ID`]）。
const LAN_SESSION_ID: u64 = 1;

/// 控制端：连一台局域网直连的被控端。
///
/// * `addr`：被控端监听的 `IP:端口`；
/// * `account` / `password`：账号密码（密码只在本地派生 PSK，绝不上线）；
/// * `me`：本机的身份（Noise 静态密钥）；
/// * `intro`：本端的介绍（名称、系统、开始时的画质等，见 [`secure::controller_intro`]）。
///
/// 返回 [`Established`]，与中转的会话链路完全一致，交给 [`super::ControllerService`] 的会话逻辑。
pub async fn connect(
    endpoint: &Endpoint,
    addr: SocketAddr,
    account: &str,
    password: &str,
    me: &Identity,
    intro: &ControllerIntro,
) -> Result<Established> {
    let cert = Cert::generate()?;
    let config = tls::client_config_lan(&cert)?;
    let conn = tokio::time::timeout(
        CONNECT_TIMEOUT,
        async {
            endpoint
                .connect_with(config, addr, SERVER_NAME)
                .map_err(anyhow::Error::from)?
                .await
                .map_err(anyhow::Error::from)
        },
    )
    .await
    .context("timed out connecting the LAN host")??;
    establish(&conn, account, password, me, intro).await
}

/// 在已经连上的 QUIC 连接上做局域网直连握手（[`connect`] 的拨号之后的部分，测试也直接用）。
pub async fn establish(
    conn: &Connection,
    account: &str,
    password: &str,
    me: &Identity,
    intro: &ControllerIntro,
) -> Result<Established> {
    let psk = lan::psk(account, password);
    let (initiator, init) = secure::initiate(secure::InitiatorParams {
        code: 0,
        me,
        host_key: None,
        pairing: None,
        lan: Some(LanCredential {
            account: account.to_string(),
            psk,
        }),
        intro,
    })?;
    let (router, router_task) = Router::start(conn);
    establish_lan(&router, conn, LAN_SESSION_ID, &init, initiator, router_task).await
}
