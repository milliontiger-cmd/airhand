//! 被控端的局域网直连 listener（协议见 `airhand_proto::handshake` 的 `Pattern::Lan` 与 [`crate::lan`]）。
//!
//! 被控端在本机监听一个 UDP 端口（QUIC，`LAN_ALPN`），控制端输入 `IP:端口 + 账号 + 密码` 即可**完全不经过中转
//! 服务器**建立会话。与中转不同：没有服务器转发 [`HandshakeInit`]，控制端在自己的控制通道上先写下这条握手消息，
//! 被控端从那条流里读出来、交给 [`super::serve_lan`]，之后与会话的其余部分完全复用（把这条直连 QUIC 连接当作
//! [`Paths`] 的中转，`direct` 为 `None`，见 [`super::HostStreams::finish`]）。
//!
//! 暴力猜码限流（[`crate::lan::Limiter`]）：同一个来源 IP 连续失败 `max_failures` 次后冷却 `cooldown` 时间，
//! 冷却期间直接拒绝握手。账号不存在与密码错误走同一条失败路径（[`airhand_proto::handshake::HandshakeError::LanAuthFailed`]），
//! 防账号枚举。
//!
//! 账号 → PSK 的映射在 [`Gate::lan_psk`] 里，由调用方（桌面版、Android）实现；`session` 是每来一个控制端调用一次的
//! 会话驱动（[`super::serve_lan`] 的封装，各平台传入自己的 `gate` + `platform` 工厂）。

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{Connection, Endpoint};
use std::time::Instant;
use tracing::{debug, info, warn};

use airhand_proto::LAN_ALPN;

use crate::direct::tls::{self, Cert};
use crate::lan::Limiter;
use crate::tasks::OwnedTask;

/// 局域网直连会话共用的会话 ID（一条直连连接只有一个会话，两端用同一个值即可）。
pub const LAN_SESSION_ID: u64 = 1;

/// 每来一个控制端调用一次的会话驱动（见模块说明）。返回 `Err` 表示端到端认证失败（账号/密码错），
/// 被 [`LanHub`] 用来记限流失败；`Ok` 表示会话正常结束（认证已通过）。
pub type LanSession =
    Arc<dyn Fn(Connection) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

/// 被控端的局域网直连 listener（见模块说明）。
pub struct LanHub {
    endpoint: Endpoint,
    limiter: Arc<Limiter>,
    session: LanSession,
}

impl LanHub {
    /// 在被控端本机开始监听 `listen`（QUIC，`LAN_ALPN`），接受控制端的局域网直连。返回的 listener 任务丢掉时停止。
    /// `session`：每来一个控制端调用一次（已经过了 QUIC 握手和限流，还没做端到端认证；认证在
    /// [`super::serve_lan`] 里，各平台的 `session` 把它和自己的 `gate` + `platform` 一起接上）。
    pub fn start(
        listen: SocketAddr,
        limiter: Arc<Limiter>,
        session: LanSession,
    ) -> Result<(Arc<Self>, OwnedTask<()>)> {
        let cert = Cert::generate()?;
        let endpoint = lan_endpoint(Some(tls::server_config_alpn(&cert, LAN_ALPN)?), listen)?;
        let hub = Arc::new(Self {
            endpoint,
            limiter,
            session,
        });
        info!(%listen, "LAN direct path listening");
        let task = OwnedTask(tokio::spawn(hub.clone().accept()));
        Ok((hub, task))
    }

    /// 实际监听着的地址（监听 `0.0.0.0` 时是其中的某个具体地址）。
    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint
            .local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
    }

    async fn accept(self: Arc<Self>) {
        while let Some(incoming) = self.endpoint.accept().await {
            let hub = self.clone();
            tokio::spawn(async move {
                let from = incoming.remote_address();
                match hub.serve(incoming).await {
                    Ok(()) => {}
                    Err(e) => debug!(%from, "refused a LAN connection: {e:#}"),
                }
            });
        }
    }

    /// 一条局域网直连：限流检查、握手，通过后交给 `session` 驱动。
    async fn serve(&self, incoming: quinn::Incoming) -> Result<()> {
        let ip = incoming.remote_address().ip();
        // 冷却期直接拒绝（在 QUIC 握手之前就挡掉，不给猜码者反馈之外的资源）
        if !self.limiter.allow(ip, Instant::now()) {
            incoming.refuse();
            warn!(%ip, "a LAN controller is cooling down after too many failed attempts");
            return Ok(());
        }
        let conn = incoming.accept()?.await?;
        // session（各平台接上的 serve_lan）做端到端认证：失败（账号/密码错）记一次，成功清掉这个来源的记录
        match (self.session)(conn).await {
            Ok(()) => self.limiter.record_success(ip),
            Err(e) => {
                self.limiter.record_failure(ip, Instant::now());
                debug!(%ip, "a LAN controller failed authentication: {e:#}");
            }
        }
        Ok(())
    }
}

/// 构造一个监听用的 QUIC [`Endpoint`]（服务端，`LAN_ALPN`）。
fn lan_endpoint(server: Option<quinn::ServerConfig>, listen: SocketAddr) -> Result<Endpoint> {
    let socket = crate::udp::bind(listen, true).context("can't bind the LAN listener socket")?;
    Endpoint::new(
        quinn::EndpointConfig::default(),
        server,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .context("can't create the LAN endpoint")
}
