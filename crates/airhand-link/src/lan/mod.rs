//! 局域网直连（协议见 `airhand_proto::handshake` 的 `Pattern::Lan`）。
//!
//! 被控端在本机监听一个 UDP 端口（QUIC），控制端输入 `IP:端口 + 账号 + 密码` 即可**完全不经过中转服务器**建立会话。
//!
//! 本模块只放与传输无关的纯逻辑：
//!
//! * [`psk`]：密码经 PBKDF2-HMAC-SHA256 派生为握手 PSK（`Noise_XXpsk0`），账号密码绝不在握手外明文传输；
//! * [`limiter`]：按来源 IP 的暴力猜码限流（默认 5 次 / 冷却 5 分钟，可动态调整）。
//!
//! 两端各自的传输与会话建立（复用 [`crate::direct::tls`]、[`crate::lanes`]、[`crate::secure`]）在
//! [`crate::host::lan`]（被控端 listener）与 [`crate::controller::lan`]（控制端拨号）。

pub mod limiter;
pub mod psk;

pub use limiter::{Config as LimitConfig, Limiter};
pub use psk::{Account, hex, psk, unhex32};
