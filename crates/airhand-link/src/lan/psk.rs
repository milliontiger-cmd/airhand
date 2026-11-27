//! 局域网直连的 PSK 派生与账号记录（协议见 `airhand_proto::handshake` 的 `Pattern::Lan`）。
//!
//! 密码经 PBKDF2-HMAC-SHA256 派生后作为 Noise 握手的 PSK（`Noise_XXpsk0`），账号、密码都不上明文线
//! （账号以明文形式随 [`airhand_proto::handshake::HandshakeInit`] 出现，但它是定位用、不是秘密；密码才是秘密）。
//!
//! # 派生规格
//!
//! ```text
//! salt = SHA-256(b"airhand lan psk v1" ‖ utf8(account))
//! psk  = PBKDF2-HMAC-SHA256(password, salt, LAN_PBKDF2_ITER, 32)
//! ```
//!
//! 盐是「确定性」的（由账号派生），不是随机盐：这样控制端和被控端都能在握手开始前独立派生 PSK
//! （`psk0` 需要在 Noise 第 1 条消息之前就设置），不需要额外的一轮「拿盐」往返。账号参与盐派生，
//! 不同账号同密码不碰撞；`psk` 本身是 32 字节高熵值，被控端存的就是它（「握手 PSK」），
//! 不存密码哈希——攻击者拿到 `psk` 也无法反推密码，真正的安全边界是「在线暴力猜密码」，由限流器防护
//! （见 `host.rs` 的 [`crate::lan::Limiter`]）。

use sha2::{Digest, Sha256};

use airhand_proto::LAN_PBKDF2_ITER;

/// 盐派生的 domain separation 前缀
const SALT_PREFIX: &[u8] = b"airhand lan psk v1";

/// 由「账号 + 密码」派生握手 PSK（32 字节）。控制端和被控端各自独立调用，结果一致。
pub fn psk(account: &str, password: &str) -> [u8; 32] {
    let salt = salt_of(account);
    let mut out = [0u8; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(LAN_PBKDF2_ITER).expect("nonzero"),
        &salt,
        password.as_bytes(),
        &mut out,
    );
    out
}

/// 由账号派生盐（SHA-256(prefix ‖ utf8(account))）
fn salt_of(account: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SALT_PREFIX);
    h.update(account.as_bytes());
    h.finalize().into()
}

/// 一个局域网直连账号（被控端本地配置里存的，见 `client/src-tauri/src/config.rs` 的 `[lan.accounts]`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    /// 握手 PSK（`psk(name, password)` 的结果），64 位小写十六进制
    pub psk: String,
}

impl Account {
    /// 从账号名和明文密码生成（只在用户新建/改密码时用一次，之后只存 `psk`）
    pub fn from_password(name: &str, password: &str) -> Self {
        Account {
            name: name.to_string(),
            psk: hex(&psk(name, password)),
        }
    }

    /// 解析存储的 64 位十六进制 PSK
    pub fn parse_psk(&self) -> Option<[u8; 32]> {
        unhex32(&self.psk)
    }
}

/// 字节写成 64 位小写十六进制
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// 解析 64 位十六进制
pub fn unhex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 固定向量：同一账号密码，两端派生一致；不同账号、不同密码都不同
    #[test]
    fn psk_is_deterministic_and_separates_inputs() {
        assert_eq!(psk("admin", "admin"), psk("admin", "admin"));
        assert_ne!(psk("admin", "admin"), psk("admin", "wrong"));
        assert_ne!(psk("admin", "admin"), psk("other", "admin"));
        // 32 字节、非零
        let k = psk("admin", "admin");
        assert_eq!(k.len(), 32);
        assert_ne!(k, [0u8; 32]);
    }

    #[test]
    fn account_roundtrip() {
        let a = Account::from_password("admin", "admin");
        assert_eq!(a.name, "admin");
        assert_eq!(a.parse_psk(), Some(psk("admin", "admin")));
        assert_eq!(hex(&[0xab; 32]).len(), 64);
        assert_eq!(unhex32(&hex(&[0xab; 32])), Some([0xab; 32]));
        assert_eq!(unhex32("zz"), None);
    }
}
