//! 控制台"局域网直连"页里保存的连接过的电脑，写在 config.toml 的 `[[lanDevice]]` 里
//! （和"我的设备"、LAN 设置在同一个文件，见 [`crate::config`]）。
//!
//! 与"我的设备"不同，这里要记下连接用的四个参数（IP、端口、账号、密码）：
//! * 四项**全部加密后**才写进文件（Windows 用当前用户的 DPAPI，见 [`crate::config::secret`]），
//!   `id` 也是 `IP:端口` 的散列，文件里看不到明文地址；
//! * 读给界面时只回传解密后的 IP 和端口，账号、密码被遮成圆点（见 [`LanDeviceView`]），
//!   真正连接时另用 `lan_device_credentials` 按 id 取回明文，明文不出现在设备列表里。
//!
//! Windows 安装版的配置由系统服务里的被控端维护：托盘进程加密好之后经命名管道交给它写，
//! 别的账户保存的项解不开，原样保留（和 `devices.rs` 一样）。

use airhand_proto::session::{Codec, QualitySettings};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use toml_edit::{InlineTable, Item, Table, Value};
use tracing::warn;

/// 每个账户最多保存多少台（控制台也按这个数截断）
pub const MAX: usize = 50;
/// 文件里最多多少项（含 Windows 上别的账户保存的）
pub const MAX_IN_FILE: usize = 200;
/// 地址、账号等文字的长度上限（字符）
const MAX_TEXT: usize = 200;
/// 加密后字符串的长度上限
const MAX_CIPHER: usize = 4096;

/// 一台保存过的 LAN 电脑。内存里/和前端之间是明文（camelCase），写进文件之前才加密（[`seal`]）。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LanDevice {
    /// `IP:端口` 的散列（由后端生成；前端回传时会被重新计算）
    #[serde(default)]
    pub id: String,
    /// 被控端的 IP
    pub addr: String,
    /// 被控端的 UDP 端口（十进制字符串）
    pub port: String,
    pub account: String,
    pub password: String,
    /// 用户起的名字（为空时显示 IP）
    #[serde(default)]
    pub alias: Option<String>,
    /// 上次连上时对方报告的名字
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub os: String,
    /// 最后一次连接的时间（Unix 毫秒）
    #[serde(default)]
    pub last_used: i64,
    /// 上次用的画质
    #[serde(default)]
    pub quality: Option<QualitySettings>,
}

/// 写进 `[[lanDevice]]` / 经 IPC 传给服务的内容：四个连接参数都是密文（base64）。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SealedLanDevice {
    pub id: String,
    pub addr: String,
    pub port: String,
    pub account: String,
    pub password: String,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub last_used: i64,
    #[serde(default)]
    pub quality: Option<QualitySettings>,
}

/// 给界面看的那一台：IP 和端口明文，账号和密码遮住。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanDeviceView {
    pub id: String,
    pub addr: String,
    pub port: String,
    pub account_masked: String,
    pub password_masked: String,
    pub alias: Option<String>,
    pub name: String,
    pub os: String,
    pub last_used: i64,
    pub quality: Option<QualitySettings>,
}

/// 点列表里的一项时，才按 id 取回明文去连接（不把密码留在列表状态里）。
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LanCredentials {
    pub addr: String,
    pub port: String,
    pub account: String,
    pub password: String,
}

/// 账号、密码显示时一律遮成固定长度，连长度都不泄露。
fn mask(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        "••••••".to_string()
    }
}

impl From<&LanDevice> for LanDeviceView {
    fn from(d: &LanDevice) -> Self {
        LanDeviceView {
            id: d.id.clone(),
            addr: d.addr.clone(),
            port: d.port.clone(),
            account_masked: mask(&d.account),
            password_masked: mask(&d.password),
            alias: d.alias.clone(),
            name: d.name.clone(),
            os: d.os.clone(),
            last_used: d.last_used,
            quality: d.quality,
        }
    }
}

fn clip(s: &str) -> String {
    s.trim().chars().take(MAX_TEXT).collect()
}

/// `IP:端口` 的 128 位散列（两个不同的 FNV-1a）。文件里不写明文地址，同时又要有稳定的 id。
pub fn id_for(addr: &str, port: &str) -> String {
    let key = format!("{}:{}", addr.trim(), port.trim());
    let mut a = 0xcbf2_9ce4_8422_2325u64;
    let mut b = 0x9ae1_6a3b_2f90_404fu64;
    for c in key.bytes() {
        a = (a ^ u64::from(c)).wrapping_mul(0x0100_0000_01b3);
        b = (b ^ u64::from(c)).wrapping_mul(0x0100_0000_01b3).rotate_left(13);
    }
    format!("{a:016x}{b:016x}")
}

fn valid_port(port: &str) -> bool {
    port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p > 0)
}

fn valid_addr(addr: &str) -> bool {
    !addr.is_empty()
        && addr.chars().count() <= MAX_TEXT
        && !addr.contains([' ', '\t', '\r', '\n', ':'])
}

/// 整理控制台发来的列表：去掉无效的、重复的，按最后连接时间排序，最多 [`MAX`] 台。
/// id 一律由 `IP:端口` 重新算，不信任前端传来的。
pub fn normalize(mut list: Vec<LanDevice>) -> Vec<LanDevice> {
    list.retain(|d| valid_addr(&d.addr) && valid_port(&d.port));
    list.sort_by_key(|d| std::cmp::Reverse(d.last_used));
    let mut seen = std::collections::HashSet::new();
    list.retain(|d| seen.insert(id_for(&d.addr, &d.port)));
    list.truncate(MAX);
    for d in &mut list {
        d.id = id_for(&d.addr, &d.port);
        d.addr = d.addr.trim().to_string();
        d.port = d.port.trim().to_string();
        d.account = clip(&d.account);
        d.name = clip(&d.name);
        d.os = clip(&d.os);
        d.alias = d.alias.as_deref().map(clip).filter(|a| !a.is_empty());
        // 密码可能有前导/尾随空格，不去 trim，只限长度
        d.password = d.password.chars().take(MAX_TEXT).collect();
    }
    list
}

/// `mass` 里的 `account` / `password` 传空串表示"沿用文件里已经存的那一个"：界面上只显示遮住的账号密码，
/// 重命名、改画质、重新排序时不能把真凭证覆盖掉。
fn keep_existing_credentials(list: &mut Vec<LanDevice>) {
    let existing: Vec<SealedLanDevice> = crate::config::read_text()
        .and_then(|t| t.parse::<toml_edit::DocumentMut>().ok())
        .map(|doc| entries(&doc))
        .unwrap_or_default();
    for d in list.iter_mut() {
        if d.account.is_empty() || d.password.is_empty() {
            if let Some(old) = existing
                .iter()
                .find(|e| e.id == d.id)
                .and_then(|e| open(e.clone()))
            {
                if d.account.is_empty() {
                    d.account = old.account;
                }
                if d.password.is_empty() {
                    d.password = old.password;
                }
            }
        }
    }
    list.retain(|d| !d.account.is_empty() && !d.password.is_empty());
}

// ───────────────────────────── 读 ─────────────────────────────

/// 配置文件里本账户的 LAN 电脑（文件不存在、没有时为空）。
pub fn load() -> Vec<LanDevice> {
    let Some(text) = crate::config::read_text() else {
        return Vec::new();
    };
    let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
        warn!("config.toml isn't valid TOML, can't read the saved LAN computers");
        return Vec::new();
    };
    let list = entries(&doc).into_iter().filter_map(open).collect();
    normalize(list)
}

/// 按 id 找到一台，取回明文（点列表项连接时调用）。
pub fn credentials(id: &str) -> Option<LanCredentials> {
    let d = load().into_iter().find(|d| d.id == id)?;
    Some(LanCredentials {
        addr: d.addr,
        port: d.port,
        account: d.account,
        password: d.password,
    })
}

/// 文件里的所有项（四个连接参数还没解密）。
pub fn entries(doc: &toml_edit::DocumentMut) -> Vec<SealedLanDevice> {
    let Some(arr) = doc.get("lanDevice").and_then(Item::as_array_of_tables) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(from_table)
        .take(MAX_IN_FILE)
        .collect()
}

fn str_of(t: &Table, k: &str) -> String {
    t.get(k)
        .and_then(Item::as_str)
        .map(clip)
        .unwrap_or_default()
}

fn from_table(t: &Table) -> Option<SealedLanDevice> {
    let cipher = |k: &str| {
        let s = t.get(k)?.as_str()?.trim().to_string();
        (!s.is_empty() && s.len() <= MAX_CIPHER).then_some(s)
    };
    let alias = str_of(t, "alias");
    Some(SealedLanDevice {
        id: str_of(t, "id"),
        addr: cipher("addr")?,
        port: cipher("port")?,
        account: cipher("account")?,
        password: cipher("password")?,
        alias: (!alias.is_empty()).then_some(alias),
        name: str_of(t, "name"),
        os: str_of(t, "os"),
        last_used: match t.get("last_used") {
            Some(Item::Value(Value::Datetime(d))) => {
                crate::devices::to_millis(d.value()).unwrap_or(0)
            }
            Some(Item::Value(Value::Integer(i))) => *i.value(),
            _ => 0,
        },
        quality: t.get("quality").and_then(quality_from),
    })
}

fn quality_from(item: &Item) -> Option<QualitySettings> {
    let t = item.as_table_like()?;
    let int = |k: &str| t.get(k).and_then(Item::as_integer);
    let codec = Codec::from_name(&t.get("codec").and_then(Item::as_str)?.to_ascii_lowercase())?;
    Some(QualitySettings {
        fps: u8::try_from(int("fps")?)
            .ok()
            .filter(|f| (1..=120).contains(f))?,
        bitrate_kbps: u32::try_from(int("bitrate_kbps")?).ok()?,
        max_short: u16::try_from(int("max_short")?).ok()?,
        adaptive: t.get("adaptive").and_then(Item::as_bool)?,
        codec,
        draw_cursor: false,
    })
}

/// 解开四个连接参数。解不开（别的账户保存的、坏了的）返回 `None`。
fn open(d: SealedLanDevice) -> Option<LanDevice> {
    let dec = |s: &str| crate::config::secret::open_lan(s).ok();
    let addr = dec(&d.addr)?;
    let port = dec(&d.port)?;
    let account = dec(&d.account)?;
    let password = dec(&d.password)?;
    if !valid_addr(&addr) || !valid_port(&port) {
        return None;
    }
    Some(LanDevice {
        id: d.id,
        addr,
        port,
        account,
        password,
        alias: d.alias,
        name: d.name,
        os: d.os,
        last_used: d.last_used,
        quality: d.quality,
    })
}

// ───────────────────────────── 写 ─────────────────────────────

/// 准备写进文件的完整列表：本账户的设备（四个参数加密后），Windows 上再加上文件里别的账户的设备（原样）。
pub fn for_file(mine: Vec<LanDevice>) -> Result<Vec<SealedLanDevice>> {
    let mut mine = normalize(mine);
    keep_existing_credentials(&mut mine);
    let mut out = Vec::with_capacity(mine.len());
    for d in &mine {
        out.push(seal(d.clone())?);
    }
    #[cfg(windows)]
    if let Some(doc) =
        crate::config::read_text().and_then(|t| t.parse::<toml_edit::DocumentMut>().ok())
    {
        out.extend(entries(&doc).into_iter().filter(|e| open(e.clone()).is_none()));
    }
    out.truncate(MAX_IN_FILE);
    Ok(out)
}

fn seal(mut d: LanDevice) -> Result<SealedLanDevice> {
    let seal_one = |s: &str| crate::config::secret::seal_lan(s);
    Ok(SealedLanDevice {
        id: d.id.clone(),
        addr: seal_one(&d.addr)?,
        port: seal_one(&d.port)?,
        account: seal_one(&d.account)?,
        password: seal_one(&d.password)?,
        alias: d.alias.take(),
        name: std::mem::take(&mut d.name),
        os: std::mem::take(&mut d.os),
        last_used: d.last_used,
        quality: d.quality,
    })
}

/// 写进 config.toml 的一项（Windows 上这份列表来自命名管道，要再检查一遍）。
pub fn to_table(d: &SealedLanDevice) -> Option<Table> {
    let cipher = |s: &str| {
        let s = s.trim();
        (!s.is_empty() && s.len() <= MAX_CIPHER && !s.contains(['\n', '\r'])).then(|| s.to_string())
    };
    let id = d.id.trim();
    if id.is_empty() || id.len() > 64 || id.contains(['\n', '\r']) {
        return None;
    }
    let mut t = Table::new();
    t["id"] = toml_edit::value(id);
    t["addr"] = toml_edit::value(cipher(&d.addr)?);
    t["port"] = toml_edit::value(cipher(&d.port)?);
    t["account"] = toml_edit::value(cipher(&d.account)?);
    t["password"] = toml_edit::value(cipher(&d.password)?);
    if let Some(a) = d.alias.as_deref().map(clip).filter(|a| !a.is_empty()) {
        t["alias"] = toml_edit::value(a);
    }
    let name = clip(&d.name);
    if !name.is_empty() {
        t["name"] = toml_edit::value(name);
    }
    let os = clip(&d.os);
    if !os.is_empty() {
        t["os"] = toml_edit::value(os);
    }
    if let Some(dt) = crate::devices::from_millis(d.last_used) {
        t["last_used"] = toml_edit::value(dt);
    }
    if let Some(q) = &d.quality {
        let mut it = InlineTable::new();
        it.insert("fps", i64::from(q.fps).into());
        it.insert("bitrate_kbps", i64::from(q.bitrate_kbps).into());
        it.insert("max_short", i64::from(q.max_short).into());
        it.insert("adaptive", q.adaptive.into());
        it.insert("codec", q.codec.or_h264().name().unwrap_or("h264").into());
        t["quality"] = toml_edit::value(it);
    }
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(addr: &str, port: &str, account: &str, password: &str) -> LanDevice {
        LanDevice {
            id: String::new(),
            addr: addr.into(),
            port: port.into(),
            account: account.into(),
            password: password.into(),
            alias: Some("书房".into()),
            name: "DESIGN-WS".into(),
            os: "Windows 11".into(),
            last_used: 1_762_597_230_000,
            quality: Some(QualitySettings {
                fps: 30,
                bitrate_kbps: 4000,
                max_short: 1080,
                adaptive: true,
                codec: Codec::H265,
                draw_cursor: false,
            }),
        }
    }

    #[test]
    fn id_is_stable_and_hides_the_address() {
        let id = id_for("192.168.1.10", "4900");
        assert_eq!(id, id_for("192.168.1.10", "4900"));
        assert_ne!(id, id_for("192.168.1.11", "4900"));
        assert_ne!(id, id_for("192.168.1.10", "4901"));
        assert!(!id.contains("192.168"));
        assert_eq!(id.len(), 32);
        // 前端的 lanDeviceId() 用同样的 FNV-1a 算 id；这个常量是两边对齐的测试向量
        assert_eq!(id, "96d05ae74e8e6f59971e1738648663e7");
    }

    #[test]
    fn normalize_validates_dedups_sorts_and_recomputes_id() {
        let mut list = vec![
            device("192.168.1.10", "4900", "admin", "pw"),
            device("192.168.1.10", "4900", "admin", "pw2"),
            device("192.168.1.11", "65536", "admin", "pw"),
            device("192.168.1.12", "0", "admin", "pw"),
            device("bad addr", "4900", "admin", "pw"),
            device("192.168.1.13", "4900", "admin", "pw"),
        ];
        list[0].last_used = 2_000;
        let out = normalize(list);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].addr, "192.168.1.10");
        assert_eq!(out[0].id, id_for("192.168.1.10", "4900"));
        // 重复地址保留时间最新的那台（后写的 pw2）
        assert_eq!(out[0].password, "pw2");
    }

    /// 四项都加密写进文件、再读回来能解开；文件里没有明文 IP/账号/密码/端口。
    #[test]
    fn sealed_roundtrip() {
        let d = device("192.168.1.10", "4900", "admin", "s3cret");
        let sealed = seal(normalize(vec![d.clone()])[0].clone()).unwrap();
        let table = to_table(&sealed).unwrap();
        let text = table.to_string();
        assert!(!text.contains("192.168.1.10"));
        assert!(!text.contains("admin"));
        assert!(!text.contains("s3cret"));
        let back = from_table(&table).unwrap();
        let opened = open(back).unwrap();
        assert_eq!(opened, normalize(vec![d])[0]);
        // 界面看到的是打码的
        let view = LanDeviceView::from(&opened);
        assert_eq!(view.addr, "192.168.1.10");
        assert_eq!(view.port, "4900");
        assert_eq!(view.account_masked, "••••••");
        assert_eq!(view.password_masked, "••••••");
    }

    #[test]
    fn broken_entry_is_ignored() {
        let mut t = Table::new();
        t["id"] = toml_edit::value("bad");
        t["addr"] = toml_edit::value("AAAA");
        t["port"] = toml_edit::value("AAAA");
        t["account"] = toml_edit::value("AAAA");
        t["password"] = toml_edit::value("AAAA");
        assert_eq!(from_table(&t).and_then(open), None);
    }
}
