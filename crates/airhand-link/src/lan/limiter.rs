//! 局域网直连的暴力猜码限流：同一来源（IP）连续失败 [`Config::max_failures`] 次后，
//! 冷却 [`Config::cooldown`] 时间，期间直接拒绝，冷却结束后重新计数。
//!
//! 与配对码的「暂停直到换码」不同，局域网直连没有「换码」概念，所以用「冷却一段时间后恢复」。
//! 阈值与冷却时长可在运行时动态调整（用户在设置里改）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 限流参数（可在运行时改）
#[derive(Debug, Clone)]
pub struct Config {
    /// 连续失败多少次后进入冷却
    pub max_failures: u32,
    /// 冷却时长
    pub cooldown: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_failures: 5,
            cooldown: Duration::from_secs(5 * 60),
        }
    }
}

/// 每个来源的失败计数与冷却截止时间
#[derive(Debug)]
struct Entry {
    failures: u32,
    /// 冷却结束的时刻（进入冷却时设置；`None` 表示不在冷却）
    cooldown_until: Option<Instant>,
}

/// 一个按来源 IP 记失败次数的限流器。
#[derive(Default)]
pub struct Limiter {
    state: Mutex<HashMap<IpAddr, Entry>>,
    config: Mutex<Config>,
}

impl Limiter {
    pub fn new(config: Config) -> Self {
        Limiter {
            state: Mutex::new(HashMap::new()),
            config: Mutex::new(config),
        }
    }

    /// 更新限流参数（用户在设置里改端口时一并可能改这里）
    pub fn set_config(&self, config: Config) {
        *self.config.lock().unwrap() = config;
    }

    /// 当前限流参数
    pub fn config(&self) -> Config {
        self.config.lock().unwrap().clone()
    }

    /// 这个来源现在能不能尝试一次认证。在冷却期返回 `false`。
    pub fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        let state = self.state.lock().unwrap();
        let Some(e) = state.get(&ip) else {
            return true;
        };
        match e.cooldown_until {
            Some(until) if now < until => false,
            _ => true,
        }
    }

    /// 记一次失败。返回是否因此进入（或已处于）冷却。
    pub fn record_failure(&self, ip: IpAddr, now: Instant) -> bool {
        let cfg = self.config();
        let mut state = self.state.lock().unwrap();
        let e = state.entry(ip).or_insert(Entry {
            failures: 0,
            cooldown_until: None,
        });
        // 冷却已过：重新从 1 开始数
        if let Some(until) = e.cooldown_until
            && now >= until
        {
            e.cooldown_until = None;
            e.failures = 0;
        }
        e.failures += 1;
        if e.failures >= cfg.max_failures {
            e.cooldown_until = Some(now + cfg.cooldown);
            true
        } else {
            false
        }
    }

    /// 认证成功：清掉这个来源的记录。
    pub fn record_success(&self, ip: IpAddr) {
        self.state.lock().unwrap().remove(&ip);
    }

    /// 清理过期条目（可定时调用，避免无限增长）
    pub fn prune(&self, now: Instant) {
        let mut state = self.state.lock().unwrap();
        state.retain(|_, e| {
            e.cooldown_until
                .is_none_or(|until| now < until)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }

    #[test]
    fn five_failures_then_cooldown_then_recovery() {
        let limiter = Limiter::new(Config::default());
        let t0 = Instant::now();
        let ip = ip();
        // 前 4 次失败不进入冷却
        for _ in 0..4 {
            assert!(limiter.allow(ip, t0));
            assert!(!limiter.record_failure(ip, t0));
        }
        // 第 5 次失败进入冷却
        assert!(limiter.allow(ip, t0));
        assert!(limiter.record_failure(ip, t0));
        // 冷却期内拒绝
        assert!(!limiter.allow(ip, t0 + Duration::from_secs(60)));
        // 冷却结束（恰好 5 分钟）后恢复
        assert!(limiter.allow(ip, t0 + Duration::from_secs(5 * 60)));
        // 恢复后又能尝试；再失败重新计数
        assert!(!limiter.record_failure(ip, t0 + Duration::from_secs(5 * 60)));
    }

    #[test]
    fn success_resets_the_counter() {
        let limiter = Limiter::new(Config::default());
        let t0 = Instant::now();
        let ip = ip();
        for _ in 0..4 {
            limiter.record_failure(ip, t0);
        }
        limiter.record_success(ip);
        for _ in 0..4 {
            assert!(limiter.allow(ip, t0));
            assert!(!limiter.record_failure(ip, t0));
        }
        assert!(limiter.record_failure(ip, t0));
    }

    #[test]
    fn config_is_adjustable_at_runtime() {
        let limiter = Limiter::new(Config::default());
        let t0 = Instant::now();
        let ip = ip();
        limiter.set_config(Config {
            max_failures: 2,
            cooldown: Duration::from_secs(60),
        });
        assert!(!limiter.record_failure(ip, t0));
        assert!(limiter.record_failure(ip, t0));
        assert!(!limiter.allow(ip, t0));
        assert!(limiter.allow(ip, t0 + Duration::from_secs(61)));
    }

    #[test]
    fn different_ips_are_independent() {
        let limiter = Limiter::new(Config::default());
        let t0 = Instant::now();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..5 {
            limiter.record_failure(a, t0);
        }
        assert!(!limiter.allow(a, t0));
        assert!(limiter.allow(b, t0));
    }
}
