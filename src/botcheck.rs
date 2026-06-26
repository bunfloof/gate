use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const ALLOWED_SUFFIXES: &[&str] = &[".googlebot.com.", ".google.com.", ".search.msn.com."];

const BOT_UA_MARKERS: &[&str] =
    &["googlebot", "bingbot", "google-inspectiontool", "storebot-google"];

const CACHE_TTL: Duration = Duration::from_secs(60 * 60);

pub struct BotVerifier {
    resolver: TokioAsyncResolver,
    cache: Mutex<HashMap<IpAddr, (bool, Instant)>>,
}

impl BotVerifier {
    pub fn new() -> Self {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        BotVerifier {
            resolver,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn ua_claims_bot(ua: &str) -> bool {
        let ua = ua.to_ascii_lowercase();
        BOT_UA_MARKERS.iter().any(|m| ua.contains(m))
    }

    pub async fn is_verified_bot(&self, ip: IpAddr) -> bool {
        if let Some(hit) = self.cache_get(ip) {
            return hit;
        }
        let verified = self.resolve_and_check(ip).await;
        self.cache_put(ip, verified);
        verified
    }

    fn cache_get(&self, ip: IpAddr) -> Option<bool> {
        let map = self.cache.lock().ok()?;
        let (val, at) = map.get(&ip)?;
        if at.elapsed() < CACHE_TTL {
            Some(*val)
        } else {
            None
        }
    }

    fn cache_put(&self, ip: IpAddr, val: bool) {
        if let Ok(mut map) = self.cache.lock() {
            map.insert(ip, (val, Instant::now()));
        }
    }

    async fn resolve_and_check(&self, ip: IpAddr) -> bool {
        let ptr = match self.resolver.reverse_lookup(ip).await {
            Ok(p) => p,
            Err(_) => return false,
        };

        for name in ptr.iter() {
            let host_l = name.to_utf8().to_ascii_lowercase();
            let suffix_ok = ALLOWED_SUFFIXES.iter().any(|s| host_l.ends_with(s));
            if !suffix_ok {
                continue;
            }
            if let Ok(fwd) = self.resolver.lookup_ip(host_l.as_str()).await {
                if fwd.iter().any(|a| a == ip) {
                    return true;
                }
            }
        }
        false
    }
}