use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

pub const TOKEN_TTL_SECS: u64 = 90 * 24 * 60 * 60;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn issue(secret: &[u8]) -> String {
    let ts = now_secs();
    let ts_hex = format!("{:x}", ts);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(ts_hex.as_bytes());
    let sig = mac.finalize().into_bytes();
    format!("{}.{}", ts_hex, hex::encode(sig))
}

pub fn verify(secret: &[u8], token: &str) -> bool {
    let mut parts = token.splitn(2, '.');
    let (ts_hex, sig_hex) = match (parts.next(), parts.next()) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };

    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(ts_hex.as_bytes());
    if mac.verify_slice(&sig_bytes).is_err() {
        return false;
    }

    let ts = match u64::from_str_radix(ts_hex, 16) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = now_secs();
    if ts > now.saturating_add(300) {
        return false;
    }
    now.saturating_sub(ts) <= TOKEN_TTL_SECS
}