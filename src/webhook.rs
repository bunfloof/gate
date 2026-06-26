use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

const WEBHOOK_URL: &str = "https://discord.com/api/webhooks/1234567890123456789/aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKlMnOpQrStUvWxYz12";

#[derive(Deserialize, Default)]
struct Geo {
    #[serde(default)]
    country_code: String,
    #[serde(default)]
    region: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    isp: String,
    #[serde(default)]
    isp_asn: i64,
}

fn detect_os(ua: &str) -> &'static str {
    let u = ua.to_ascii_lowercase();
    if u.contains("windows nt 10") {
        "Windows 10/11"
    } else if u.contains("windows nt 6.3") {
        "Windows 8.1"
    } else if u.contains("windows nt 6.1") {
        "Windows 7"
    } else if u.contains("windows") {
        "Windows"
    } else if u.contains("iphone") || u.contains("ipad") || u.contains("ipod") {
        "iOS"
    } else if u.contains("android") {
        "Android"
    } else if u.contains("cros") {
        "ChromeOS"
    } else if u.contains("mac os x") || u.contains("macintosh") {
        "macOS"
    } else if u.contains("linux") {
        "Linux"
    } else {
        "Unknown"
    }
}

async fn lookup(client: &reqwest::Client, ip: &str) -> Option<Geo> {
    let url = format!("https://web-api.nordvpn.com/v1/ips/lookup/{ip}");
    let resp = client
        .get(url)
        .timeout(Duration::from_secs(8))
        .send()
        .await
        .ok()?;
    resp.json::<Geo>().await.ok()
}

fn cap(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

pub fn notify(
    client: reqwest::Client,
    verdict: &'static str,
    score: i32,
    reasons: String,
    ip: Option<String>,
    ua: String,
) {
    actix_web::rt::spawn(async move {
        let geo = match &ip {
            Some(ip) => lookup(&client, ip).await.unwrap_or_default(),
            None => Geo::default(),
        };

        let cc = if geo.country_code.is_empty() {
            "??".to_string()
        } else {
            geo.country_code.clone()
        };
        let flag = if geo.country_code.is_empty() {
            ":flag_white:".to_string()
        } else {
            format!(":flag_{}:", geo.country_code.to_ascii_lowercase())
        };
        let city = if geo.city.is_empty() {
            "Unknown".to_string()
        } else {
            geo.city
        };
        let region = if geo.region.is_empty() {
            "Unknown".to_string()
        } else {
            geo.region
        };
        let isp = if geo.isp.is_empty() {
            "Unknown".to_string()
        } else {
            geo.isp
        };
        let ip_s = ip.unwrap_or_else(|| "Unknown".to_string());
        let os = detect_os(&ua);

        let now = chrono::Utc::now().with_timezone(&chrono_tz::America::Los_Angeles);
        let time = now.format("%Y-%m-%d %I:%M:%S %p %Z").to_string();

        let reasons_part = if reasons.is_empty() {
            String::new()
        } else {
            format!(" reasons=[{reasons}]")
        };

        let line = format!(
            "[{time}] {flag} {ip_s} | {city}, {region}, {cc} | {isp} (AS{asn}) | {os} | {verdict} score={score}{reasons_part} | UA: {ua}",
            asn = geo.isp_asn
        );

        let payload = json!({ "content": cap(&line, 2000) });
        let _ = client.post(WEBHOOK_URL).json(&payload).send().await;
    });
}