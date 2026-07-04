mod botcheck;
mod diag;
mod gate;
mod token;
mod webhook;

use actix_files::NamedFile;
use actix_web::http::header::{self, HeaderValue};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use botcheck::BotVerifier;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use percent_encoding::percent_decode_str;

const PORT: u16 = 25720;

struct AppState {
    secret: Vec<u8>,
    verifier: BotVerifier,
    public_dir: PathBuf,
    diag: diag::Diag,
    http: reqwest::Client,
}

fn headers_json(req: &HttpRequest) -> Value {
    let mut m = serde_json::Map::new();
    for (k, v) in req.headers().iter() {
        let key = k.as_str().to_string();
        let val = v.to_str().unwrap_or("<non-utf8>").to_string();
        match m.get_mut(&key) {
            Some(Value::Array(arr)) => arr.push(Value::from(val)),
            Some(existing) => {
                let prev = existing.clone();
                *existing = Value::Array(vec![prev, Value::from(val)]);
            }
            None => {
                m.insert(key, Value::from(val));
            }
        }
    }
    Value::Object(m)
}

fn ip_json(req: &HttpRequest) -> Value {
    let h = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    json!({
        "peer_addr": req.peer_addr().map(|s| s.ip().to_string()),
        "cf_connecting_ip": h("cf-connecting-ip"),
        "true_client_ip": h("true-client-ip"),
        "x_forwarded_for": h("x-forwarded-for"),
        "resolved": peer_ip(req).map(|i| i.to_string()),
    })
}

fn load_secret() -> Vec<u8> {
    if let Ok(s) = std::env::var("GATE_SECRET") {
        if !s.is_empty() {
            return s.into_bytes();
        }
    }
    let path = Path::new(".gate_secret");
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() >= 32 {
            return bytes;
        }
    }
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    if let Err(e) = std::fs::write(path, buf) {
        log::warn!("could not persist .gate_secret ({e}); tokens will not survive restart");
    }
    buf.to_vec()
}

fn has_valid_token(req: &HttpRequest, secret: &[u8]) -> bool {
    req.cookie("__gate")
        .map(|c| token::verify(secret, c.value()))
        .unwrap_or(false)
}

fn peer_ip(req: &HttpRequest) -> Option<IpAddr> {
    for header in ["cf-connecting-ip", "true-client-ip"] {
        if let Some(v) = req.headers().get(header) {
            if let Ok(s) = v.to_str() {
                if let Ok(ip) = s.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    if let Some(v) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = v.to_str() {
            if let Some(first) = s.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    req.peer_addr().map(|s| s.ip())
}

async fn gate_ws(
    req: HttpRequest,
    body: web::Payload,
    data: web::Data<AppState>,
) -> actix_web::Result<impl Responder> {
    let (response, mut session, mut stream) = actix_ws::handle(&req, body)?;
    let secret = data.secret.clone();
    let data2 = data.clone();
    let http = data.http.clone();
    let resolved_ip = peer_ip(&req).map(|i| i.to_string());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let conn = json!({ "ip": ip_json(&req), "ua": ua });

    actix_web::rt::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                actix_ws::Message::Text(text) => {
                    let reply = decide(&text, &secret, &data2.diag, &conn, &http, &resolved_ip, &ua);
                    let _ = session.text(reply).await;
                    let _ = session.close(None).await;
                    break;
                }
                actix_ws::Message::Ping(p) => {
                    let _ = session.pong(&p).await;
                }
                actix_ws::Message::Close(_) => break,
                _ => {}
            }
        }
    });

    Ok(response)
}

fn decide(
    text: &str,
    secret: &[u8],
    diag: &diag::Diag,
    conn: &Value,
    http: &reqwest::Client,
    ip: &Option<String>,
    ua: &str,
) -> String {
    if diag.enabled {
        let report_val: Value = serde_json::from_str(text).unwrap_or(Value::Null);
        diag.log(
            "client",
            json!({ "conn": conn, "report": report_val, "raw_len": text.len() }),
        );
    }

    let report: gate::ClientReport = match serde_json::from_str(text) {
        Ok(r) => r,
        Err(_) => return r#"{"ok":false}"#.to_string(),
    };
    let (s, reasons) = gate::score(&report);
    let deny = s >= gate::DENY_THRESHOLD;
    let verdict = if deny { "DENY" } else { "PASS" };
    webhook::notify(http.clone(), verdict, s, reasons.join(","), ip.clone(), ua.to_string());

    if deny {
        log::info!("DENY score={s} reasons={reasons:?} renderer={:?}", report.renderer);
        r#"{"ok":false}"#.to_string()
    } else {
        log::info!("PASS score={s} renderer={:?}", report.renderer);
        let tok = token::issue(secret);
        format!(r#"{{"ok":true,"token":"{tok}"}}"#)
    }
}

fn serve_gate_shell(diag: bool) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header(("X-Robots-Tag", "noindex"))
        .body(gate::gate_shell(diag))
}

fn resolve_file(public_dir: &Path, raw_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode_str(raw_path).decode_utf8().ok()?;
    let trimmed = decoded.trim_start_matches('/');
    let rel = if trimmed.is_empty() { "index.html" } else { trimmed };

    if rel.split('/').any(|seg| seg == "..") {
        return None;
    }

    let base = public_dir.join(rel);
    let candidates = [
        base.clone(),
        base.with_extension("html"),
        base.join("index.html"),
    ];

    for cand in candidates {
        if let Ok(canon) = cand.canonicalize() {
            if canon.starts_with(public_dir) && canon.is_file() {
                return Some(canon);
            }
        }
    }
    None
}

async fn catch_all(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    if has_valid_token(&req, &data.secret) {
        return serve_real(&req, &data);
    }

    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if BotVerifier::ua_claims_bot(ua) {
        if let Some(ip) = peer_ip(&req) {
            if data.verifier.is_verified_bot(ip).await {
                return serve_real(&req, &data);
            }
        }
    }

    if data.diag.enabled {
        data.diag.log(
            "http",
            json!({ "method": req.method().as_str(), "path": req.path(),
                    "version": format!("{:?}", req.version()),
                    "ip": ip_json(&req), "headers": headers_json(&req) }),
        );
    }
    serve_gate_shell(data.diag.enabled)
}

fn serve_real(req: &HttpRequest, data: &AppState) -> HttpResponse {
    match resolve_file(&data.public_dir, req.path()) {
        Some(file) => match NamedFile::open(file) {
            Ok(nf) => {
                let mut resp = nf
                    .use_last_modified(true)
                    .prefer_utf8(true)
                    .into_response(req);
                resp.headers_mut().insert(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("private, max-age=0, must-revalidate"),
                );
                resp
            }
            Err(_) => HttpResponse::NotFound().body("404 Not Found"),
        },
        None => HttpResponse::NotFound().body("404 Not Found"),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let public_dir = std::env::var("PUBLIC_DIR").unwrap_or_else(|_| "public_html".to_string());
    let public_dir = PathBuf::from(public_dir)
        .canonicalize()
        .expect("PUBLIC_DIR must exist (default ./public_html)");

    let diag_on = std::env::var("DIAG")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let diag_path = std::env::var("DIAG_FILE").unwrap_or_else(|_| "diag.jsonl".to_string());
    if diag_on {
        log::warn!("DIAGNOSTIC MODE ON: verbose probe + logging to {diag_path}");
    }

    let state = web::Data::new(AppState {
        secret: load_secret(),
        verifier: BotVerifier::new(),
        public_dir: public_dir.clone(),
        diag: diag::Diag::new(diag_on, &diag_path),
        http: reqwest::Client::new(),
    });

    log::info!("gate listening on http://0.0.0.0:{PORT}  serving {public_dir:?}");

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/__gate_ws", web::get().to(gate_ws))
            .default_service(web::route().to(catch_all))
    })
    .bind(("0.0.0.0", PORT))?
    .run()
    .await
}