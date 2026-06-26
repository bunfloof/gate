use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Diag {
    pub enabled: bool,
    path: String,
    file: Mutex<Option<File>>,
}

impl Diag {
    pub fn new(enabled: bool, path: &str) -> Self {
        Diag {
            enabled,
            path: path.to_string(),
            file: Mutex::new(None),
        }
    }

    fn now_ms() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }

    pub fn log(&self, kind: &str, mut obj: Value) {
        if !self.enabled {
            return;
        }
        if let Value::Object(ref mut m) = obj {
            m.insert("ts_ms".into(), Value::from(Self::now_ms() as u64));
            m.insert("kind".into(), Value::from(kind));
        }
        let line = obj.to_string();
        if let Ok(mut guard) = self.file.lock() {
            if guard.is_none() {
                *guard = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                    .ok();
            }
            if let Some(f) = guard.as_mut() {
                let _ = writeln!(f, "{line}");
            }
        }
        log::info!("[DIAG:{kind}] {line}");
    }
}