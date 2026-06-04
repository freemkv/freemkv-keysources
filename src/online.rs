//! Online key-service source.

use std::time::Duration;

use base64::Engine;
use libfreemkv::{DiscInputs, Key, KeySource, Result};

const MAX_MKB_BYTES: usize = 10 * 1024 * 1024;
const TIMEOUT_SECS: u64 = 180;

pub struct OnlineSource {
    base_url: String,
    secret: String,
}

impl OnlineSource {
    pub fn new(base_url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            secret: secret.into(),
        }
    }
}

impl KeySource for OnlineSource {
    fn resolve(&self, inputs: &DiscInputs) -> Result<Vec<Key>> {
        if self.base_url.is_empty() || inputs.mkb.len() > MAX_MKB_BYTES {
            return Ok(Vec::new());
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut body = serde_json::json!({
            "inf_b64": b64.encode(&inputs.unit_key_ro),
            "mkb_b64": b64.encode(&inputs.mkb),
        });
        if inputs.volume_id != [0u8; 16] {
            body["vid_b64"] = serde_json::Value::String(b64.encode(inputs.volume_id));
        }
        if !inputs.samples.is_empty() {
            body["units_b64"] = serde_json::Value::Array(
                inputs
                    .samples
                    .iter()
                    .map(|u| serde_json::Value::String(b64.encode(u)))
                    .collect(),
            );
        }
        let mut req = ureq::post(&self.base_url).timeout(Duration::from_secs(TIMEOUT_SECS));
        if !self.secret.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.secret));
        }
        let resp = match req.send_json(body) {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };
        let json: serde_json::Value = match resp.into_json() {
            Ok(j) => j,
            Err(_) => return Ok(Vec::new()),
        };
        match json.get("UK").and_then(|u| u.as_str()).and_then(parse_uk) {
            Some(uk) => Ok(vec![Key::Unit(vec![(1, uk)])]),
            None => Ok(Vec::new()),
        }
    }

    fn needs_samples(&self) -> bool {
        true
    }
}

fn parse_uk(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
