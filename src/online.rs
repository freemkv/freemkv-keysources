//! Online key-service source.

use std::time::Duration;

use base64::Engine;
use libfreemkv::{DiscInputs, Key, KeySource};

const MAX_MKB_BYTES: usize = 10 * 1024 * 1024;
const TIMEOUT_SECS: u64 = 180;

pub struct OnlineSource {
    base_url: String,
    secret: String,
    /// The key service pre-validates server-side and returns a single UK, so it
    /// is asked **at most once** — this flips true after the first `next_key`,
    /// and every later ask returns `None` without re-hitting the network.
    asked: bool,
    /// Set when the round-trip itself failed (network down, bad response) — as
    /// opposed to the service simply having no key. Lets the caller report
    /// "key service unreachable" distinctly from "no key for this disc".
    errored: bool,
}

impl OnlineSource {
    pub fn new(base_url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            secret: secret.into(),
            asked: false,
            errored: false,
        }
    }

    /// The single server-resolved UK for this disc, or `None`. Runs exactly the
    /// one network round-trip; `next_key` gates it to one call per session.
    fn query(&mut self, inputs: &DiscInputs) -> Option<Key> {
        if self.base_url.is_empty() || inputs.mkb.len() > MAX_MKB_BYTES {
            return None;
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
            Err(_) => {
                self.errored = true;
                return None;
            }
        };
        let json: serde_json::Value = match resp.into_json() {
            Ok(j) => j,
            Err(_) => {
                self.errored = true;
                return None;
            }
        };
        json.get("UK")
            .and_then(|u| u.as_str())
            .and_then(parse_uk)
            .map(|uk| Key::Unit(vec![(1, uk)]))
    }
}

impl KeySource for OnlineSource {
    fn next_key(&mut self, inputs: &DiscInputs) -> Option<Key> {
        // One shot: the service pre-validates and returns a single UK, so a
        // second ask has nothing new to offer — don't re-hit the network.
        if self.asked {
            return None;
        }
        self.asked = true;
        self.query(inputs)
    }

    fn needs_samples(&self) -> bool {
        true
    }

    fn errored(&self) -> bool {
        self.errored
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
