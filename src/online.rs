//! Online key-service source (source #2).
//!
//! Sends the disc's `Unit_Key_RO.inf`, MKB, Volume ID, and a few encrypted
//! content samples to a remote key service and receives a Unit Key. autorip's
//! original `OnlineKeyService` lived in the app; it moves here so the online
//! lookup is a first-class published source. The library never makes the
//! request — this crate does, keeping libfreemkv network-free.
//!
//! The service does all derivation server-side and returns a final UK, so this
//! source yields a single [`Key::Unit`] candidate (or none).

use std::time::Duration;

use base64::Engine;
use libfreemkv::{DiscInputs, Key, KeySource, Result};

/// A real MKB is at most a few MB (a UHD MKB ~3.8 MB). Far larger means
/// something is wrong (e.g. the padded MKB_RW region was read); don't ship a
/// giant body — skip the query.
const MAX_MKB_BYTES: usize = 10 * 1024 * 1024;

/// Generous deadline: the body carries the MKB (~5 MB base64) plus samples and
/// the service is often remote on a slow link. A down server still fails fast
/// (connection refused returns immediately).
const KEYSERVICE_TIMEOUT_SECS: u64 = 180;

/// Client for a remote AACS key service. Opaque third party: it is sent the
/// disc's files + samples and returns a Unit Key or nothing.
pub struct OnlineSource {
    base_url: String,
    secret: String,
}

impl OnlineSource {
    /// A source posting to `base_url` with an optional bearer `secret`.
    pub fn new(base_url: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            secret: secret.into(),
        }
    }
}

impl KeySource for OnlineSource {
    fn resolve(&self, inputs: &DiscInputs) -> Result<Vec<Key>> {
        if self.base_url.is_empty() {
            tracing::warn!(phase = "keyservice_query", "no key service URL configured");
            return Ok(Vec::new());
        }
        if inputs.mkb.len() > MAX_MKB_BYTES {
            tracing::warn!(
                phase = "keyservice_query",
                mkb_bytes = inputs.mkb.len(),
                "MKB unexpectedly large ({} MB) — not querying the key service",
                inputs.mkb.len() / 1024 / 1024
            );
            return Ok(Vec::new());
        }

        let url = format!("{}/decode", self.base_url.trim_end_matches('/'));
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

        let mut req = ureq::post(&url).timeout(Duration::from_secs(KEYSERVICE_TIMEOUT_SECS));
        if !self.secret.is_empty() {
            req = req.set("Authorization", &format!("Bearer {}", self.secret));
        }
        tracing::info!(
            phase = "keyservice_query",
            url = %url,
            inf = inputs.unit_key_ro.len(),
            mkb = inputs.mkb.len(),
            has_vid = inputs.volume_id != [0u8; 16],
            units = inputs.samples.len(),
            "querying key service"
        );

        // A source never fails the whole resolve: network / status / parse
        // problems are logged (so the device log shows unreachable vs no-key)
        // and surface as "no candidate", letting the next source try.
        let resp = match req.send_json(body) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, _)) => {
                tracing::warn!(
                    phase = "keyservice_query",
                    status = code,
                    "key service returned no key"
                );
                return Ok(Vec::new());
            }
            Err(e) => {
                tracing::warn!(phase = "keyservice_query", error = %e, "key service unreachable");
                return Ok(Vec::new());
            }
        };
        let json: serde_json::Value = match resp.into_json() {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(phase = "keyservice_query", error = %e, "key service reply unreadable");
                return Ok(Vec::new());
            }
        };
        match json.get("UK").and_then(|u| u.as_str()).and_then(parse_uk) {
            Some(uk) => {
                tracing::info!(phase = "keyservice_query", "key service returned a key");
                // The service resolves a final unit key server-side; hand it in
                // as the terminal level for CPS unit 1 (matching the prior
                // rescan-with-unit-key behavior).
                Ok(vec![Key::Unit(vec![(1, uk)])])
            }
            None => {
                tracing::warn!(
                    phase = "keyservice_query",
                    "key service reply had no usable key"
                );
                Ok(Vec::new())
            }
        }
    }
}

/// Parse a 32-char hex Unit Key into 16 bytes.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uk_roundtrip() {
        assert_eq!(
            parse_uk("1deb13ba851d8fbc01e169dca7d2f258").unwrap(),
            [
                0x1d, 0xeb, 0x13, 0xba, 0x85, 0x1d, 0x8f, 0xbc, 0x01, 0xe1, 0x69, 0xdc, 0xa7, 0xd2,
                0xf2, 0x58
            ]
        );
        assert!(parse_uk("deadbeef").is_none());
        assert!(parse_uk("zz").is_none());
    }

    #[test]
    fn empty_url_yields_no_candidate() {
        let src = OnlineSource::new("", "");
        let inputs = DiscInputs {
            disc_hash: "0xaabb".into(),
            volume_id: [0u8; 16],
            mkb: Vec::new(),
            unit_key_ro: Vec::new(),
            samples: Vec::new(),
        };
        assert!(src.resolve(&inputs).unwrap().is_empty());
    }
}
