use anyhow::{Context, Result};
use ed25519_dalek::{PublicKey, Signature};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine as _;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Assignment {
    pub tenant_id: String,
    pub version: i64,
    pub blob: String, // raw JSON blob contents
}

#[derive(Clone)]
pub struct ConfigServiceClient {
    pub base_url: String,
    pub object_id: String,
    pub pubkey: PublicKey,
    pub assignments: Arc<RwLock<HashMap<String, Assignment>>>,
    pub http: reqwest::Client,
}

impl ConfigServiceClient {
    pub fn new(base_url: String, object_id: String, pubkey: PublicKey) -> Self {
        ConfigServiceClient {
            base_url,
            object_id,
            pubkey,
            assignments: Arc::new(RwLock::new(HashMap::new())),
            http: reqwest::Client::new(),
        }
    }

    #[allow(dead_code)]
    pub fn assignments_handle(&self) -> Arc<RwLock<HashMap<String, Assignment>>> {
        self.assignments.clone()
    }

    /// Long-running poll loop. Not used in tests but kept for runtime.
    /// Long-running poll loop. This updates the library's internal assignment
    /// store. Consumers should call `snapshot_routes` to obtain parsed routes
    /// and merge them into their own runtime config.
    pub async fn poll_loop(self) -> Result<()> {
        let url = format!("{}/configs/{}/assignments", self.base_url, self.object_id);
        loop {
            match self.fetch_and_apply(&url).await {
                Ok(_) => tracing::debug!("assignment poll ok"),
                Err(e) => tracing::warn!(error=%e, "assignment poll failed"),
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    async fn fetch_and_apply(&self, url: &str) -> Result<()> {
        let resp = self.http.get(url).send().await.with_context(|| "fetch assignments")?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("assignments endpoint returned {}", resp.status()));
        }
        let body: serde_json::Value = resp.json().await.with_context(|| "parse assignments json")?;
        // Expect { assignments: [ { tenant_id, version, blob_url, signature_url } ] }
        let arr = body.get("assignments").and_then(|v| v.as_array()).ok_or_else(|| anyhow::anyhow!("missing assignments"))?;
        for a in arr {
            let tenant = a.get("tenant_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            let version = a.get("version").and_then(|v| v.as_i64()).unwrap_or(0);
            let blob_url = a.get("blob_url").and_then(|v| v.as_str()).unwrap_or_default();
            let sig_url = a.get("signature_url").and_then(|v| v.as_str()).unwrap_or_default();

            // download blob
            let blob_bytes = self.http.get(blob_url).send().await?.bytes().await?;
            let sig_bytes = self.http.get(sig_url).send().await?.bytes().await?;

            // signature may be base64 encoded or raw; try base64 decode first, else use raw
            let sig_vec = match BASE64_ENGINE.decode(sig_bytes.as_ref()) {
                Ok(v) => v,
                Err(_) => sig_bytes.to_vec(),
            };

            let signature = Signature::from_bytes(&sig_vec).with_context(|| "parsing signature")?;
            self.pubkey.verify_strict(&blob_bytes, &signature).with_context(|| "verifying signature")?;

            // For simplicity store blob as string (assume utf8 JSON), replace assignment
            let blob_str = String::from_utf8(blob_bytes.to_vec()).unwrap_or_default();
            let assign = Assignment { tenant_id: tenant.clone(), version, blob: blob_str };
            let mut map = self.assignments.write().await;
            map.insert(tenant, assign);
        }
        Ok(())
    }

    /// Public helper to invoke a single fetch+apply cycle. Useful for tests.
    /// Public helper to invoke a single fetch cycle. Useful for tests.
    pub async fn fetch_once(&self, url: &str) -> Result<()> {
        self.fetch_and_apply(url).await
    }

    /// Return a snapshot of the current assignments map (tenant -> Assignment).
    /// Consumers receive the raw assignment blobs and are responsible for
    /// parsing any application-specific payload (such as `routes`). This keeps
    /// the library free of any schema assumptions.
    pub async fn snapshot_assignments(&self) -> HashMap<String, Assignment> {
        self.assignments.read().await.clone()
    }
}

// Minimal unit tests that run without extra dev-dependencies.
#[cfg(test)]
mod tests_integration {
    use super::*;
    use ed25519_dalek::{Keypair, SecretKey, PublicKey, Signer};
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn control_plane_fetch_applies_routes() {
        // simple blob with routes
        let blob_json = r#"{"routes": {"play.test": "127.0.0.1:25565"}}"#;

        // deterministic keypair from seed bytes
        let seed: [u8; 32] = [7u8; 32];
        let secret = SecretKey::from_bytes(&seed).expect("secret");
        let public = PublicKey::from(&secret);
        let mut kp_bytes = [0u8; 64];
        kp_bytes[..32].copy_from_slice(&seed);
        kp_bytes[32..].copy_from_slice(public.as_bytes());
        let kp = Keypair::from_bytes(&kp_bytes).expect("keypair");
        let sig = kp.sign(blob_json.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());

        // start ephemeral TCP HTTP server that serves assignments, blob and signature
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server_task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let blob = blob_json.to_string();
                let sig = sig_b64.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = socket.read(&mut buf).await {
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let path = req.split_whitespace().nth(1).unwrap_or("/");
                        let (status, body) = match path {
                            "/configs/object1/assignments" => (
                                200,
                                serde_json::json!({
                                    "assignments": [
                                        {
                                            "tenant_id": "t1",
                                            "version": 1,
                                            "blob_url": format!("http://{}{}", addr, "/blob.json"),
                                            "signature_url": format!("http://{}{}", addr, "/blob.sig"),
                                        }
                                    ]
                                })
                                .to_string(),
                            ),
                            "/blob.json" => (200, blob.clone()),
                            "/blob.sig" => (200, sig.clone()),
                            _ => (404, "not found".to_string()),
                        };
                        let resp = format!("HTTP/1.1 {} OK\r\nContent-Length: {}\r\n\r\n{}", status, body.len(), body);
                        let _ = socket.write_all(resp.as_bytes()).await;
                    }
                });
            }
        });

        // client
    let cp = ConfigServiceClient::new(format!("http://{}", addr), "test-router".to_string(), kp.public);

    let url = format!("http://{}/configs/object1/assignments", addr);
    cp.fetch_once(&url).await.expect("fetch should succeed");

    let assigns = cp.snapshot_assignments().await;
    let blob = assigns.get("t1").map(|a| a.blob.clone());
    assert_eq!(blob, Some(blob_json.to_string()));

        server_task.abort();
    }
}
