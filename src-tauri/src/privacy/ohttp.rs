use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// OHTTP Key Configuration (from the relay's /.well-known/ohttp-gateway endpoint).
/// Stored in the DB after first fetch; refreshed weekly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OhttpKeyConfig {
    pub key_id: u8,
    /// Raw HPKE public key bytes (P-256 uncompressed point, 65 bytes).
    pub public_key_bytes: Vec<u8>,
    /// IANA KEM ID (0x0010 = DHKEM(P-256, HKDF-SHA256))
    pub kem_id: u16,
    /// IANA KDF ID (0x0001 = HKDF-SHA256)
    pub kdf_id: u16,
    /// IANA AEAD ID (0x0001 = AES-128-GCM)
    pub aead_id: u16,
}

impl OhttpKeyConfig {
    /// Parse from RFC 9458 binary Key Configuration format.
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() < 8 {
            bail!("key config too short: {} bytes", raw.len());
        }
        let key_id = raw[0];
        let kem_id = u16::from_be_bytes([raw[1], raw[2]]);
        let pk_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        if raw.len() < 5 + pk_len + 2 {
            bail!("key config truncated at public key");
        }
        let public_key_bytes = raw[5..5 + pk_len].to_vec();
        let kdf_id = u16::from_be_bytes([raw[5 + pk_len], raw[5 + pk_len + 1]]);
        let aead_id = if raw.len() >= 5 + pk_len + 4 {
            u16::from_be_bytes([raw[5 + pk_len + 2], raw[5 + pk_len + 3]])
        } else {
            0x0001
        };

        Ok(Self {
            key_id,
            public_key_bytes,
            kem_id,
            kdf_id,
            aead_id,
        })
    }
}

/// A pending OHTTP request with its decapsulation context.
pub struct OhttpRequest {
    /// Encapsulated request bytes ready to POST to the relay.
    pub encapsulated: Vec<u8>,
    /// HPKE context used to decapsulate the response.  Consumed on first use.
    response_context: Vec<u8>,
    key_config_id: u8,
}

/// Encapsulate an HTTP GET request for OHTTP relay.
///
/// Returns an OhttpRequest that can be POSTed to the relay at the
/// "application/ohttp-req" content type.
///
/// `url_path`: e.g. "/path?query=value" (scheme + authority are in `target_authority`)
/// `target_authority`: e.g. "urlhaus.abuse.ch:443"
pub fn encapsulate_get(
    config: &OhttpKeyConfig,
    target_scheme: &str,
    target_authority: &str,
    url_path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<OhttpRequest> {
    let bhttp = build_bhttp_request(
        "GET",
        target_scheme,
        target_authority,
        url_path,
        extra_headers,
        &[],
    )
    .context("build bhttp")?;

    let (enc, ct, response_context) = hpke_seal(config, &bhttp).context("hpke seal")?;

    let mut encapsulated = Vec::new();
    encapsulated.push(config.key_id);
    encapsulated.extend_from_slice(&config.kem_id.to_be_bytes());
    encapsulated.extend_from_slice(&config.kdf_id.to_be_bytes());
    encapsulated.extend_from_slice(&config.aead_id.to_be_bytes());
    encapsulated.extend_from_slice(&enc);
    encapsulated.extend_from_slice(&ct);

    Ok(OhttpRequest {
        encapsulated,
        response_context,
        key_config_id: config.key_id,
    })
}

/// Decapsulate an OHTTP response (the encrypted blob returned by the relay).
/// Returns the plaintext HTTP response body as bytes.
pub fn decapsulate_response(req: &OhttpRequest, response_bytes: &[u8]) -> Result<Vec<u8>> {
    hpke_open_response(&req.response_context, response_bytes).context("hpke open response")
}

//
// Suite: DHKEM(P-256, HKDF-SHA256)  KEM=0x0010
//        HKDF-SHA256                KDF=0x0001
//        AES-128-GCM                AEAD=0x0001
//
// The response_context stored in OhttpRequest is:
//   enc (65 bytes) || exporter_secret (32 bytes) = 97 bytes total.
// Both halves are needed to derive the response decryption key per §4.2 of RFC 9458.

const P256_PK_LEN: usize = 65; // uncompressed SEC1

/// RFC 9180 §4 — LabeledExtract using a fixed suite_id.
/// Returns the HKDF PRK bytes directly (32 bytes for SHA-256).
fn labeled_extract(suite_id: &[u8], salt: Option<&[u8]>, label: &[u8], ikm: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let labeled_ikm: Vec<u8> = b"HPKE-v1"
        .iter()
        .chain(suite_id)
        .chain(label)
        .chain(ikm)
        .copied()
        .collect();
    let (prk, _) = Hkdf::<Sha256>::extract(salt, &labeled_ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// RFC 9180 §4 — LabeledExpand using a fixed suite_id.
fn labeled_expand(
    prk: &[u8; 32],
    suite_id: &[u8],
    label: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<()> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let len = out.len() as u16;
    let labeled_info: Vec<u8> = len
        .to_be_bytes()
        .iter()
        .chain(b"HPKE-v1")
        .chain(suite_id)
        .chain(label)
        .chain(info)
        .copied()
        .collect();
    let hk = Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| anyhow::anyhow!("labeled_expand: invalid PRK length"))?;
    hk.expand(&labeled_info, out)
        .map_err(|_| anyhow::anyhow!("labeled_expand: output too large"))?;
    Ok(())
}

/// RFC 9180 §7.1 — DHKEM(P-256, HKDF-SHA256) Encap.
///
/// Returns (enc, shared_secret, exporter_secret) where:
///   enc              = ephemeral public key (65 bytes, uncompressed SEC1)
///   shared_secret    = 32-byte KEM shared secret
///   exporter_secret  = 32-byte HPKE exporter secret (from KeySchedule)
fn hpke_seal(config: &OhttpKeyConfig, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    use aes_gcm::{
        Aes128Gcm, KeyInit,
        aead::{Aead, Payload},
    };
    use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret};

    if config.kem_id != 0x0010 {
        bail!("unsupported KEM 0x{:04x}", config.kem_id);
    }
    if config.kdf_id != 0x0001 {
        bail!("unsupported KDF 0x{:04x}", config.kdf_id);
    }
    if config.aead_id != 0x0001 {
        bail!("unsupported AEAD 0x{:04x}", config.aead_id);
    }

    // RFC 9180 §7.1: suite_id for the KEM layer
    let kem_suite_id: &[u8] = b"KEM\x00\x10";
    // RFC 9180 §5: suite_id for the full HPKE ciphersuite
    let hpke_suite_id: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x01";

    // Parse recipient public key
    let recipient_pk = PublicKey::from_sec1_bytes(&config.public_key_bytes)
        .map_err(|e| anyhow::anyhow!("invalid recipient public key: {e}"))?;

    // Generate ephemeral key pair
    let eph_sk = EphemeralSecret::random(&mut rand::rngs::OsRng);
    let eph_pk = EncodedPoint::from(eph_sk.public_key());
    let enc: Vec<u8> = eph_pk.as_bytes().to_vec(); // 65 bytes
    assert_eq!(enc.len(), P256_PK_LEN);

    // DH shared secret
    let dh_output = eph_sk.diffie_hellman(&recipient_pk);
    let dh_bytes: &[u8] = dh_output.raw_secret_bytes().as_slice();

    // kem_context = enc || pkR (RFC 9180 §4.1)
    let pkr_bytes = EncodedPoint::from(recipient_pk).as_bytes().to_vec();
    let kem_context: Vec<u8> = enc.iter().chain(pkr_bytes.iter()).copied().collect();

    // ExtractAndExpand → shared_secret (32 bytes)
    let prk_kem = labeled_extract(kem_suite_id, None, b"shared_secret", dh_bytes);
    let mut shared_secret = [0u8; 32];
    labeled_expand(
        &prk_kem,
        kem_suite_id,
        b"shared_secret",
        &kem_context,
        &mut shared_secret,
    )?;

    // KeySchedule — base mode (mode = 0, empty psk / psk_id / info)
    let psk_id_hash = labeled_extract(hpke_suite_id, Some(b""), b"psk_id_hash", b"");
    let info_hash = labeled_extract(hpke_suite_id, Some(b""), b"info_hash", b"");
    let ks_context: Vec<u8> = std::iter::once(0u8) // mode_base
        .chain(psk_id_hash)
        .chain(info_hash)
        .collect();

    // secret = LabeledExtract(shared_secret, "secret", psk="")
    let secret_prk = labeled_extract(hpke_suite_id, Some(&shared_secret), b"secret", b"");

    let mut key_bytes = [0u8; 16]; // Nk = 16 for AES-128-GCM
    let mut nonce_bytes = [0u8; 12]; // Nn = 12
    let mut exp_secret = [0u8; 32]; // Nh = 32
    labeled_expand(
        &secret_prk,
        hpke_suite_id,
        b"key",
        &ks_context,
        &mut key_bytes,
    )?;
    labeled_expand(
        &secret_prk,
        hpke_suite_id,
        b"base_nonce",
        &ks_context,
        &mut nonce_bytes,
    )?;
    labeled_expand(
        &secret_prk,
        hpke_suite_id,
        b"exp",
        &ks_context,
        &mut exp_secret,
    )?;

    // RFC 9458 §3.3: AAD = request header bytes
    let mut aad = vec![config.key_id];
    aad.extend_from_slice(&config.kem_id.to_be_bytes());
    aad.extend_from_slice(&config.kdf_id.to_be_bytes());
    aad.extend_from_slice(&config.aead_id.to_be_bytes());

    let cipher = Aes128Gcm::new_from_slice(&key_bytes).context("aes128gcm init")?;
    let ct = cipher
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("aes-gcm encrypt: {e}"))?;

    // response_context = enc || exp_secret (97 bytes) so hpke_open_response can
    // derive the response key per RFC 9458 §4.2 (salt = enc || response_nonce).
    let response_context: Vec<u8> = enc.iter().chain(exp_secret.iter()).copied().collect();
    Ok((enc, ct, response_context))
}

/// RFC 9458 §4.2 — Decapsulate an OHTTP response.
///
/// `response_context` is the 97-byte blob stored in OhttpRequest:
///   enc (65 bytes) || exporter_secret (32 bytes).
///
/// `response_bytes` from the relay:
///   response_nonce (16 bytes) || AEAD ciphertext.
fn hpke_open_response(response_context: &[u8], response_bytes: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes128Gcm, KeyInit,
        aead::{Aead, Payload},
    };
    use hkdf::Hkdf;
    use sha2::Sha256;

    // Unpack response_context = enc || exp_secret
    if response_context.len() != P256_PK_LEN + 32 {
        bail!(
            "response_context wrong length: {} (expected {})",
            response_context.len(),
            P256_PK_LEN + 32
        );
    }
    let enc = &response_context[..P256_PK_LEN];
    let exp_secret = &response_context[P256_PK_LEN..];

    // max(Nn=12, Nk=16) = 16 bytes for the response nonce
    const RESPONSE_NONCE_LEN: usize = 16;
    if response_bytes.len() < RESPONSE_NONCE_LEN {
        bail!("OHTTP response too short: {} bytes", response_bytes.len());
    }
    let response_nonce = &response_bytes[..RESPONSE_NONCE_LEN];
    let ct = &response_bytes[RESPONSE_NONCE_LEN..];

    // RFC 9458 §4.2:
    //   secret = HPKE.Export("message/bhttp response", Nk=16)
    //   salt   = enc || response_nonce
    //   prk    = Extract(salt, secret)
    //   aead_key   = Expand(prk, "key",   Nk=16)
    //   aead_nonce = Expand(prk, "nonce", Nn=12)

    // Derive the HPKE export value (RFC 9180 §5.3).
    // The exporter_secret stored above IS the `exp` value from KeySchedule,
    // which for Export(L, context) is used as:
    //   Expand(exporter_secret, concat("sec", context), L)
    let hpke_suite_id: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x01";
    let export_label = b"message/bhttp response";
    let export_len: u16 = 16;
    let labeled_info: Vec<u8> = export_len
        .to_be_bytes()
        .iter()
        .chain(b"HPKE-v1")
        .chain(hpke_suite_id)
        .chain(b"sec")
        .chain(export_label)
        .copied()
        .collect();
    let hk_exp = Hkdf::<Sha256>::from_prk(exp_secret)
        .map_err(|_| anyhow::anyhow!("invalid exporter_secret length"))?;
    let mut secret = [0u8; 16];
    hk_exp
        .expand(&labeled_info, &mut secret)
        .map_err(|_| anyhow::anyhow!("HPKE export expand failed"))?;

    // salt = enc || response_nonce
    let salt: Vec<u8> = enc.iter().chain(response_nonce).copied().collect();
    let (prk, _) = Hkdf::<Sha256>::extract(Some(&salt), &secret);

    let mut aead_key = [0u8; 16];
    let mut aead_nonce = [0u8; 12];
    Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|_| anyhow::anyhow!("response PRK invalid"))?
        .expand(b"key", &mut aead_key)
        .map_err(|_| anyhow::anyhow!("response key expand failed"))?;
    Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|_| anyhow::anyhow!("response PRK invalid"))?
        .expand(b"nonce", &mut aead_nonce)
        .map_err(|_| anyhow::anyhow!("response nonce expand failed"))?;

    let cipher = Aes128Gcm::new_from_slice(&aead_key).context("aes128gcm init")?;
    cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(&aead_nonce),
            Payload { msg: ct, aad: b"" },
        )
        .map_err(|e| anyhow::anyhow!("aes-gcm decrypt: {e}"))
}

fn write_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 64 {
        buf.push(n as u8);
    } else if n < 16_384 {
        buf.extend_from_slice(&((n as u16 | 0x4000).to_be_bytes()));
    } else if n < 1_073_741_824 {
        buf.extend_from_slice(&((n as u32 | 0x8000_0000).to_be_bytes()));
    } else {
        buf.extend_from_slice(&((n | 0xC000_0000_0000_0000).to_be_bytes()));
    }
}

fn write_str(buf: &mut Vec<u8>, s: &str) {
    write_varint(buf, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

fn build_bhttp_request(
    method: &str,
    scheme: &str,
    authority: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    write_varint(&mut buf, 0x00);

    write_str(&mut buf, method);
    write_str(&mut buf, scheme);
    write_str(&mut buf, authority);
    write_str(&mut buf, path);

    let mut hdr_buf = Vec::new();
    for (k, v) in headers {
        write_str(&mut hdr_buf, k);
        write_str(&mut hdr_buf, v);
    }
    write_varint(&mut buf, hdr_buf.len() as u64);
    buf.extend_from_slice(&hdr_buf);

    write_varint(&mut buf, body.len() as u64);
    buf.extend_from_slice(body);

    write_varint(&mut buf, 0);

    Ok(buf)
}

/// Known OHTTP relay endpoints supported by Diatom.
pub const OHTTP_RELAYS: &[&str] = &["https://ohttp.fastly.com/", "https://ohttp.brave.com/"];

/// Fetch the OHTTP key configuration from a relay.
/// Endpoint: GET <relay>/.well-known/ohttp-gateway
pub async fn fetch_key_config(client: &reqwest::Client, relay: &str) -> Result<OhttpKeyConfig> {
    let url = format!("{}/.well-known/ohttp-gateway", relay.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .header("Accept", "application/ohttp-keys")
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .with_context(|| format!("fetch key config from {relay}"))?
        .error_for_status()
        .context("key config status")?;
    let bytes = resp.bytes().await.context("key config body")?;
    OhttpKeyConfig::from_bytes(&bytes)
}

/// Send an OHTTP request to a relay and decapsulate the response.
pub async fn ohttp_fetch(
    client: &reqwest::Client,
    relay: &str,
    req: OhttpRequest,
) -> Result<Vec<u8>> {
    let relay_url = relay.trim_end_matches('/').to_owned() + "/relay";
    let resp = client
        .post(&relay_url)
        .header("Content-Type", "application/ohttp-req")
        .body(req.encapsulated.clone())
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .with_context(|| format!("ohttp relay POST to {relay_url}"))?
        .error_for_status()
        .context("ohttp relay response status")?;

    let resp_bytes = resp.bytes().await.context("ohttp relay body")?;
    decapsulate_response(&req, &resp_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bhttp_request_roundtrip_structure() {
        let bhttp = build_bhttp_request(
            "GET",
            "https",
            "example.com:443",
            "/test",
            &[("Accept", "text/plain")],
            &[],
        )
        .unwrap();
        assert_eq!(bhttp[0], 0x00);
        assert!(bhttp.len() > 10);
    }

    #[test]
    fn key_config_parse_too_short() {
        let result = OhttpKeyConfig::from_bytes(&[0x01, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn varint_encoding_single_byte() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 42);
        assert_eq!(buf, &[42u8]);
    }

    #[test]
    fn varint_encoding_two_byte() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 64);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf[0] & 0xC0, 0x40); // two-byte prefix
    }
}
