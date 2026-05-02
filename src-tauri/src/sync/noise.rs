use anyhow::{Context, Result, bail};
use snow::{Builder, HandshakeState, TransportState};
use std::io::{Read, Write};
use zeroize::Zeroizing;

const PATTERN: &str = "Noise_XX_25519_AESGCM_BLAKE2b";

/// Maximum Noise message size (snow's hard limit is 65535 bytes).
const MAX_MSG: usize = 65_000;

/// A 32-byte Curve25519 static keypair stored as raw bytes.
#[derive(Clone)]
pub struct NoiseKeypair {
    pub public: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

impl NoiseKeypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let builder = Builder::new(PATTERN.parse().expect("valid pattern"));
        let kp = builder.generate_keypair().expect("keypair generation");
        let mut public = [0u8; 32];
        let mut secret = [0u8; 32];
        public.copy_from_slice(kp.public.as_slice());
        secret.copy_from_slice(kp.private.as_slice());
        Self {
            public,
            secret: Zeroizing::new(secret),
        }
    }

    /// Load from raw bytes (e.g., from the encrypted Diatom keychain store).
    pub fn from_bytes(public: [u8; 32], secret: [u8; 32]) -> Self {
        Self {
            public,
            secret: Zeroizing::new(secret),
        }
    }

    /// Human-readable fingerprint for TOFU UI display.
    /// Format: first 20 bytes of the public key shown as 5 groups of 4 hex chars.
    pub fn fingerprint(&self) -> String {
        self.public
            .chunks(4)
            .take(5)
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Handshake state machine — wraps snow's HandshakeState.
pub struct NoiseHandshake {
    state: HandshakeState,
    is_initiator: bool,
}

impl NoiseHandshake {
    pub fn new_initiator(local_kp: &NoiseKeypair) -> Result<Self> {
        let state = Builder::new(PATTERN.parse()?)
            .local_private_key(local_kp.secret.as_ref())
            .build_initiator()
            .context("build initiator")?;
        Ok(Self {
            state,
            is_initiator: true,
        })
    }

    pub fn new_responder(local_kp: &NoiseKeypair) -> Result<Self> {
        let state = Builder::new(PATTERN.parse()?)
            .local_private_key(local_kp.secret.as_ref())
            .build_responder()
            .context("build responder")?;
        Ok(Self {
            state,
            is_initiator: false,
        })
    }

    /// Write the next handshake message into `buf`.  Returns the number of
    /// bytes written.  Caller is responsible for framing (length prefix etc.).
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_MSG];
        let n = self
            .state
            .write_message(payload, &mut buf)
            .context("handshake write")?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Feed the peer's handshake message.  Returns any payload embedded by
    /// the peer (typically empty in Noise_XX).
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_MSG];
        let n = self
            .state
            .read_message(msg, &mut buf)
            .context("handshake read")?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn is_handshake_done(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Transition to transport mode.  Fails if handshake is not complete.
    pub fn into_transport(self) -> Result<NoiseSession> {
        if !self.state.is_handshake_finished() {
            bail!("handshake not complete");
        }
        let remote_pub = self
            .state
            .get_remote_static()
            .context("remote static not available after XX")?;
        let mut remote_public = [0u8; 32];
        remote_public.copy_from_slice(remote_pub);
        let transport = self.state.into_transport_mode().context("into transport")?;
        Ok(NoiseSession {
            transport,
            remote_public,
        })
    }
}

/// Encrypted transport session after a successful Noise handshake.
pub struct NoiseSession {
    transport: TransportState,
    /// Peer's static public key — used for TOFU fingerprint checking in the UI.
    pub remote_public: [u8; 32],
}

impl NoiseSession {
    /// Encrypt `plaintext` → returns ciphertext (no framing, caller frames).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 16 + 2]; // AESGCM tag + overhead
        let n = self
            .transport
            .write_message(plaintext, &mut buf)
            .context("transport encrypt")?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Decrypt `ciphertext` → returns plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(ciphertext, &mut buf)
            .context("transport decrypt")?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Human-readable peer fingerprint for TOFU display.
    pub fn peer_fingerprint(&self) -> String {
        self.remote_public
            .chunks(4)
            .take(5)
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Write one encrypted frame to a sync-Write.
    pub fn write_frame<W: Write>(&mut self, writer: &mut W, plaintext: &[u8]) -> Result<()> {
        let ct = self.encrypt(plaintext)?;
        let len = ct.len() as u32;
        writer
            .write_all(&len.to_le_bytes())
            .context("frame len write")?;
        writer.write_all(&ct).context("frame body write")?;
        Ok(())
    }

    /// Read one encrypted frame from a sync-Read.
    pub fn read_frame<R: Read>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).context("frame len read")?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_MSG + 16 {
            bail!("frame too large: {len} bytes");
        }
        let mut ct = vec![0u8; len];
        reader.read_exact(&mut ct).context("frame body read")?;
        self.decrypt(&ct)
    }
}

/// Derive a Noise keypair deterministically from the app master key.
/// This makes the P2P identity stable across app restarts without storing
/// an extra secret — the master key is the single secret source.
pub fn derive_keypair_from_master(master_key: &[u8; 32]) -> NoiseKeypair {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(b"diatom-noise-v1"), master_key);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"noise-static-key", &mut *okm)
        .expect("HKDF expand");
    let builder = Builder::new(PATTERN.parse().expect("valid pattern"));
    let raw_kp = builder
        .local_private_key(&*okm)
        .build_initiator()
        .expect("build for keypair extraction");
    let pub_bytes = raw_kp
        .get_remote_static()
        .map(|b| {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            a
        })
        .unwrap_or_else(|| {
            let mut pub_arr = [0u8; 32];
            pub_arr.copy_from_slice(okm.as_slice());
            pub_arr
        });
    NoiseKeypair::from_bytes(pub_bytes, *okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xx_handshake_roundtrip() {
        let kp_i = NoiseKeypair::generate();
        let kp_r = NoiseKeypair::generate();

        let mut hs_i = NoiseHandshake::new_initiator(&kp_i).unwrap();
        let mut hs_r = NoiseHandshake::new_responder(&kp_r).unwrap();

        let msg1 = hs_i.write_message(&[]).unwrap();
        hs_r.read_message(&msg1).unwrap();

        let msg2 = hs_r.write_message(&[]).unwrap();
        hs_i.read_message(&msg2).unwrap();

        let msg3 = hs_i.write_message(&[]).unwrap();
        hs_r.read_message(&msg3).unwrap();

        assert!(hs_i.is_handshake_done());
        assert!(hs_r.is_handshake_done());

        let mut sess_i = hs_i.into_transport().unwrap();
        let mut sess_r = hs_r.into_transport().unwrap();

        let ct = sess_i.encrypt(b"hello from initiator").unwrap();
        let pt = sess_r.decrypt(&ct).unwrap();
        assert_eq!(&pt, b"hello from initiator");

        assert_eq!(sess_i.peer_fingerprint(), kp_r.fingerprint());
    }
}
