// P2P synchronisation: Nostr relay, Noise_XX transport.
pub mod noise;
pub mod nostr;

pub use noise::derive_keypair_from_master;
