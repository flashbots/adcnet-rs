//! Reference 1-round session: IBLT-message broadcast without auction.
//!
//! Each client encodes its payload into a fresh multi-V IBLT entry (key =
//! random, V slots = length-prefixed payload), blinds the field-element
//! representation with the field-additive primitive, and signs the result.
//! Servers aggregate, contribute their shares, and combine partials to
//! recover the field-element vector. Decoding peels payloads atomically.
//!
//! No auction round, no slot assignment, no scheduling — payload size and
//! per-round message count are session config.

use std::collections::HashMap;

use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{PrivateKey, PublicKey, ServerId, SharedKey};
use crate::encoders::iblt_msg::{
    decode_round, encode_empty, encode_payload, IbltMsgError, IbltMsgParams,
};
use crate::primitives::field_round;
use crate::protocol::messages::{u64_vec_bytes, Signed};

/// Session-level config shared by all participants.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OneRoundConfig {
    pub iblt: IbltMsgParamsOwned,
}

/// Owned (and serde-friendly) form of [`IbltMsgParams`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IbltMsgParamsOwned {
    pub estimated_messages: u32,
    pub max_payload_bytes: usize,
}

impl IbltMsgParamsOwned {
    pub fn as_params(&self) -> IbltMsgParams {
        IbltMsgParams {
            estimated_messages: self.estimated_messages,
            max_payload_bytes: self.max_payload_bytes,
        }
    }
}

/// Per-round, per-client payload contribution riding on the field-additive
/// primitive.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientContribution {
    pub round: u32,
    #[serde(with = "u64_vec_bytes")]
    pub blinded: Vec<u64>,
}

/// Per-round, per-server share. Subtracted from the aggregate during decode.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerShare {
    pub server_id: ServerId,
    pub round: u32,
    #[serde(with = "u64_vec_bytes")]
    pub share: Vec<u64>,
}

#[derive(Debug, Error)]
pub enum OneRoundError {
    #[error("encoder error: {0}")]
    Encoder(#[from] IbltMsgError),
    #[error("protocol error: {0}")]
    Protocol(#[from] crate::protocol::messages::ProtocolError),
    #[error("server share count mismatch: expected {expected}, got {got}")]
    ServerShareCount { expected: usize, got: usize },
    #[error("inconsistent round: contribution claims {got}, expected {expected}")]
    WrongRound { got: u32, expected: u32 },
}

/// Client-side: encode `payload` and blind for `round`. Returns the signed
/// contribution wire object.
///
/// `shared_secrets` maps each server's `ServerId` to the client's shared
/// secret with that server. The set of servers must match what the servers
/// use to compute their shares.
pub fn client_contribute<R: Rng>(
    cfg: &OneRoundConfig,
    round: u32,
    signing_key: &PrivateKey,
    shared_secrets: &HashMap<ServerId, SharedKey>,
    payload: Option<&[u8]>,
    rng: &mut R,
) -> Result<Signed<ClientContribution>, OneRoundError> {
    let params = cfg.iblt.as_params();
    let contents = match payload {
        Some(p) => encode_payload(&params, p, rng)?,
        None => encode_empty(&params),
    };
    let secrets = sorted_secrets(shared_secrets);
    let blinded = field_round::client_blind(&secrets, round, contents);
    let obj = ClientContribution { round, blinded };
    Ok(Signed::new(signing_key, obj)?)
}

/// Server-side: build this server's share for `round` and sign it.
///
/// `shared_secrets` maps each client's `PublicKey` to the server's shared
/// secret with that client.
pub fn server_contribute(
    cfg: &OneRoundConfig,
    round: u32,
    server_id: ServerId,
    signing_key: &PrivateKey,
    shared_secrets: &HashMap<PublicKey, SharedKey>,
) -> Result<Signed<ServerShare>, OneRoundError> {
    let params = cfg.iblt.as_params();
    let secrets: Vec<SharedKey> = {
        let mut entries: Vec<(&PublicKey, &SharedKey)> = shared_secrets.iter().collect();
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        entries.into_iter().map(|(_, s)| s.clone()).collect()
    };
    let share = field_round::server_share(&secrets, round, params.encoded_len());
    let obj = ServerShare {
        server_id,
        round,
        share,
    };
    Ok(Signed::new(signing_key, obj)?)
}

/// Combine all client contributions and all server shares to recover the
/// set of payloads contributed this round.
///
/// Caller verifies signatures upstream (this function takes raw payloads).
/// `expected_servers` is the number of servers that must contribute; an
/// undersupplied set returns `ServerShareCount`.
pub fn combine_round(
    cfg: &OneRoundConfig,
    round: u32,
    clients: &[ClientContribution],
    servers: &[ServerShare],
    expected_servers: usize,
) -> Result<Vec<Vec<u8>>, OneRoundError> {
    if servers.len() != expected_servers {
        return Err(OneRoundError::ServerShareCount {
            expected: expected_servers,
            got: servers.len(),
        });
    }
    let mut seen = std::collections::HashSet::with_capacity(servers.len());
    for s in servers {
        if !seen.insert(s.server_id) {
            return Err(crate::protocol::messages::ProtocolError::DuplicatePartial(s.server_id).into());
        }
    }
    for c in clients {
        if c.round != round {
            return Err(OneRoundError::WrongRound {
                got: c.round,
                expected: round,
            });
        }
    }
    for s in servers {
        if s.round != round {
            return Err(OneRoundError::WrongRound {
                got: s.round,
                expected: round,
            });
        }
    }
    let blinded_slices: Vec<&[u64]> = clients.iter().map(|c| c.blinded.as_slice()).collect();
    let agg = field_round::aggregate_clients(&blinded_slices);
    let share_slices: Vec<&[u64]> = servers.iter().map(|s| s.share.as_slice()).collect();
    let recovered = field_round::combine_partials(&agg, &share_slices);
    let params = cfg.iblt.as_params();
    Ok(decode_round(&params, &recovered)?)
}

fn sorted_secrets(secrets: &HashMap<ServerId, SharedKey>) -> Vec<SharedKey> {
    let mut entries: Vec<(&ServerId, &SharedKey)> = secrets.iter().collect();
    entries.sort_by_key(|(sid, _)| sid.0);
    entries.into_iter().map(|(_, s)| s.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, ExchangePrivateKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn config(max_payload: usize, n_msgs: u32) -> OneRoundConfig {
        OneRoundConfig {
            iblt: IbltMsgParamsOwned {
                estimated_messages: n_msgs,
                max_payload_bytes: max_payload,
            },
        }
    }

    #[test]
    fn end_to_end_3_clients_2_servers_1kb_payloads() {
        let n_clients = 3;
        let n_servers = 2;
        let round = 7u32;
        let cfg = config(1024, n_clients as u32);

        // Server identities.
        let mut server_signing: Vec<PrivateKey> = Vec::new();
        let mut server_xkey: Vec<ExchangePrivateKey> = Vec::new();
        let mut server_ids: Vec<ServerId> = Vec::new();
        for s in 0..n_servers {
            let (_pk, sk) = generate_keypair();
            server_signing.push(sk);
            server_xkey.push(ExchangePrivateKey::generate());
            server_ids.push(ServerId((s as u32) + 1));
        }

        // Client identities + ECDH with each server.
        let mut client_signing: Vec<PrivateKey> = Vec::new();
        let mut client_pubs: Vec<PublicKey> = Vec::new();
        let mut client_xkey: Vec<ExchangePrivateKey> = Vec::new();
        let mut client_secrets: Vec<HashMap<ServerId, SharedKey>> =
            vec![HashMap::new(); n_clients];
        for csec in &mut client_secrets {
            let (pk, sk) = generate_keypair();
            let xk = ExchangePrivateKey::generate();
            for s in 0..n_servers {
                let secret = xk.ecdh(&server_xkey[s].public());
                csec.insert(server_ids[s], secret);
            }
            client_signing.push(sk);
            client_pubs.push(pk);
            client_xkey.push(xk);
        }

        // Server side: each server learns each client's shared secret.
        let mut server_secrets: Vec<HashMap<PublicKey, SharedKey>> =
            vec![HashMap::new(); n_servers];
        for s in 0..n_servers {
            for c in 0..n_clients {
                let secret = server_xkey[s].ecdh(&client_xkey[c].public());
                server_secrets[s].insert(client_pubs[c].clone(), secret);
            }
        }

        // Client contributions.
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let payloads: Vec<Vec<u8>> = (0..n_clients)
            .map(|i| {
                let mut v = vec![0u8; 1024];
                for (j, b) in v.iter_mut().enumerate() {
                    *b = ((i * 1024 + j) % 251) as u8;
                }
                v
            })
            .collect();
        let mut signed_clients: Vec<Signed<ClientContribution>> = Vec::new();
        for c in 0..n_clients {
            let s = client_contribute(
                &cfg,
                round,
                &client_signing[c],
                &client_secrets[c],
                Some(&payloads[c]),
                &mut rng,
            )
            .unwrap();
            signed_clients.push(s);
        }

        // Server contributions.
        let mut signed_servers: Vec<Signed<ServerShare>> = Vec::new();
        for s in 0..n_servers {
            let signed = server_contribute(
                &cfg,
                round,
                server_ids[s],
                &server_signing[s],
                &server_secrets[s],
            )
            .unwrap();
            signed_servers.push(signed);
        }

        // Verify signatures, strip envelopes.
        let clients_raw: Vec<ClientContribution> = signed_clients
            .iter()
            .map(|s| s.recover().unwrap().0.clone())
            .collect();
        let servers_raw: Vec<ServerShare> = signed_servers
            .iter()
            .map(|s| s.recover().unwrap().0.clone())
            .collect();

        let mut decoded =
            combine_round(&cfg, round, &clients_raw, &servers_raw, n_servers).unwrap();
        let mut expected = payloads.clone();
        decoded.sort();
        expected.sort();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn missing_server_share_errors() {
        let cfg = config(64, 4);
        let err = combine_round(&cfg, 0, &[], &[], 2).unwrap_err();
        assert!(matches!(err, OneRoundError::ServerShareCount { .. }));

        // Right count, but one server_id duplicated (and another missing)
        // must not be silently treated as full coverage.
        let dup = ServerShare { server_id: ServerId(1), round: 0, share: vec![0u64; 4] };
        let err = combine_round(&cfg, 0, &[], &[dup.clone(), dup], 2).unwrap_err();
        assert!(
            matches!(
                err,
                OneRoundError::Protocol(crate::protocol::messages::ProtocolError::DuplicatePartial(_))
            ),
            "got {err:?}"
        );
    }
}
