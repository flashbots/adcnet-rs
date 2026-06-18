//! Stateful per-component services guarding their state with interior `Mutex`.
//!
//! Under [`AggregationMode::Disabled`](crate::protocol::AggregationMode),
//! [`ServerService::process_client_message`] folds a signed client message
//! directly into the round's running aggregate, skipping the
//! [`AggregatorService`].
//!
//! These are reference compositions: state is locked with `.lock().unwrap()`,
//! so a panic while holding a lock poisons the `Mutex` and propagates as a
//! panic on the next access. Deployments needing fault isolation should supply
//! their own concurrency by driving the underlying primitives directly.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::auction::auction::AuctionData;
use crate::crypto::fields::add_mod_slice;
use crate::crypto::{xor_inplace, ExchangePrivateKey, ExchangePublicKey, PrivateKey, PublicKey, ServerId, SharedKey};

use super::config::AdcNetConfig;
use super::messages::{
    AggregatedClientMessages, ClientRoundMessage, ProtocolError, RoundBroadcast,
    ServerPartialDecryptionMessage, Signed,
};
use super::messager::{
    AggregatorMessager, ClientMessager, ServerMessager, VerifiedClientMessage, VerifyClientMessages,
};
use super::round::Round;

// -----------------------------------------------------------------------------
// Server
// -----------------------------------------------------------------------------

pub struct ServerService {
    config: AdcNetConfig,
    server_id: ServerId,
    server_signing_key: PrivateKey,
    server_exchange_key: ExchangePrivateKey,

    shared_secrets: Mutex<HashMap<String, SharedKey>>,
    /// Registered signing pubkeys for every peer server (including self). Used
    /// by [`Self::process_signed_partial_decryption_message`] to verify that
    /// the claimed `server_id` matches the signer's identity.
    peer_pubkeys: Mutex<HashMap<ServerId, PublicKey>>,
    state: Mutex<ServerState>,
}

#[derive(Default)]
struct ServerState {
    current_round: i64,
    round: Option<ServerRoundData>,
}

#[derive(Default)]
struct ServerRoundData {
    partials: HashMap<ServerId, ServerPartialDecryptionMessage>,
    own_partial: Option<ServerPartialDecryptionMessage>,
    round_output: Option<RoundBroadcast>,
    /// Running aggregate built from direct client submissions when aggregation is disabled.
    direct_aggregate: Option<AggregatedClientMessages>,
}

impl ServerService {
    pub fn new(
        config: AdcNetConfig,
        server_id: ServerId,
        server_signing_key: PrivateKey,
        server_exchange_key: ExchangePrivateKey,
    ) -> Self {
        // Register self automatically — the leader's own partial trivially
        // verifies against its own signing key.
        let own_pub = server_signing_key
            .public_key()
            .expect("server signing key must yield a public key");
        let mut peers = HashMap::new();
        peers.insert(server_id, own_pub);
        Self {
            config,
            server_id,
            server_signing_key,
            server_exchange_key,
            shared_secrets: Mutex::new(HashMap::new()),
            peer_pubkeys: Mutex::new(peers),
            state: Mutex::new(ServerState::default()),
        }
    }

    /// Register a peer server's signing pubkey. Required before accepting
    /// signed partial-decryption messages from that peer.
    pub fn register_peer_server(&self, server_id: ServerId, pubkey: PublicKey) {
        self.peer_pubkeys.lock().unwrap().insert(server_id, pubkey);
    }

    pub fn server_id(&self) -> ServerId {
        self.server_id
    }
    pub fn signing_key(&self) -> &PrivateKey {
        &self.server_signing_key
    }

    pub fn advance_to_round(&self, round: Round) {
        let mut state = self.state.lock().unwrap();
        if state.current_round >= round.number {
            return;
        }
        state.current_round = round.number;
        state.round = Some(ServerRoundData::default());
        let _ = round;
    }

    pub fn register_client(
        &self,
        client_pubkey: &PublicKey,
        client_ecdh_pubkey: &ExchangePublicKey,
    ) -> Result<(), ProtocolError> {
        let shared = self.server_exchange_key.ecdh(client_ecdh_pubkey);
        self.shared_secrets
            .lock()
            .unwrap()
            .insert(client_pubkey.to_hex(), shared);
        Ok(())
    }

    pub fn deregister_client(&self, client_pubkey: &PublicKey) {
        self.shared_secrets.lock().unwrap().remove(&client_pubkey.to_hex());
    }

    /// Used in the aggregation-disabled mode: fold a signed client message into
    /// the round aggregate, in place. Returns nothing — the running aggregate
    /// stays inside the server's per-round state and is consumed later by
    /// [`Self::finalize_partial_for_direct_aggregate`].
    ///
    /// Buffers are owned by the server (allocated zero-filled on first call);
    /// no slice of the caller's `ClientRoundMessage` is reused, so the caller
    /// can free `msg` after this call returns.
    pub fn process_client_message(
        &self,
        msg: &Signed<ClientRoundMessage>,
    ) -> Result<(), ProtocolError> {
        let (raw, signer) = msg.recover()?;
        let mut state = self.state.lock().unwrap();
        let cur = state.current_round;
        let rd = state.round.as_mut().ok_or(ProtocolError::ClientNotInitialized)?;

        if raw.round_number != cur {
            return Err(ProtocolError::WrongRound { got: raw.round_number, expected: cur });
        }

        // Lazy-init the aggregate's owned buffers on the first message.
        let agg = rd.direct_aggregate.get_or_insert_with(|| AggregatedClientMessages {
            round_number: raw.round_number,
            all_server_ids: raw.all_server_ids.clone(),
            auction_vector: vec![0u64; raw.auction_vector.len()],
            message_vector: vec![0u8; raw.message_vector.len()],
            user_pks: Vec::new(),
        });

        if agg.all_server_ids != raw.all_server_ids {
            return Err(ProtocolError::MismatchingServers);
        }
        if agg.message_vector.len() != raw.message_vector.len()
            || agg.auction_vector.len() != raw.auction_vector.len()
        {
            return Err(ProtocolError::MismatchingVectorLengths);
        }

        // Fold directly: SIMD field-add auction, AVX2-XOR message, push signer.
        add_mod_slice(&mut agg.auction_vector, &raw.auction_vector);
        xor_inplace(&mut agg.message_vector, &raw.message_vector);
        agg.user_pks.push(signer.clone());
        Ok(())
    }

    /// Run server-side unblinding over the running aggregate. Used in
    /// aggregation-disabled mode to finalize the per-server share. Takes
    /// ownership of the running aggregate (subsequent calls in the same round
    /// will see it gone).
    pub fn finalize_partial_for_direct_aggregate(
        &self,
    ) -> Result<ServerPartialDecryptionMessage, ProtocolError> {
        let agg = {
            let mut state = self.state.lock().unwrap();
            let rd = state.round.as_mut().ok_or(ProtocolError::ClientNotInitialized)?;
            rd.direct_aggregate.take().ok_or(ProtocolError::ClientNotInitialized)?
        };
        self.process_aggregate_message(&agg)
    }

    pub fn process_aggregate_message(
        &self,
        msg: &AggregatedClientMessages,
    ) -> Result<ServerPartialDecryptionMessage, ProtocolError> {
        let cur = self.state.lock().unwrap().current_round;
        if !msg.all_server_ids.contains(&self.server_id) {
            return Err(ProtocolError::InvalidServer(self.server_id));
        }
        if msg.round_number != cur {
            return Err(ProtocolError::WrongRound { got: msg.round_number, expected: cur });
        }

        let shared = self.shared_secrets.lock().unwrap();
        let messager = ServerMessager {
            config: &self.config,
            server_id: self.server_id,
            shared_secrets: &shared,
        };
        let additional = messager.unblind_aggregate(cur, msg)?;
        drop(shared);

        let mut state = self.state.lock().unwrap();
        let rd = state.round.as_mut().ok_or(ProtocolError::ClientNotInitialized)?;
        match &mut rd.own_partial {
            None => {
                rd.own_partial = Some(additional.clone());
            }
            Some(current) => {
                current.user_pks.extend(additional.user_pks.iter().cloned());
                add_mod_slice(&mut current.auction_vector, &additional.auction_vector);
                xor_inplace(&mut current.message_vector, &additional.message_vector);
                current.original_aggregate.union_inplace(msg)?;
            }
        }
        // Note: do *not* insert into `rd.partials` here — the leader's own
        // partial joins the partial set via the standard
        // `process_partial_decryption_message` path, which now enforces
        // duplicate rejection.
        let out = rd.own_partial.clone().unwrap();
        Ok(out)
    }

    /// Sign this server's own partial-decryption output. Use the returned
    /// `Signed<...>` envelope when forwarding to peer servers so they can
    /// authenticate it via [`Self::process_signed_partial_decryption_message`].
    pub fn sign_partial(
        &self,
        partial: ServerPartialDecryptionMessage,
    ) -> Result<Signed<ServerPartialDecryptionMessage>, ProtocolError> {
        Signed::new(&self.server_signing_key, partial)
    }

    /// Accept a *signed* partial from another server. Verifies the signature
    /// and checks the claimed `server_id` against the registered peer-pubkey
    /// map (see [`Self::register_peer_server`]). Rejects forged or
    /// unregistered partials before they ever touch the per-round state.
    pub fn process_signed_partial_decryption_message(
        &self,
        signed: Signed<ServerPartialDecryptionMessage>,
    ) -> Result<Option<RoundBroadcast>, ProtocolError> {
        let claimed = signed.object.server_id;
        let (raw, signer) = signed.recover()?;
        let expected = self
            .peer_pubkeys
            .lock()
            .unwrap()
            .get(&claimed)
            .cloned()
            .ok_or(ProtocolError::UnknownPeerServer(claimed))?;
        if signer != &expected {
            return Err(ProtocolError::SignerIdentityMismatch { claimed });
        }
        let msg = raw.clone();
        self.process_partial_decryption_message(msg)
    }

    /// Accept a partial from another server. Once all partials have arrived,
    /// returns the reconstructed [`RoundBroadcast`].
    ///
    /// **This is the trusted-input variant**: it expects the caller to have
    /// authenticated `msg` already. For untrusted transport, prefer
    /// [`Self::process_signed_partial_decryption_message`] which gates on the
    /// peer-pubkey registry. Either way, the function rejects duplicate
    /// `server_id`s within a round.
    pub fn process_partial_decryption_message(
        &self,
        msg: ServerPartialDecryptionMessage,
    ) -> Result<Option<RoundBroadcast>, ProtocolError> {
        let cur = self.state.lock().unwrap().current_round;
        if msg.original_aggregate.round_number != cur {
            return Err(ProtocolError::WrongRound {
                got: msg.original_aggregate.round_number,
                expected: cur,
            });
        }

        let mut state = self.state.lock().unwrap();
        let rd = state.round.as_mut().ok_or(ProtocolError::ClientNotInitialized)?;
        if let Some(ref out) = rd.round_output {
            return Ok(Some(out.clone()));
        }

        if !msg.original_aggregate.all_server_ids.contains(&msg.server_id) {
            return Err(ProtocolError::InvalidServer(msg.server_id));
        }
        let n_servers = msg.original_aggregate.all_server_ids.len();
        // Reject duplicate partials from the same server within a round
        // (collision-detection, prevents one peer from racing another's
        // submission even in the unauthenticated path).
        let sid = msg.server_id;
        match rd.partials.entry(sid) {
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(ProtocolError::DuplicatePartial(sid));
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(msg);
            }
        }
        if rd.partials.len() < n_servers {
            return Ok(None);
        }

        let mut msgs: Vec<ServerPartialDecryptionMessage> = rd.partials.values().cloned().collect();
        drop(state);
        let shared = self.shared_secrets.lock().unwrap();
        let messager = ServerMessager {
            config: &self.config,
            server_id: self.server_id,
            shared_secrets: &shared,
        };
        let bc = messager.unblind_partial_messages(&mut msgs)?;
        drop(shared);

        let mut state = self.state.lock().unwrap();
        let rd = state.round.as_mut().ok_or(ProtocolError::ClientNotInitialized)?;
        rd.round_output = Some(bc.clone());
        Ok(Some(bc))
    }
}

// -----------------------------------------------------------------------------
// Aggregator
// -----------------------------------------------------------------------------

pub struct AggregatorService {
    config: AdcNetConfig,
    authorized: Mutex<HashMap<String, bool>>,
    state: Mutex<AggregatorState>,
}

#[derive(Default)]
struct AggregatorState {
    current_round: i64,
    aggregate: Option<AggregatedClientMessages>,
}

impl AggregatorService {
    pub fn new(config: AdcNetConfig) -> Self {
        Self {
            config,
            authorized: Mutex::new(HashMap::new()),
            state: Mutex::new(AggregatorState::default()),
        }
    }

    pub fn advance_to_round(&self, round: Round) {
        let mut state = self.state.lock().unwrap();
        if state.current_round >= round.number {
            return;
        }
        state.current_round = round.number;
        state.aggregate = None;
    }

    pub fn register_client(&self, pk: &PublicKey) {
        self.authorized.lock().unwrap().insert(pk.to_hex(), true);
    }
    pub fn deregister_client(&self, pk: &PublicKey) {
        self.authorized.lock().unwrap().remove(&pk.to_hex());
    }

    pub fn process_client_messages(
        &self,
        msgs: &[Signed<ClientRoundMessage>],
    ) -> Result<AggregatedClientMessages, ProtocolError> {
        let verified = VerifyClientMessages::verify(msgs)?;
        self.process_verified_messages(&verified)
    }

    pub fn process_verified_messages(
        &self,
        verified: &[VerifiedClientMessage],
    ) -> Result<AggregatedClientMessages, ProtocolError> {
        let mut state = self.state.lock().unwrap();
        for v in verified {
            if v.message.round_number != state.current_round {
                return Err(ProtocolError::WrongRound {
                    got: v.message.round_number,
                    expected: state.current_round,
                });
            }
        }
        let authorized = self.authorized.lock().unwrap();
        let m = AggregatorMessager { config: &self.config };
        let agg = m.aggregate_verified_messages(
            state.current_round,
            state.aggregate.as_ref(),
            verified,
            &authorized,
        )?;
        state.aggregate = Some(agg.clone());
        Ok(agg)
    }

    pub fn current_aggregate(&self) -> Option<AggregatedClientMessages> {
        self.state.lock().unwrap().aggregate.clone()
    }
}

// -----------------------------------------------------------------------------
// Client
// -----------------------------------------------------------------------------

pub struct ClientService {
    config: AdcNetConfig,
    exchange_key: ExchangePrivateKey,
    signing_key: PrivateKey,

    shared_secrets: Mutex<HashMap<ServerId, SharedKey>>,
    state: Mutex<ClientState>,
}

#[derive(Default)]
struct ClientState {
    current_round: i64,
    pending: Option<PendingMessage>,
    scheduled: Option<ScheduledMessage>,
    last_broadcast: Option<RoundBroadcast>,
}

#[derive(Clone)]
struct PendingMessage {
    message: Vec<u8>,
    auction_data: AuctionData,
}

#[derive(Clone)]
struct ScheduledMessage {
    message: Vec<u8>,
    auction_round: i64,
}

impl ClientService {
    pub fn new(
        config: AdcNetConfig,
        signing_key: PrivateKey,
        exchange_key: ExchangePrivateKey,
    ) -> Self {
        Self {
            config,
            exchange_key,
            signing_key,
            shared_secrets: Mutex::new(HashMap::new()),
            state: Mutex::new(ClientState::default()),
        }
    }

    pub fn exchange_public(&self) -> ExchangePublicKey {
        self.exchange_key.public()
    }
    pub fn signing_key(&self) -> &PrivateKey {
        &self.signing_key
    }

    pub fn advance_to_round(&self, round: Round) {
        let mut state = self.state.lock().unwrap();
        if round.number <= state.current_round {
            return;
        }
        if let Some(s) = &state.scheduled {
            if s.auction_round + 1 < round.number {
                state.scheduled = None;
            }
        }
        state.current_round = round.number;
    }

    pub fn register_server(
        &self,
        server_id: ServerId,
        server_exchange: &ExchangePublicKey,
    ) -> Result<(), ProtocolError> {
        let shared = self.exchange_key.ecdh(server_exchange);
        self.shared_secrets.lock().unwrap().insert(server_id, shared);
        Ok(())
    }

    pub fn deregister_server(&self, server_id: ServerId) {
        self.shared_secrets.lock().unwrap().remove(&server_id);
    }

    pub fn schedule_message_for_next_round(
        &self,
        msg: &[u8],
        bid_value: u32,
    ) -> Result<(), ProtocolError> {
        if msg.is_empty() {
            return Err(ProtocolError::NilMessage);
        }
        let mut state = self.state.lock().unwrap();
        if state.current_round == 0 {
            return Err(ProtocolError::ClientNotInitialized);
        }
        if state.pending.is_some() {
            return Err(ProtocolError::AlreadyPending);
        }
        state.pending = Some(PendingMessage {
            message: msg.to_vec(),
            auction_data: AuctionData::from_message(msg, bid_value),
        });
        Ok(())
    }

    /// Generate a signed `ClientRoundMessage` for the current round.
    pub fn messages_for_current_round(
        &self,
    ) -> Result<(Signed<ClientRoundMessage>, bool), ProtocolError> {
        let mut state = self.state.lock().unwrap();
        let cur = state.current_round;
        let last_bc = state.last_broadcast.clone().ok_or(ProtocolError::NoPreviousBroadcast)?;
        if last_bc.round_number != cur - 1 {
            return Err(ProtocolError::NoPreviousBroadcast);
        }

        let message_to_transmit = match &state.scheduled {
            Some(s) if s.auction_round == cur - 1 => {
                let m = s.message.clone();
                state.scheduled = None;
                m
            }
            _ => Vec::new(),
        };
        let auction_bid = state.pending.take().map(|p| {
            state.scheduled = Some(ScheduledMessage {
                message: p.message.clone(),
                auction_round: cur,
            });
            p.auction_data
        });

        let shared = self.shared_secrets.lock().unwrap();
        let messager = ClientMessager { config: &self.config, shared_secrets: &shared };
        let (msg, won) = messager.prepare_message(
            cur,
            &last_bc,
            &message_to_transmit,
            auction_bid.as_ref(),
        )?;
        drop(shared);

        let signed = Signed::new(&self.signing_key, msg)?;
        Ok((signed, won))
    }

    pub fn process_round_broadcast(&self, rb: RoundBroadcast) {
        self.state.lock().unwrap().last_broadcast = Some(rb);
    }
}
