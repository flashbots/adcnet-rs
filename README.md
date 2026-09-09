# adcnet

Auction-based anonymous broadcast DC net, in Rust.

`adcnet` implements an auction-based DC-net protocol for anonymous broadcast. Message scheduling is handled by an Invertible Bloom Lookup Table (IBLT) based auction. The protocol is loosely inspired by [ZIPNet: Low-bandwidth anonymous broadcast from (dis)Trusted Execution Environments](https://eprint.iacr.org/2024/1227).

> [!WARNING]
> Research code. Almost all of it is vibe-coded and unaudited. Do not use it for any production use case.
> Do use it to familiarize yourself with and experiment with the protocol 💖

## Library posture

Use the **sessions** for the provided one-round and two-round flows, or compose
**stateless primitives and encoders** for a custom flow. The caller supplies
transport, scheduling, and threading.

- **Primitives** (`primitives`) — blinded-broadcast rounds:
  - `field_round`: field-additive over `F_p`. Subtract server shares from the
    aggregated client contributions to recover the plaintext mod `p`.
  - `xor_round`: the same shape over raw bytes (XOR-additive).

  Both expose `client_blind`, `server_share`, `aggregate_clients`, and
  `combine_partials`, with in-place aggregation variants.

- **Encoders** (`encoders`) — payload encode/decode that brackets a round:
  - `auction_iblt`: encode bids into an IBLT, decode winners from the recovered
    field-element vector (runs the knapsack auction).
  - `iblt_msg`: encode payloads into an IBLT, decode everyone's payloads from
    the recovered vector (scheduling-free, one round).
  - `message_slots`: write/read payloads at auction-assigned slot offsets.

- **Sessions** (`protocol::session`) — reference compositions:
  - `two_round`: auction round (field-additive IBLT of bids) → broadcast round
    (XOR-additive message slots), with an optional aggregator layer.
  - `one_round`: scheduling-free IBLT-message flow — one field-additive round
    that carries the payloads directly.

## How it works

1. Every client shares an ECDH secret with every server.
2. Each round, clients **blind** their contribution by adding (or XORing)
   PRF-derived one-time pads, one per shared secret, then sign it.
3. Contributions are **aggregated** (summed mod `p`, or XORed) — optionally via
   an aggregator to cut server fan-in.
4. Each server contributes its **share** (the same pads summed over its own
   secrets). With every server's share, the pads cancel and the aggregate
   plaintext is **recovered**.
5. Field rounds recover an IBLT of bids (two-round) or payloads (one-round).
   The two-round flow then broadcasts payloads in auction-assigned XOR slots.

## Install

```toml
[dependencies]
adcnet = { git = "https://github.com/flashbots/adcnet-rs" }
```

Enable `features = ["parallel"]` to parallelize pad derivation and aggregation
with Rayon. Signature verification remains sequential.

## Usage

Compose the primitives and encoders by hand — one field-additive auction round
with several clients and servers:

```rust
use adcnet::auction::auction::AuctionData;
use adcnet::crypto::{ExchangePrivateKey, SharedKey};
use adcnet::{auction_iblt, field_round};

let round: u32 = 42;
let auction_slots: u32 = 16;

let clients: Vec<_> = (0..3).map(|_| ExchangePrivateKey::generate()).collect();
let servers: Vec<_> = (0..2).map(|_| ExchangePrivateKey::generate()).collect();
let client_secrets: Vec<Vec<SharedKey>> = clients.iter()
    .map(|client| servers.iter().map(|server| client.ecdh(&server.public())).collect())
    .collect();
let server_secrets: Vec<Vec<SharedKey>> = servers.iter()
    .map(|server| clients.iter().map(|client| server.ecdh(&client.public())).collect())
    .collect();

// Each client encodes a bid into an identically-sized IBLT and blinds it.
let blinded: Vec<Vec<u64>> = client_secrets.iter().enumerate().map(|(c, secrets)| {
    let mut iblt = auction_iblt::empty_iblt(auction_slots);
    let bid = AuctionData { message_hash: [c as u8; 32], weight: 10 + c as u32, size: 20 };
    auction_iblt::insert_bid(&mut iblt, &bid, &mut rand::thread_rng()).unwrap();
    field_round::client_blind(secrets, round, auction_iblt::encode_iblt(&iblt))
}).collect();

// Aggregate client contributions, gather server shares, combine to unblind.
let agg = field_round::aggregate_clients(&blinded.iter().map(Vec::as_slice).collect::<Vec<_>>());
let shares: Vec<Vec<u64>> = server_secrets.iter()
    .map(|s| field_round::server_share(s, round, agg.len()))
    .collect();
let recovered = field_round::combine_partials(&agg, &shares.iter().map(Vec::as_slice).collect::<Vec<_>>());

// Decode the recovered IBLT and run the auction.
// Each bid occupies a 1 KiB slot; the budget admits the two highest bids.
let winners = auction_iblt::decode_winners(&recovered, auction_slots, 2 * 1024, 1).unwrap();
assert_eq!(winners.len(), 2);
assert_eq!(winners.iter().map(|w| w.bid.weight).sum::<u32>(), 23);
```

## Implementation details

- **Field**: 61-bit prime `p = 0x1eeed4e13a526bab`. Data elements pack into 7
  bytes (`< 2^56 < p`, lossless); 8 bytes on the wire. `2·p < 2^64`, so additions
  never overflow before reduction.
- **IBLT**: uniform `γ × δ` layout — `γ = 4` rows, `δ = max(1, ⌈1.5·n⌉)` buckets per row
  for `n` expected elements. Multi-value cells store `(counter, key, V_0 … V_{ξ-1})`,
  all field elements accumulating by modular addition, so an IBLT aggregates
  across clients through the field-additive primitive.
- **Signatures**: Ed25519 (`ed25519-dalek`) through `Signed<T>` envelopes.
  Callers must verify signatures before passing raw messages to APIs such as
  `one_round::combine_round`.
- **Key exchange**: P-256 ECDH (`p256`).
- **Pads**: AES-128-CTR keyed by `SHA3-256(round ‖ secret)`, domain-separated so
  the same ECDH secret yields independent field- and XOR-round pads.
- Hot paths (pad derivation, field add/sub, XOR) have runtime-detected AVX2 fast
  paths with scalar fallbacks, validated against the scalar implementation in
  tests.

## Security assumptions and limits

The protocol assumes an honest server, authenticated peer keys, and agreement
on the participating clients and servers. These assumptions are not a security
proof for this implementation.

- Verify signatures and authorize signers. Signatures do not establish that
  contributions or shares are correctly formed.
- Use each round's pads only once. Pad derivation uses 32-bit round numbers;
  refresh secrets before wraparound and use separate secrets for independent sessions.
- Agree on the client set before releasing server shares. Do not release shares
  for arbitrary subsets of clients.
- Supply cover traffic, padding, and round scheduling. Fresh pads alone do not
  prevent traffic analysis.
- Recovery requires every server's share. Malicious participants can disrupt
  decoding; the crate provides no blame or disruption-recovery protocol.
- Field arithmetic is not constant-time.

## Testing

```bash
cargo test
cargo bench            # criterion-free, prints timings; see benches/
cargo run --example profile
```

## License

MIT — see the LICENSE file.
