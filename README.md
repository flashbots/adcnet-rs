# adcnet

Auction-based anonymous broadcast DC net, in Rust.

`adcnet` provides anonymous broadcast: a client's message is hidden among all participants, and sender identity stays private as long as at least one server is honest. Message scheduling is handled by an Invertible Bloom Lookup Table (IBLT) based auction. The protocol is loosely inspired by [ZIPNet: Low-bandwidth anonymous broadcast from (dis)Trusted Execution Environments](https://eprint.iacr.org/2024/1227).

> [!WARNING]
> Research code. Almost all of it is vibe-coded and unaudited. Do not use it for any production use case.
> Do use it to familiarize yourself with and experiment with the protocol 💖

## Library posture

The crate is library-first. The public surface is a set of **stateless
primitives and encoders**; a downstream caller wires its own transport,
scheduling, and threading around them. Two reference **sessions** ship in-tree
as worked examples of how to compose those pieces — they are illustrations, not
the intended integration point.

- **Primitives** (`primitives`) — blinded-broadcast rounds:
  - `field_round`: field-additive over `F_p`. Client contributions and server
    shares sum to the plaintext mod `p`.
  - `xor_round`: the same shape over raw bytes (XOR-additive).

  Each exposes four functions: `client_blind`, `server_share`,
  `aggregate_clients`, `combine_partials`. They don't know about auctions,
  slots, or IBLTs — they blind, aggregate, and unblind.

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
5. The recovered vector is an IBLT, which is peeled to read out the bids
   (two-round) or the payloads (one-round).

Anonymity holds as long as one server withholds its share from an adversary:
without all shares, the pads don't cancel and nothing is recovered.

## Install

```bash
cargo add adcnet
```

Optional `parallel` feature parallelizes pad derivation and per-message verify
with [rayon](https://crates.io/crates/rayon):

```toml
adcnet = { version = "0.1", features = ["parallel"] }
```

## Usage

Compose the primitives and encoders by hand — one field-additive auction round
with several clients and servers:

```rust
use adcnet::auction::auction::AuctionData;
use adcnet::crypto::SharedKey;
use adcnet::{auction_iblt, field_round};

let round: u32 = 42;
let auction_slots: u32 = 16;

// Per client, the shared secrets with each server (here, fixed for the demo;
// in practice these come from ECDH — see `adcnet::crypto`).
let client_secrets: Vec<Vec<SharedKey>> = /* ... */;
let server_secrets: Vec<Vec<SharedKey>> = /* ... */; // transposed by server

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
let winners = auction_iblt::decode_winners(&recovered, auction_slots, 200, 1).unwrap();
```

## Implementation details

- **Field**: 61-bit prime `p = 0x1eeed4e13a526bab`. Data elements pack into 7
  bytes (`< 2^56 < p`, lossless); 8 bytes on the wire. `2·p < 2^64`, so additions
  never overflow before reduction.
- **IBLT**: uniform `γ × δ` layout — `γ = 4` rows, `δ = ⌈1.5·n⌉` buckets per row
  for `n` expected elements. Multi-value cells store `(counter, key, V_0 … V_{ξ-1})`,
  all field elements accumulating by modular addition, so an IBLT aggregates
  across clients through the field-additive primitive.
- **Signatures**: Ed25519 (`ed25519-dalek`); every wire message is a
  `Signed<T>` envelope.
- **Key exchange**: P-256 ECDH (`p256`).
- **Pads**: AES-128-CTR keyed by `SHA3-256(round ‖ secret)`, domain-separated so
  the same ECDH secret yields independent field- and XOR-round pads.
- Hot paths (pad derivation, field add/sub, XOR) have runtime-detected AVX2 fast
  paths with scalar fallbacks, validated against the scalar implementation in
  tests.

## Security properties

- **Anonymity**: sender identity is protected as long as ≥1 server is honest
  (anytrust).
- **Confidentiality**: contributions are recoverable only with every server's
  share.
- **Unlinkability**: fresh per-round pads prevent cross-round correlation.
- **Integrity**: Ed25519 signatures authenticate every protocol message.
- **Availability**: all servers must contribute their share for recovery.

### Considerations

- All authorized clients should participate each round (with real or dummy
  contributions) to preserve the anonymity set.
- Message padding is required to resist traffic analysis.
- Synchronous rounds are assumed.
- Field arithmetic is **not** constant-time.

## Testing

```bash
cargo test
cargo bench            # criterion-free, prints timings; see benches/
cargo run --example profile
```

## License

MIT — see the LICENSE file.
