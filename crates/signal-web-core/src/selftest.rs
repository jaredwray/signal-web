//! Local cryptographic self-test.
//!
//! Everything here runs in-process with in-memory stores and synthetic
//! identities. It exercises the current libsignal-protocol code paths
//! (PQXDH with Kyber1024, the SPQR triple ratchet, sealed sender) inside the
//! browser's WebAssembly engine. It is NOT a live Signal test: nothing here
//! contacts Signal's servers or an official client.

use libsignal_protocol::*;
use rand::Rng;
use rand::rngs::ThreadRng;
use serde::Serialize;

use crate::clock;

#[derive(Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub ms: f64,
}

#[derive(Serialize)]
pub struct Report {
    pub kind: &'static str,
    pub label: &'static str,
    pub libsignal_core_version: &'static str,
    pub passed: usize,
    pub failed: usize,
    pub aborted: Option<String>,
    pub checks: Vec<Check>,
}

impl Report {
    fn record(&mut self, name: &str, started: f64, result: R<String>) -> bool {
        let ms = clock::perf_ms() - started;
        let (ok, detail) = match result {
            Ok(detail) => (true, detail),
            Err(err) => (false, err),
        };
        if ok {
            self.passed += 1;
        } else {
            self.failed += 1;
        }
        self.checks.push(Check {
            name: name.to_owned(),
            ok,
            detail,
            ms,
        });
        ok
    }
}

type R<T> = Result<T, String>;

fn ctx<E: std::fmt::Display>(context: &str) -> impl FnOnce(E) -> String + '_ {
    move |err| format!("{context}: {err}")
}

fn ensure(cond: bool, msg: impl Into<String>) -> R<()> {
    if cond { Ok(()) } else { Err(msg.into()) }
}

struct Party {
    address: ProtocolAddress,
    store: InMemSignalProtocolStore,
}

fn random_service_id(rng: &mut ThreadRng) -> String {
    let mut b: [u8; 16] = rng.random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

impl Party {
    fn new(rng: &mut ThreadRng, address: Option<ProtocolAddress>) -> R<Self> {
        let identity = IdentityKeyPair::generate(rng);
        let registration_id: u32 = rng.random_range(1..16380);
        let address = match address {
            Some(address) => address,
            None => ProtocolAddress::new(
                random_service_id(rng),
                DeviceId::new(1).map_err(ctx("device id"))?,
            ),
        };
        Ok(Self {
            address,
            store: InMemSignalProtocolStore::new(identity, registration_id)
                .map_err(ctx("store"))?,
        })
    }
}

/// Mirrors `create_pre_key_bundle` in libsignal's rust/protocol/tests/support.
async fn publish_bundle(p: &mut Party, rng: &mut ThreadRng) -> R<PreKeyBundle> {
    let identity = p
        .store
        .get_identity_key_pair()
        .await
        .map_err(ctx("identity"))?;
    let pre_key_pair = KeyPair::generate(rng);
    let signed_pre_key_pair = KeyPair::generate(rng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
    let signed_sig = identity
        .private_key()
        .calculate_signature(&signed_pre_key_pair.public_key.serialize(), rng)
        .map_err(ctx("sign signed prekey"))?;
    let kyber_sig = identity
        .private_key()
        .calculate_signature(&kyber_pre_key_pair.public_key.serialize(), rng)
        .map_err(ctx("sign kyber prekey"))?;
    let pre_key_id: PreKeyId = rng.random_range(1..0xFF_FFFFu32).into();
    let signed_id: SignedPreKeyId = rng.random_range(1..0xFF_FFFFu32).into();
    let kyber_id: KyberPreKeyId = rng.random_range(1..0xFF_FFFFu32).into();
    let ts = Timestamp::from_epoch_millis(clock::now_millis());

    p.store
        .save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key_pair))
        .await
        .map_err(ctx("save prekey"))?;
    p.store
        .save_signed_pre_key(
            signed_id,
            &SignedPreKeyRecord::new(signed_id, ts, &signed_pre_key_pair, &signed_sig),
        )
        .await
        .map_err(ctx("save signed prekey"))?;
    // KyberPreKeyRecord::generate() calls SystemTime::now(), which panics on
    // wasm32-unknown-unknown, so the record is assembled from its parts.
    p.store
        .save_kyber_pre_key(
            kyber_id,
            &KyberPreKeyRecord::new(kyber_id, ts, &kyber_pre_key_pair, &kyber_sig),
        )
        .await
        .map_err(ctx("save kyber prekey"))?;

    PreKeyBundle::new(
        p.store
            .get_local_registration_id()
            .await
            .map_err(ctx("registration id"))?,
        p.address.device_id(),
        Some((pre_key_id, pre_key_pair.public_key)),
        signed_id,
        signed_pre_key_pair.public_key,
        signed_sig.to_vec(),
        kyber_id,
        kyber_pre_key_pair.public_key.clone(),
        kyber_sig.to_vec(),
        *identity.identity_key(),
    )
    .map_err(ctx("bundle"))
}

/// Serialized bytes, as they would cross the network.
#[derive(Clone)]
struct Wire {
    kind: CiphertextMessageType,
    bytes: Vec<u8>,
}

async fn send(from: &mut Party, to: &ProtocolAddress, text: &[u8], rng: &mut ThreadRng) -> R<Wire> {
    let msg = message_encrypt(
        text,
        to,
        &from.address,
        &mut from.store.session_store,
        &mut from.store.identity_store,
        clock::now(),
        rng,
    )
    .await
    .map_err(ctx("encrypt"))?;
    Ok(Wire {
        kind: msg.message_type(),
        bytes: msg.serialize().to_vec(),
    })
}

fn parse(w: &Wire) -> R<CiphertextMessage> {
    match w.kind {
        CiphertextMessageType::PreKey => PreKeySignalMessage::try_from(w.bytes.as_slice())
            .map(CiphertextMessage::PreKeySignalMessage)
            .map_err(ctx("parse PreKeySignalMessage")),
        CiphertextMessageType::Whisper => SignalMessage::try_from(w.bytes.as_slice())
            .map(CiphertextMessage::SignalMessage)
            .map_err(ctx("parse SignalMessage")),
        other => Err(format!("unexpected message type {}", other as u8)),
    }
}

async fn receive(
    to: &mut Party,
    from: &ProtocolAddress,
    w: &Wire,
    rng: &mut ThreadRng,
) -> R<Vec<u8>> {
    let msg = parse(w)?;
    message_decrypt(
        &msg,
        from,
        &to.address,
        &mut to.store.session_store,
        &mut to.store.identity_store,
        &mut to.store.pre_key_store,
        &to.store.signed_pre_key_store,
        &mut to.store.kyber_pre_key_store,
        rng,
    )
    .await
    .map_err(ctx("decrypt"))
}

async fn exchange(
    from: &mut Party,
    to: &mut Party,
    text: &str,
    rng: &mut ThreadRng,
) -> R<CiphertextMessageType> {
    let to_addr = to.address.clone();
    let from_addr = from.address.clone();
    let wire = send(from, &to_addr, text.as_bytes(), rng).await?;
    let plain = receive(to, &from_addr, &wire, rng).await?;
    ensure(plain == text.as_bytes(), format!("plaintext mismatch for {text:?}"))?;
    Ok(wire.kind)
}

async fn session_bytes(p: &Party, peer: &ProtocolAddress) -> R<Vec<u8>> {
    p.store
        .load_session(peer)
        .await
        .map_err(ctx("load session"))?
        .ok_or("no session")?
        .serialize()
        .map_err(ctx("serialize session"))
}

/// Rebuilds a party from serialized bytes only, as if loaded from storage.
struct Snapshot {
    address: ProtocolAddress,
    identity: Vec<u8>,
    registration_id: u32,
    peer: ProtocolAddress,
    peer_identity: Vec<u8>,
    session: Vec<u8>,
}

async fn snapshot(p: &Party, peer: &ProtocolAddress) -> R<Snapshot> {
    Ok(Snapshot {
        address: p.address.clone(),
        identity: p
            .store
            .get_identity_key_pair()
            .await
            .map_err(ctx("identity"))?
            .serialize()
            .to_vec(),
        registration_id: p
            .store
            .get_local_registration_id()
            .await
            .map_err(ctx("registration id"))?,
        peer: peer.clone(),
        peer_identity: p
            .store
            .get_identity(peer)
            .await
            .map_err(ctx("peer identity"))?
            .ok_or("peer identity missing")?
            .serialize()
            .to_vec(),
        session: session_bytes(p, peer).await?,
    })
}

async fn restore(s: &Snapshot) -> R<Party> {
    let identity =
        IdentityKeyPair::try_from(s.identity.as_slice()).map_err(ctx("restore identity"))?;
    let mut store =
        InMemSignalProtocolStore::new(identity, s.registration_id).map_err(ctx("store"))?;
    let peer_identity =
        IdentityKey::decode(&s.peer_identity).map_err(ctx("restore peer identity"))?;
    store
        .save_identity(&s.peer, &peer_identity)
        .await
        .map_err(ctx("save peer identity"))?;
    let record = SessionRecord::deserialize(&s.session).map_err(ctx("restore session"))?;
    store
        .store_session(&s.peer, &record)
        .await
        .map_err(ctx("store session"))?;
    Ok(Party {
        address: s.address.clone(),
        store,
    })
}

/// Returns Ok(stage) if the tampered message was rejected at parse or decrypt.
async fn expect_rejected(to: &mut Party, from: &ProtocolAddress, w: &Wire, rng: &mut ThreadRng) -> R<String> {
    match parse(w) {
        Err(err) => Ok(format!("rejected at parse ({err})")),
        Ok(_) => match receive(to, from, w, rng).await {
            Err(err) => Ok(format!("rejected at decrypt ({err})")),
            Ok(_) => Err("tampered message was ACCEPTED".into()),
        },
    }
}

pub async fn run() -> Report {
    let mut report = Report {
        kind: "local-crypto-selftest",
        label: "LOCAL cryptographic test with synthetic identities; not a live Signal test",
        libsignal_core_version: libsignal_core::VERSION,
        passed: 0,
        failed: 0,
        aborted: None,
        checks: Vec::new(),
    };
    if let Err(err) = run_inner(&mut report).await {
        report.aborted = Some(err);
    }
    report
}

/// Runs one named check. The body is wrapped in an async block so that `?`
/// inside it fails *this* check (and is recorded) instead of returning from
/// the whole runner. Later checks depend on earlier state, so the run stops
/// at the first failure.
macro_rules! step {
    ($report:expr, $name:expr, $body:block) => {{
        let started = clock::perf_ms();
        let result: R<String> = async { $body }.await;
        if !$report.record($name, started, result) {
            return Err(format!("stopped after failed step {}", $name));
        }
    }};
}

async fn run_inner(report: &mut Report) -> R<()> {
    let mut rng = rand::rng();
    let rng = &mut rng;

    step!(report, "keygen.identity_sign_verify", {
        let identity = IdentityKeyPair::generate(rng);
        let msg = b"signal-web keygen check";
        let sig = identity
            .private_key()
            .calculate_signature(msg, rng)
            .map_err(ctx("sign"))?;
        ensure(identity.public_key().verify_signature(msg, &sig), "valid signature rejected")?;
        let mut bad = sig.to_vec();
        bad[10] ^= 1;
        ensure(!identity.public_key().verify_signature(msg, &bad), "tampered signature accepted")?;
        Ok(format!(
            "identity public key {} bytes, signature {} bytes",
            identity.public_key().serialize().len(),
            sig.len()
        ))
    });

    step!(report, "keygen.kyber1024_encapsulate", {
        let kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
        let (ss1, ct) = kp.public_key.encapsulate(rng).map_err(ctx("encapsulate"))?;
        let ss2 = kp.secret_key.decapsulate(&ct).map_err(ctx("decapsulate"))?;
        ensure(ss1[..] == ss2[..], "shared secrets differ")?;
        Ok(format!(
            "public key {} bytes, ciphertext {} bytes, shared secret {} bytes",
            kp.public_key.serialize().len(),
            ct.len(),
            ss1.len()
        ))
    });

    let mut alice = Party::new(rng, None)?;
    let mut bob = Party::new(rng, None)?;
    let (alice_addr, bob_addr) = (alice.address.clone(), bob.address.clone());

    #[allow(unused_assignments)]
    let mut bob_bundle: Option<PreKeyBundle> = None;
    step!(report, "pqxdh.publish_bundle_with_kyber", {
        let bundle = publish_bundle(&mut bob, rng).await?;
        ensure(bundle.kyber_pre_key_public().is_ok(), "bundle lacks kyber prekey")?;
        bob_bundle = Some(bundle);
        Ok("signed prekey + one-time prekey + Kyber1024 prekey".into())
    });

    step!(report, "pqxdh.process_prekey_bundle", {
        process_prekey_bundle(
            &bob_addr,
            &alice_addr,
            &mut alice.store.session_store,
            &mut alice.store.identity_store,
            bob_bundle.as_ref().ok_or("no bundle")?,
            clock::now(),
            rng,
        )
        .await
        .map_err(ctx("process_prekey_bundle"))?;
        Ok("Alice built an outgoing session from Bob's bundle".into())
    });

    step!(report, "session.first_message_is_prekey_message", {
        let kind = exchange(&mut alice, &mut bob, "hello bob (1)", rng).await?;
        ensure(kind == CiphertextMessageType::PreKey, "first message not a PreKeySignalMessage")?;
        Ok("PreKeySignalMessage decrypted by Bob".into())
    });

    step!(report, "session.reply_is_signal_message", {
        let kind = exchange(&mut bob, &mut alice, "hi alice (1)", rng).await?;
        ensure(kind == CiphertextMessageType::Whisper, "reply not a SignalMessage")?;
        Ok("SignalMessage decrypted by Alice".into())
    });

    step!(report, "session.pqxdh_and_spqr_in_use", {
        let required =
            SessionUsabilityRequirements::EstablishedWithPqxdh | SessionUsabilityRequirements::Spqr;
        for (p, peer, who) in [(&alice, &bob_addr, "alice"), (&bob, &alice_addr, "bob")] {
            let rec = p
                .store
                .load_session(peer)
                .await
                .map_err(ctx("load"))?
                .ok_or("no session")?;
            ensure(
                rec.has_usable_sender_chain(clock::now(), required)
                    .map_err(ctx("usability"))?,
                format!("{who}'s session does not satisfy PQXDH+SPQR"),
            )?;
            ensure(
                rec.session_version().map_err(ctx("version"))? == 4,
                format!("{who}'s session version is not 4"),
            )?;
        }
        Ok("both sessions: version 4, EstablishedWithPqxdh + Spqr".into())
    });

    step!(report, "session.evolution_40_messages", {
        let before = session_bytes(&alice, &bob_addr).await?;
        for i in 0..20 {
            exchange(&mut alice, &mut bob, &format!("a->b round {i} {}", rng.random::<u64>()), rng).await?;
            exchange(&mut bob, &mut alice, &format!("b->a round {i} {}", rng.random::<u64>()), rng).await?;
        }
        let after = session_bytes(&alice, &bob_addr).await?;
        ensure(before != after, "session state did not change")?;
        Ok(format!(
            "40 alternating messages; session record {} -> {} bytes",
            before.len(),
            after.len()
        ))
    });

    step!(report, "session.out_of_order_delivery", {
        let mut wires = Vec::new();
        for i in 0..6 {
            let text = format!("burst {i}");
            wires.push((text.clone(), send(&mut alice, &bob_addr, text.as_bytes(), rng).await?));
        }
        for idx in [3usize, 0, 5, 1, 4, 2] {
            let (text, wire) = &wires[idx];
            let plain = receive(&mut bob, &alice_addr, wire, rng).await?;
            ensure(plain == text.as_bytes(), format!("mismatch at {idx}"))?;
        }
        exchange(&mut bob, &mut alice, "ack burst", rng).await?;
        Ok("6 messages decrypted in order [3,0,5,1,4,2]".into())
    });

    step!(report, "persistence.serialize_and_restore_sessions", {
        let a = snapshot(&alice, &bob_addr).await?;
        let b = snapshot(&bob, &alice_addr).await?;
        let total = a.identity.len() + a.session.len() + b.identity.len() + b.session.len();
        alice = restore(&a).await?;
        bob = restore(&b).await?;
        for i in 0..5 {
            exchange(&mut alice, &mut bob, &format!("after restore a->b {i}"), rng).await?;
            exchange(&mut bob, &mut alice, &format!("after restore b->a {i}"), rng).await?;
        }
        Ok(format!(
            "rebuilt both stores from {total} serialized bytes; 10 more messages OK"
        ))
    });

    // Tampering: each variant must be rejected, and must not damage the
    // session (the untouched original still decrypts afterwards).
    let original = send(&mut alice, &bob_addr, b"tamper target", rng).await?;
    for (name, mutate) in [
        ("reject.flipped_mac_bit", 0usize),
        ("reject.flipped_body_bit", 1),
        ("reject.truncated", 2),
        ("reject.unknown_version", 3),
    ] {
        step!(report, name, {
            let mut w = original.clone();
            let n = w.bytes.len();
            match mutate {
                0 => w.bytes[n - 1] ^= 0x01,
                1 => w.bytes[n / 2] ^= 0x10,
                2 => w.bytes.truncate(n / 2),
                _ => w.bytes[0] = 0x22,
            }
            expect_rejected(&mut bob, &alice_addr, &w, rng).await
        });
    }

    step!(report, "accept.original_after_rejections", {
        let plain = receive(&mut bob, &alice_addr, &original, rng).await?;
        ensure(plain == b"tamper target", "plaintext mismatch")?;
        Ok("session state intact after rejected messages".into())
    });

    step!(report, "reject.replayed_message", {
        match receive(&mut bob, &alice_addr, &original, rng).await {
            Err(err) => Ok(format!("replay rejected ({err})")),
            Ok(_) => Err("replayed message was accepted".into()),
        }
    });

    step!(report, "reject.tampered_prekey_message", {
        let mut carol = Party::new(rng, None)?;
        let mut dave = Party::new(rng, None)?;
        let (carol_addr, dave_addr) = (carol.address.clone(), dave.address.clone());
        let bundle = publish_bundle(&mut dave, rng).await?;
        process_prekey_bundle(
            &dave_addr,
            &carol_addr,
            &mut carol.store.session_store,
            &mut carol.store.identity_store,
            &bundle,
            clock::now(),
            rng,
        )
        .await
        .map_err(ctx("process bundle"))?;
        let w = send(&mut carol, &dave_addr, b"first contact", rng).await?;
        ensure(w.kind == CiphertextMessageType::PreKey, "not a prekey message")?;
        let mut bad = w.clone();
        let n = bad.bytes.len();
        bad.bytes[n - 3] ^= 0x04;
        let stage = expect_rejected(&mut dave, &carol_addr, &bad, rng).await?;
        let plain = receive(&mut dave, &carol_addr, &w, rng).await?;
        ensure(plain == b"first contact", "original prekey message failed after rejection")?;
        Ok(format!("{stage}; untampered original then accepted"))
    });

    // Sealed sender with a synthetic trust root (production clients verify
    // against Signal's server trust roots instead).
    let trust_root = KeyPair::generate(rng);
    let server_key = KeyPair::generate(rng);
    let alice_identity = alice
        .store
        .get_identity_key_pair()
        .await
        .map_err(ctx("identity"))?;
    let expires = Timestamp::from_epoch_millis(clock::now_millis() + 86_400_000);
    let server_cert = ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, rng)
        .map_err(ctx("server cert"))?;
    let sender_cert = SenderCertificate::new(
        alice_addr.name().to_owned(),
        None,
        *alice_identity.public_key(),
        alice_addr.device_id(),
        expires,
        server_cert,
        &server_key.private_key,
        rng,
    )
    .map_err(ctx("sender cert"))?;

    async fn sealed(
        from: &mut Party,
        to: &ProtocolAddress,
        cert: &SenderCertificate,
        text: &[u8],
        rng: &mut ThreadRng,
    ) -> R<Vec<u8>> {
        sealed_sender_encrypt(
            to,
            cert,
            text,
            &mut from.store.session_store,
            &mut from.store.identity_store,
            clock::now(),
            rng,
        )
        .await
        .map_err(ctx("sealed_sender_encrypt"))
    }

    async fn unseal(to: &mut Party, ct: &[u8], root: &PublicKey, at_millis: u64) -> R<SealedSenderDecryptionResult> {
        sealed_sender_decrypt(
            ct,
            root,
            Timestamp::from_epoch_millis(at_millis),
            None,
            to.address.name().to_owned(),
            to.address.device_id(),
            &mut to.store.identity_store,
            &mut to.store.session_store,
            &mut to.store.pre_key_store,
            &to.store.signed_pre_key_store,
            &mut to.store.kyber_pre_key_store,
        )
        .await
        .map_err(ctx("sealed_sender_decrypt"))
    }

    step!(report, "sealed_sender.roundtrip", {
        let ct = sealed(&mut alice, &bob_addr, &sender_cert, b"sealed hello", rng).await?;
        let res = unseal(&mut bob, &ct, &trust_root.public_key, clock::now_millis()).await?;
        ensure(res.message == b"sealed hello", "plaintext mismatch")?;
        ensure(res.sender_uuid == alice_addr.name(), "sender uuid mismatch")?;
        ensure(res.device_id == alice_addr.device_id(), "sender device mismatch")?;
        Ok(format!("{} byte envelope; sender certificate verified", ct.len()))
    });

    step!(report, "sealed_sender.reject_untrusted_root", {
        let ct = sealed(&mut alice, &bob_addr, &sender_cert, b"wrong root", rng).await?;
        let other_root = KeyPair::generate(rng);
        match unseal(&mut bob, &ct, &other_root.public_key, clock::now_millis()).await {
            Ok(_) => Err("accepted certificate from untrusted root".into()),
            Err(err) => {
                let res = unseal(&mut bob, &ct, &trust_root.public_key, clock::now_millis()).await?;
                ensure(res.message == b"wrong root", "retry with correct root failed")?;
                Ok(format!("rejected ({err}); same envelope accepted with the correct root"))
            }
        }
    });

    step!(report, "sealed_sender.reject_expired_certificate", {
        let ct = sealed(&mut alice, &bob_addr, &sender_cert, b"expired", rng).await?;
        match unseal(&mut bob, &ct, &trust_root.public_key, expires.epoch_millis() + 1).await {
            Ok(_) => Err("accepted expired sender certificate".into()),
            Err(err) => Ok(format!("rejected ({err})")),
        }
    });

    step!(report, "sealed_sender.reject_tampered_envelope", {
        let mut ct = sealed(&mut alice, &bob_addr, &sender_cert, b"tamper", rng).await?;
        let n = ct.len();
        ct[n / 2] ^= 0x01;
        match unseal(&mut bob, &ct, &trust_root.public_key, clock::now_millis()).await {
            Ok(_) => Err("accepted tampered envelope".into()),
            Err(err) => Ok(format!("rejected ({err})")),
        }
    });

    step!(report, "identity.reject_changed_identity_key", {
        let mut bob_reinstalled = Party::new(rng, Some(bob_addr.clone()))?;
        let bundle = publish_bundle(&mut bob_reinstalled, rng).await?;
        match process_prekey_bundle(
            &bob_addr,
            &alice_addr,
            &mut alice.store.session_store,
            &mut alice.store.identity_store,
            &bundle,
            clock::now(),
            rng,
        )
        .await
        {
            Err(SignalProtocolError::UntrustedIdentity(_)) => {
                Ok("UntrustedIdentity raised for a changed identity key".into())
            }
            Err(err) => Err(format!("unexpected error: {err}")),
            Ok(()) => Err("changed identity key silently accepted".into()),
        }
    });

    Ok(())
}
