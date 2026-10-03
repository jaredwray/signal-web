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

/// Decrypts and keeps libsignal's error variant, so checks can assert *why*
/// a message was rejected.
async fn decrypt_raw(
    to: &mut Party,
    from: &ProtocolAddress,
    msg: &CiphertextMessage,
    rng: &mut ThreadRng,
) -> std::result::Result<Vec<u8>, SignalProtocolError> {
    message_decrypt(
        msg,
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
}

async fn receive(
    to: &mut Party,
    from: &ProtocolAddress,
    w: &Wire,
    rng: &mut ThreadRng,
) -> R<Vec<u8>> {
    let msg = parse(w)?;
    decrypt_raw(to, from, &msg, rng)
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
    ensure(
        plain == text.as_bytes(),
        format!("plaintext mismatch for {text:?}"),
    )?;
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
async fn expect_rejected(
    to: &mut Party,
    from: &ProtocolAddress,
    w: &Wire,
    rng: &mut ThreadRng,
) -> R<String> {
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
        ensure(
            identity.public_key().verify_signature(msg, &sig),
            "valid signature rejected",
        )?;
        let mut bad = sig.to_vec();
        bad[10] ^= 1;
        ensure(
            !identity.public_key().verify_signature(msg, &bad),
            "tampered signature accepted",
        )?;
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
        let kyber = bundle.kyber_pre_key_public().map_err(ctx("kyber prekey"))?;
        ensure(
            kyber.key_type() == kem::KeyType::Kyber1024,
            "kyber prekey is not Kyber1024",
        )?;
        let signature = bundle
            .kyber_pre_key_signature()
            .map_err(ctx("kyber prekey signature"))?;
        ensure(
            bundle
                .identity_key()
                .map_err(ctx("identity key"))?
                .public_key()
                .verify_signature(&kyber.serialize(), signature),
            "kyber prekey signature does not verify under the identity key",
        )?;
        bob_bundle = Some(bundle);
        Ok("signed prekey + one-time prekey + Kyber1024 prekey signed by the identity key".into())
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
        ensure(
            kind == CiphertextMessageType::PreKey,
            "first message not a PreKeySignalMessage",
        )?;
        Ok("PreKeySignalMessage decrypted by Bob".into())
    });

    step!(report, "session.reply_is_signal_message", {
        let kind = exchange(&mut bob, &mut alice, "hi alice (1)", rng).await?;
        ensure(
            kind == CiphertextMessageType::Whisper,
            "reply not a SignalMessage",
        )?;
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
            exchange(
                &mut alice,
                &mut bob,
                &format!("a->b round {i} {}", rng.random::<u64>()),
                rng,
            )
            .await?;
            exchange(
                &mut bob,
                &mut alice,
                &format!("b->a round {i} {}", rng.random::<u64>()),
                rng,
            )
            .await?;
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
            wires.push((
                text.clone(),
                send(&mut alice, &bob_addr, text.as_bytes(), rng).await?,
            ));
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
            exchange(
                &mut alice,
                &mut bob,
                &format!("after restore a->b {i}"),
                rng,
            )
            .await?;
            exchange(
                &mut bob,
                &mut alice,
                &format!("after restore b->a {i}"),
                rng,
            )
            .await?;
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
        match decrypt_raw(&mut bob, &alice_addr, &parse(&original)?, rng).await {
            Err(err @ SignalProtocolError::DuplicatedMessage(..)) => {
                Ok(format!("replay rejected as DuplicatedMessage ({err})"))
            }
            Err(err) => Err(format!("replay rejected for an unexpected reason: {err}")),
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
        ensure(
            w.kind == CiphertextMessageType::PreKey,
            "not a prekey message",
        )?;
        let mut bad = w.clone();
        let n = bad.bytes.len();
        bad.bytes[n - 3] ^= 0x04;
        let stage = expect_rejected(&mut dave, &carol_addr, &bad, rng).await?;
        let plain = receive(&mut dave, &carol_addr, &w, rng).await?;
        ensure(
            plain == b"first contact",
            "original prekey message failed after rejection",
        )?;
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
    let server_cert =
        ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, rng)
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

    async fn unseal_raw(
        to: &mut Party,
        ct: &[u8],
        root: &PublicKey,
        at_millis: u64,
    ) -> std::result::Result<SealedSenderDecryptionResult, SignalProtocolError> {
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
    }

    async fn unseal(
        to: &mut Party,
        ct: &[u8],
        root: &PublicKey,
        at_millis: u64,
    ) -> R<SealedSenderDecryptionResult> {
        unseal_raw(to, ct, root, at_millis)
            .await
            .map_err(ctx("sealed_sender_decrypt"))
    }

    step!(report, "sealed_sender.roundtrip", {
        let ct = sealed(&mut alice, &bob_addr, &sender_cert, b"sealed hello", rng).await?;
        let res = unseal(&mut bob, &ct, &trust_root.public_key, clock::now_millis()).await?;
        ensure(res.message == b"sealed hello", "plaintext mismatch")?;
        ensure(res.sender_uuid == alice_addr.name(), "sender uuid mismatch")?;
        ensure(
            res.device_id == alice_addr.device_id(),
            "sender device mismatch",
        )?;
        Ok(format!(
            "{} byte envelope; sender certificate verified",
            ct.len()
        ))
    });

    step!(report, "sealed_sender.reject_untrusted_root", {
        let ct = sealed(&mut alice, &bob_addr, &sender_cert, b"wrong root", rng).await?;
        let other_root = KeyPair::generate(rng);
        match unseal_raw(&mut bob, &ct, &other_root.public_key, clock::now_millis()).await {
            Ok(_) => Err("accepted certificate from untrusted root".into()),
            Err(err @ SignalProtocolError::InvalidSealedSenderMessage(_)) => {
                let res =
                    unseal(&mut bob, &ct, &trust_root.public_key, clock::now_millis()).await?;
                ensure(
                    res.message == b"wrong root",
                    "retry with correct root failed",
                )?;
                Ok(format!(
                    "rejected as InvalidSealedSenderMessage ({err}); same envelope accepted with the correct root"
                ))
            }
            Err(err) => Err(format!("rejected for an unexpected reason: {err}")),
        }
    });

    step!(report, "sealed_sender.reject_expired_certificate", {
        let ct = sealed(&mut alice, &bob_addr, &sender_cert, b"expired", rng).await?;
        match unseal_raw(
            &mut bob,
            &ct,
            &trust_root.public_key,
            expires.epoch_millis() + 1,
        )
        .await
        {
            Ok(_) => Err("accepted expired sender certificate".into()),
            Err(err @ SignalProtocolError::InvalidSealedSenderMessage(_)) => {
                // Same envelope, same root, 2 ms earlier: must be accepted, so
                // the rejection above was caused by the expiry alone.
                let res = unseal(
                    &mut bob,
                    &ct,
                    &trust_root.public_key,
                    expires.epoch_millis() - 1,
                )
                .await?;
                ensure(res.message == b"expired", "plaintext mismatch")?;
                Ok(format!(
                    "rejected 1 ms after expiry as InvalidSealedSenderMessage (libsignal's message for any certificate validation failure: {err}); accepted 1 ms before expiry"
                ))
            }
            Err(err) => Err(format!("rejected for an unexpected reason: {err}")),
        }
    });

    step!(report, "sealed_sender.reject_tampered_envelope", {
        let ct = sealed(&mut alice, &bob_addr, &sender_cert, b"tamper", rng).await?;
        let mut bad = ct.clone();
        let n = bad.len();
        bad[n / 2] ^= 0x01;
        match unseal_raw(&mut bob, &bad, &trust_root.public_key, clock::now_millis()).await {
            Ok(_) => Err("accepted tampered envelope".into()),
            Err(err) => {
                // The untampered envelope must still decrypt, so the rejection
                // was caused by the flipped bit.
                let res =
                    unseal(&mut bob, &ct, &trust_root.public_key, clock::now_millis()).await?;
                ensure(res.message == b"tamper", "plaintext mismatch")?;
                Ok(format!(
                    "rejected ({err}); untampered envelope then accepted"
                ))
            }
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

// ---------------------------------------------------------------------------
// Linked-device provisioning (local). Uses synthetic frames and an
// independent test vector produced by scripts/make_provisioning_vector.py.
// ---------------------------------------------------------------------------

use crate::provisioning::{self, ProvisioningError, ProvisioningSession, proto as pproto};
use base64::Engine as _;
use prost::Message as _;

#[derive(serde::Deserialize)]
struct Vector {
    recipient_private_key_hex: String,
    recipient_public_key_hex: String,
    envelope_hex: String,
    expected: VectorExpected,
}

#[derive(serde::Deserialize)]
struct VectorExpected {
    aci: String,
    number: String,
    provisioning_code: String,
    profile_key_hex: String,
    account_entropy_pool: String,
    aci_identity_public_hex: String,
}

fn server_frame(id: u64, path: &str, body: Vec<u8>) -> Vec<u8> {
    pproto::WebSocketMessage {
        r#type: Some(pproto::TYPE_REQUEST),
        request: Some(pproto::WebSocketRequestMessage {
            verb: Some("PUT".into()),
            path: Some(path.into()),
            body: Some(body),
            headers: Vec::new(),
            id: Some(id),
        }),
        response: None,
    }
    .encode_to_vec()
}

fn check_ack(ack_b64: &str, id: u64) -> R<()> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(ack_b64)
        .map_err(ctx("ack base64"))?;
    let msg = pproto::WebSocketMessage::decode(bytes.as_slice()).map_err(ctx("ack decode"))?;
    let resp = msg.response.ok_or("ack has no response")?;
    ensure(
        msg.r#type == Some(pproto::TYPE_RESPONSE),
        "ack is not a RESPONSE",
    )?;
    ensure(
        resp.id == Some(id) && resp.status == Some(200),
        "ack id/status mismatch",
    )
}

fn percent_decode(s: &str) -> R<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).map_err(ctx("percent"))?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(ctx("utf8"))
}

fn tamper_envelope(
    envelope: &[u8],
    f: impl FnOnce(&mut pproto::ProvisionEnvelope) -> Option<()>,
) -> R<Vec<u8>> {
    let mut env = pproto::ProvisionEnvelope::decode(envelope).map_err(ctx("vector envelope"))?;
    f(&mut env).ok_or("vector envelope is too short to tamper with")?;
    Ok(env.encode_to_vec())
}

fn address_frame(id: u64, address: &str) -> Vec<u8> {
    server_frame(
        id,
        "/v1/address",
        pproto::ProvisioningAddress {
            address: Some(address.into()),
        }
        .encode_to_vec(),
    )
}

/// (check name, tampered envelope, recipient key, expected rejection)
type TamperCase<'a> = (
    &'static str,
    Vec<u8>,
    &'a PrivateKey,
    fn(&ProvisioningError) -> bool,
);

pub async fn run_provisioning(vector_json: &str) -> Report {
    let mut report = Report {
        kind: "local-provisioning-selftest",
        label: "LOCAL provisioning (QR linking) crypto/framing test; synthetic data, not a live Signal test",
        libsignal_core_version: libsignal_core::VERSION,
        passed: 0,
        failed: 0,
        aborted: None,
        checks: Vec::new(),
    };
    if let Err(err) = run_provisioning_inner(&mut report, vector_json).await {
        report.aborted = Some(err);
    }
    report
}

async fn run_provisioning_inner(report: &mut Report, vector_json: &str) -> R<()> {
    step!(report, "provisioning.qr_withheld_until_server_address", {
        let session = ProvisioningSession::new();
        ensure(
            session.link_qr_svg().is_none(),
            "QR produced before the server assigned an address",
        )?;
        Ok("no QR code is produced before a ProvisioningAddress arrives".into())
    });

    step!(report, "provisioning.address_frame_link_url_and_ack", {
        let mut session = ProvisioningSession::new();
        let frame = address_frame(7, "Ab+cd/ef==");
        let provisioning::FrameEvent::Address { link_url, ack_b64 } =
            session.handle(&frame).map_err(ctx("handle"))?
        else {
            return Err("expected an Address event".into());
        };
        check_ack(&ack_b64, 7)?;
        let prefix = "sgnl://linkdevice?uuid=Ab%2Bcd%2Fef%3D%3D&pub_key=";
        ensure(
            link_url.starts_with(prefix),
            format!("unexpected URL {link_url}"),
        )?;
        ensure(
            link_url.ends_with("&capabilities=nopni"),
            "capabilities missing",
        )?;
        let pub_key = &link_url[prefix.len()..link_url.len() - "&capabilities=nopni".len()];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(percent_decode(pub_key)?)
            .map_err(ctx("pub_key base64"))?;
        ensure(
            decoded == session.public_key().serialize().to_vec(),
            "pub_key does not round-trip",
        )?;
        ensure(
            decoded.len() == 33 && decoded[0] == 0x05,
            "pub_key not a 33-byte typed Curve25519 key",
        )?;
        let svg = session.link_qr_svg().ok_or("no QR after address")?;
        ensure(svg.contains("<svg"), "QR is not SVG")?;
        Ok(format!(
            "URL format matches Signal-Desktop linkDeviceRoute; QR SVG {} bytes; ack id 7 status 200",
            svg.len()
        ))
    });

    step!(report, "provisioning.roundtrip_envelope_frame", {
        let mut session = ProvisioningSession::new();
        let message = pproto::ProvisionMessage {
            aci: Some("00000000-0000-4000-8000-000000000001".into()),
            provisioning_code: Some("synthetic-code".into()),
            aci_identity_key_private: Some(vec![1; 32]),
            aci_identity_key_public: Some(vec![5; 33]),
            profile_key: Some(vec![2; 32]),
            provisioning_version: Some(1),
            ..Default::default()
        };
        let envelope = provisioning::encrypt_for_test(&session.public_key(), &message);
        session
            .handle(&address_frame(7, "synthetic-address"))
            .map_err(ctx("address"))?;
        let event = session
            .handle(&server_frame(8, "/v1/message", envelope))
            .map_err(ctx("handle"))?;
        let provisioning::FrameEvent::Provisioned { summary, ack_b64 } = event else {
            return Err("expected a Provisioned event".into());
        };
        check_ack(&ack_b64, 8)?;
        ensure(
            session.provisioned() == Some(&message),
            "decrypted message differs",
        )?;
        ensure(
            summary.has_provisioning_code && summary.has_aci_identity_key_pair,
            "summary incomplete",
        )?;
        Ok("envelope frame decrypted, acknowledged, secrets kept in WASM".into())
    });

    step!(report, "provisioning.reject_out_of_order_frames", {
        let message = pproto::ProvisionMessage {
            aci: Some("00000000-0000-4000-8000-000000000002".into()),
            ..Default::default()
        };
        let mut early = ProvisioningSession::new();
        let envelope = provisioning::encrypt_for_test(&early.public_key(), &message);
        ensure(
            early
                .handle(&server_frame(1, "/v1/message", envelope.clone()))
                .is_err(),
            "message accepted before any address",
        )?;
        let mut session = ProvisioningSession::new();
        let envelope = provisioning::encrypt_for_test(&session.public_key(), &message);
        session
            .handle(&address_frame(1, "first"))
            .map_err(ctx("address"))?;
        ensure(
            session.handle(&address_frame(2, "second")).is_err(),
            "second address accepted",
        )?;
        session
            .handle(&server_frame(3, "/v1/message", envelope.clone()))
            .map_err(ctx("message"))?;
        ensure(
            session
                .handle(&server_frame(4, "/v1/message", envelope))
                .is_err(),
            "second message accepted",
        )?;
        Ok("message-before-address, second address and second message are rejected".into())
    });

    let vector: Vector = serde_json::from_str(vector_json).map_err(ctx("vector json"))?;
    let hexd = |s: &str| hex::decode(s).map_err(ctx("hex"));
    let private = PrivateKey::deserialize(&hexd(&vector.recipient_private_key_hex)?)
        .map_err(ctx("private key"))?;
    let public = private.public_key().map_err(ctx("public key"))?;
    let envelope = hexd(&vector.envelope_hex)?;

    step!(report, "provisioning.independent_python_vector", {
        ensure(
            public.serialize().to_vec() == hexd(&vector.recipient_public_key_hex)?,
            "recipient public key mismatch",
        )?;
        let m = provisioning::decrypt_envelope(&private, &envelope).map_err(ctx("decrypt"))?;
        let e = &vector.expected;
        ensure(m.aci.as_deref() == Some(e.aci.as_str()), "aci")?;
        ensure(m.number.as_deref() == Some(e.number.as_str()), "number")?;
        ensure(
            m.provisioning_code.as_deref() == Some(e.provisioning_code.as_str()),
            "provisioning code",
        )?;
        ensure(
            m.profile_key.as_deref() == Some(hexd(&e.profile_key_hex)?.as_slice()),
            "profile key",
        )?;
        ensure(
            m.account_entropy_pool.as_deref() == Some(e.account_entropy_pool.as_str()),
            "AEP",
        )?;
        let id_pub = hexd(&e.aci_identity_public_hex)?;
        ensure(
            m.aci_identity_key_public.as_deref() == Some(id_pub.as_slice()),
            "identity public",
        )?;
        // The shared identity private key must match the shared public key.
        let id_priv = PrivateKey::deserialize(
            m.aci_identity_key_private
                .as_deref()
                .ok_or("no identity private")?,
        )
        .map_err(ctx("identity private"))?;
        ensure(
            id_priv
                .public_key()
                .map_err(ctx("derive"))?
                .serialize()
                .to_vec()
                == id_pub,
            "identity key pair inconsistent",
        )?;
        let aci_binary = m.aci_binary.as_deref().ok_or("no aciBinary")?;
        ensure(
            hex::encode(aci_binary) == e.aci.replace('-', ""),
            "aciBinary",
        )?;
        Ok(format!(
            "{}-byte envelope from a separate Python implementation decrypted; all fields match",
            envelope.len()
        ))
    });

    let other = KeyPair::generate(&mut rand::rng());
    let cases: [TamperCase<'_>; 6] = [
        (
            "provisioning.reject_flipped_mac",
            tamper_envelope(&envelope, |e| {
                *e.body.as_mut()?.last_mut()? ^= 1;
                Some(())
            })?,
            &private,
            |e| *e == ProvisioningError::BadMac,
        ),
        (
            "provisioning.reject_flipped_ciphertext",
            tamper_envelope(&envelope, |e| {
                *e.body.as_mut()?.get_mut(20)? ^= 1;
                Some(())
            })?,
            &private,
            |e| *e == ProvisioningError::BadMac,
        ),
        (
            "provisioning.reject_unknown_version",
            tamper_envelope(&envelope, |e| {
                *e.body.as_mut()?.first_mut()? = 2;
                Some(())
            })?,
            &private,
            |e| *e == ProvisioningError::BadVersion(2),
        ),
        (
            "provisioning.reject_truncated_body",
            tamper_envelope(&envelope, |e| {
                e.body.as_mut()?.truncate(40);
                Some(())
            })?,
            &private,
            |e| matches!(e, ProvisioningError::Envelope(_)),
        ),
        (
            "provisioning.reject_substituted_sender_key",
            tamper_envelope(&envelope, |e| {
                e.public_key = Some(
                    KeyPair::generate(&mut rand::rng())
                        .public_key
                        .serialize()
                        .to_vec(),
                );
                Some(())
            })?,
            &private,
            |e| *e == ProvisioningError::BadMac,
        ),
        (
            "provisioning.reject_wrong_recipient",
            envelope.clone(),
            &other.private_key,
            |e| *e == ProvisioningError::BadMac,
        ),
    ];
    for (name, bytes, key, expected) in cases {
        step!(report, name, {
            match provisioning::decrypt_envelope(key, &bytes) {
                Ok(_) => Err("tampered envelope was ACCEPTED".into()),
                Err(err) if expected(&err) => Ok(format!("rejected ({err})")),
                Err(err) => Err(format!("rejected for an unexpected reason: {err}")),
            }
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LocalConversation: two synthetic parties whose libsignal state can be
// snapshotted to bytes and restored. Used by web/storage-test.html to persist
// real ratchet state in encrypted IndexedDB and resume after a browser restart.
// LOCAL only: both parties live in this page.
// ---------------------------------------------------------------------------

use futures_util::FutureExt as _;
use wasm_bindgen::prelude::*;

fn now_or_fail<F: std::future::Future>(f: F) -> F::Output {
    // libsignal's in-memory stores never actually suspend.
    f.now_or_never()
        .expect("in-memory store futures complete immediately")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SnapshotWire {
    name: String,
    device: u32,
    identity_hex: String,
    registration_id: u32,
    peer_name: String,
    peer_device: u32,
    peer_identity_hex: String,
    session_hex: String,
}

impl SnapshotWire {
    fn from(s: &Snapshot) -> Self {
        Self {
            name: s.address.name().to_owned(),
            device: u32::from(s.address.device_id()),
            identity_hex: hex::encode(&s.identity),
            registration_id: s.registration_id,
            peer_name: s.peer.name().to_owned(),
            peer_device: u32::from(s.peer.device_id()),
            peer_identity_hex: hex::encode(&s.peer_identity),
            session_hex: hex::encode(&s.session),
        }
    }

    fn into_snapshot(self) -> R<Snapshot> {
        let dev = |d: u32| DeviceId::try_from(d).map_err(|_| "invalid device id".to_string());
        Ok(Snapshot {
            address: ProtocolAddress::new(self.name, dev(self.device)?),
            identity: hex::decode(self.identity_hex).map_err(ctx("hex"))?,
            registration_id: self.registration_id,
            peer: ProtocolAddress::new(self.peer_name, dev(self.peer_device)?),
            peer_identity: hex::decode(self.peer_identity_hex).map_err(ctx("hex"))?,
            session: hex::decode(self.session_hex).map_err(ctx("hex"))?,
        })
    }
}

#[wasm_bindgen]
pub struct LocalConversation {
    alice: Party,
    bob: Party,
}

#[wasm_bindgen]
impl LocalConversation {
    /// Two fresh synthetic identities with an established PQXDH/SPQR session.
    pub fn create() -> Result<LocalConversation, JsError> {
        let mut rng = rand::rng();
        let mut alice = Party::new(&mut rng, None).map_err(|e| JsError::new(&e))?;
        let mut bob = Party::new(&mut rng, None).map_err(|e| JsError::new(&e))?;
        let bundle =
            now_or_fail(publish_bundle(&mut bob, &mut rng)).map_err(|e| JsError::new(&e))?;
        let (alice_addr, bob_addr) = (alice.address.clone(), bob.address.clone());
        now_or_fail(process_prekey_bundle(
            &bob_addr,
            &alice_addr,
            &mut alice.store.session_store,
            &mut alice.store.identity_store,
            &bundle,
            clock::now(),
            &mut rng,
        ))
        .map_err(|e| JsError::new(&e.to_string()))?;
        let mut conv = LocalConversation { alice, bob };
        conv.alice_to_bob("hello")?;
        conv.bob_to_alice("hi")?;
        Ok(conv)
    }

    /// Restores both parties from `snapshot()` bytes.
    #[wasm_bindgen(js_name = fromSnapshot)]
    pub fn from_snapshot(bytes: &[u8]) -> Result<LocalConversation, JsError> {
        let (a, b): (SnapshotWire, SnapshotWire) =
            serde_json::from_slice(bytes).map_err(|e| JsError::new(&format!("snapshot: {e}")))?;
        let restore_one =
            |w: SnapshotWire| -> R<Party> { now_or_fail(restore(&w.into_snapshot()?)) };
        Ok(LocalConversation {
            alice: restore_one(a).map_err(|e| JsError::new(&e))?,
            bob: restore_one(b).map_err(|e| JsError::new(&e))?,
        })
    }

    /// Serialized identity keys, registration ids and session records.
    /// Contains private key material: callers must encrypt it before storing.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsError> {
        let a =
            now_or_fail(snapshot(&self.alice, &self.bob.address)).map_err(|e| JsError::new(&e))?;
        let b =
            now_or_fail(snapshot(&self.bob, &self.alice.address)).map_err(|e| JsError::new(&e))?;
        serde_json::to_vec(&(SnapshotWire::from(&a), SnapshotWire::from(&b)))
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Encrypts as Alice, decrypts as Bob, returns Bob's plaintext.
    #[wasm_bindgen(js_name = aliceToBob)]
    pub fn alice_to_bob(&mut self, text: &str) -> Result<String, JsError> {
        self.send(true, text)
    }

    #[wasm_bindgen(js_name = bobToAlice)]
    pub fn bob_to_alice(&mut self, text: &str) -> Result<String, JsError> {
        self.send(false, text)
    }

    /// Hex of Alice's current session record, to show the ratchet advancing.
    #[wasm_bindgen(js_name = aliceSessionDigest)]
    pub fn alice_session_digest(&self) -> Result<String, JsError> {
        use sha2::Digest as _;
        let bytes = now_or_fail(session_bytes(&self.alice, &self.bob.address))
            .map_err(|e| JsError::new(&e))?;
        Ok(hex::encode(&sha2::Sha256::digest(&bytes)[..8]))
    }
}

impl LocalConversation {
    fn send(&mut self, alice_sends: bool, text: &str) -> Result<String, JsError> {
        let mut rng = rand::rng();
        let (from, to) = if alice_sends {
            (&mut self.alice, &mut self.bob)
        } else {
            (&mut self.bob, &mut self.alice)
        };
        let (from_addr, to_addr) = (from.address.clone(), to.address.clone());
        let wire = now_or_fail(send(from, &to_addr, text.as_bytes(), &mut rng))
            .map_err(|e| JsError::new(&e))?;
        let plain =
            now_or_fail(receive(to, &from_addr, &wire, &mut rng)).map_err(|e| JsError::new(&e))?;
        String::from_utf8(plain).map_err(|e| JsError::new(&e.to_string()))
    }
}
