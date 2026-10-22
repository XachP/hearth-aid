//! Shared harness for the Hearth tests and the narrated demo.
//!
//! It plays the client side of every role the way a real wallet would:
//! * the **operator** (NGO) builds confidential grants, encrypts each grant notice to the family and
//!   the treasury change back to itself, so its treasury can be recovered from the chain alone;
//! * the **household** scans its wallet and decrypts its own grant notice (amount, mask, memo);
//! * the **auditor** (donor-appointed) decrypts every amount with the view key and reconciles;
//! * a **verifier** (landlord, clinic, merchant) checks a single grant opening against the chain.
#![allow(dead_code)]

use std::collections::BTreeMap;

use tari_template_test_tooling::{
    TemplateTest,
    byte_type::{FromByteType, ToByteType},
    crypto::{PublicKey as _, RistrettoPublicKey, RistrettoSecretKey, SecretKey as _},
    engine_types::{
        commit_result::ExecuteResult,
        confidential::MIN_CONFIDENTIAL_OUTPUT_VALUE_PROMISE,
        crypto::{ElgamalVerifiableBalance, OutputBody, ValueLookup, commit_amount},
    },
    support::{GenerateValueLookup, confidential::generate_withdraw_proof_with_view_key, value_proof::value_proofs_for_commitment},
    template_lib_types::{
        Amount,
        ComponentAddress,
        ConfidentialOutputAddress,
        ResourceAddress,
        confidential::{ConfidentialOutputStatement, ConfidentialWithdrawProof},
        crypto::{CommitmentValueProof, PedersenCommitmentBytes, RistrettoPublicKeyBytes},
    },
    transaction::{Transaction, args, builder::named_args::NamedArg},
    wallet_crypto::{MaskAndValue, OutputWitness, StealthCryptoApi, confidential, memo::Memo},
};

pub type ValueProofs = BTreeMap<PedersenCommitmentBytes, CommitmentValueProof>;

pub const BUDGET: u64 = 10_000;
pub const PROGRAMME: &str = "Riverside flood relief 2026";

/// Salted SHA-256 enrolment tag, as the NGO's registration tool would compute it off-chain.
pub fn tag(registration_id: &str) -> String {
    use std::fmt::Write;
    let h = sha256(format!("programme-salt-7f3a|{registration_id}").as_bytes());
    h.iter().fold(String::new(), |mut s, b| { let _ = write!(s, "{b:02x}"); s })
}

/// Tiny self-contained SHA-256 (keeps the test harness dependency-free).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    let mut h: [u32; 8] = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 { w[i] = u32::from_be_bytes([chunk[4*i], chunk[4*i+1], chunk[4*i+2], chunk[4*i+3]]); }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 { h[i] = h[i].wrapping_add(v[i]); }
    }
    let mut out = [0u8; 32];
    for i in 0..8 { out[4*i..4*i+4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

pub fn rng() -> impl rand::CryptoRng {
    rand::rng()
}

pub fn keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
    RistrettoPublicKey::random_keypair(&mut rand::rng())
}

/// A decrypted grant notice, as the family wallet recovers it from the chain.
#[derive(Debug, Clone)]
pub struct GrantNotice {
    pub commitment: PedersenCommitmentBytes,
    pub amount: u64,
    pub mask: RistrettoSecretKey,
    pub memo: Option<String>,
}

/// What a family hands to a landlord or clinic: the opening of one grant commitment.
#[derive(Debug, Clone)]
pub struct GrantProof {
    pub household: ComponentAddress,
    pub commitment: PedersenCommitmentBytes,
    pub amount: u64,
    pub mask: RistrettoSecretKey,
}

pub struct Family {
    pub account: ComponentAddress,
    pub secret: RistrettoSecretKey,
    pub public: RistrettoPublicKey,
    pub proof: tari_template_test_tooling::template_lib_types::NonFungibleAddress,
}

pub struct Programme {
    pub test: TemplateTest,
    pub hearth: ComponentAddress,
    pub resource: ResourceAddress,
    pub auditor_secret: RistrettoSecretKey,
    pub auditor_pk: RistrettoPublicKey,
    pub operator_secret: RistrettoSecretKey,
    pub operator_pk: RistrettoPublicKey,
    /// The operator wallet's view of the treasury: (mask, value) of each live commitment.
    pub treasury: Vec<(RistrettoSecretKey, u64)>,
}

/// Builds an output witness whose encrypted data is DH-encrypted to `recipient`.
pub fn sealed_witness(
    amount: u64,
    mask: &RistrettoSecretKey,
    recipient: &RistrettoPublicKey,
    memo: Option<&str>,
    view_key: &RistrettoPublicKey,
) -> OutputWitness {
    let (nonce_secret, nonce_public) = keypair();
    let memo = memo.map(|m| Memo::new_message(m).expect("memo fits"));
    let encrypted_data = StealthCryptoApi::new()
        .encrypt_value_and_mask(amount, mask, recipient, &nonce_secret, memo.as_ref())
        .expect("encrypt pay stub");
    OutputWitness {
        amount,
        mask: mask.clone(),
        sender_public_nonce: nonce_public,
        minimum_value_promise: MIN_CONFIDENTIAL_OUTPUT_VALUE_PROMISE,
        encrypted_data,
        resource_view_key: Some(view_key.clone()),
    }
}

/// Opening budget / top-up statement, encrypted to the operator so its wallet can recover it.
pub fn budget_statement(
    amount: u64,
    operator: &RistrettoPublicKey,
    view_key: &RistrettoPublicKey,
) -> (ConfidentialOutputStatement, RistrettoSecretKey, ValueProofs) {
    let mask = RistrettoSecretKey::random(&mut rand::rng());
    let witness = sealed_witness(amount, &mask, operator, Some("treasury"), view_key);
    let statement = confidential::create_output_statement(Some(&witness), Amount::zero(), None, Amount::zero())
        .expect("budget statement");
    let proofs = value_proofs_for_commitment(amount, &mask);
    (statement, mask, proofs)
}

pub fn setup() -> Programme {
    setup_with_budget(BUDGET)
}

pub fn setup_with_budget(budget: u64) -> Programme {
    let mut test = TemplateTest::my_crate();
    let (auditor_secret, auditor_pk) = keypair();
    let auditor_vk: RistrettoPublicKeyBytes = auditor_pk.to_byte_type();
    let operator_secret = test.secret_key().clone();
    let operator_pk = RistrettoPublicKey::from_secret_key(&operator_secret);

    let (statement, mask, proofs) = budget_statement(budget, &operator_pk, &auditor_pk);
    let hearth: ComponentAddress =
        test.call_function("Hearth", "new", args![PROGRAMME, auditor_vk, statement, proofs], vec![]);
    let resource: ResourceAddress = test.call_method(hearth, "aid_resource", args![], vec![]);

    Programme {
        test,
        hearth,
        resource,
        auditor_secret,
        auditor_pk,
        operator_secret,
        operator_pk,
        treasury: vec![(mask, budget)],
    }
}

impl Programme {
    pub fn new_household(&mut self) -> Family {
        let (account, proof, secret) = self.test.create_empty_account();
        let public = RistrettoPublicKey::from_secret_key(&secret);
        Family { account, secret, public, proof }
    }

    pub fn operator_tx(&mut self, method: &str, args: Vec<NamedArg>) -> ExecuteResult {
        let tx = self
            .test
            .transaction()
            .call_method(self.hearth, method, args)
            .build_and_seal(self.test.secret_key());
        let proof = self.test.owner_proof();
        self.test.execute_expect_success(tx, vec![proof])
    }

    pub fn operator_call(&mut self, method: &str, args: Vec<NamedArg>) {
        self.operator_tx(method, args);
    }

    pub fn operator_call_fails(&mut self, method: &str, args: Vec<NamedArg>) -> String {
        let tx = self
            .test
            .transaction()
            .call_method(self.hearth, method, args)
            .build_and_seal(self.test.secret_key());
        let proof = self.test.owner_proof();
        format!("{:?}", self.test.execute_expect_failure(tx, vec![proof]))
    }

    pub fn treasury_value(&self) -> u64 {
        self.treasury.iter().map(|(_, v)| v).sum()
    }

    /// Builds one fully confidential paycheck that spends the whole tracked treasury, pays
    /// `amount` to the household (notice encrypted to it) and returns change to the treasury
    /// (encrypted to the operator). Returns the proof, the paycheck mask and the change mask.
    pub fn build_grant(
        &self,
        household: &RistrettoPublicKey,
        amount: u64,
        memo: &str,
    ) -> (ConfidentialWithdrawProof, RistrettoSecretKey, RistrettoSecretKey, u64) {
        let total = self.treasury_value();
        let change = total.checked_sub(amount).expect("treasury too small");
        let pay_mask = RistrettoSecretKey::random(&mut rand::rng());
        let change_mask = RistrettoSecretKey::random(&mut rand::rng());
        let output = sealed_witness(amount, &pay_mask, household, Some(memo), &self.auditor_pk);
        let change_out = sealed_witness(change, &change_mask, &self.operator_pk, Some("treasury"), &self.auditor_pk);
        let inputs = self
            .treasury
            .iter()
            .map(|(mask, value)| MaskAndValue { value: *value, mask: mask.clone() })
            .collect::<Vec<_>>();
        let proof = confidential::create_withdraw_proof(
            &inputs,
            Amount::zero(),
            Some(&output),
            Amount::zero(),
            Some(&change_out),
            Amount::zero(),
        )
        .expect("withdraw proof");
        (proof, pay_mask, change_mask, change)
    }

    /// Pays one household with an encrypted grant notice. Returns the grant mask.
    pub fn grant(&mut self, family: &Family, amount: u64, memo: &str) -> RistrettoSecretKey {
        let (proof, pay_mask, change_mask, change) = self.build_grant(&family.public, amount, memo);
        self.operator_call("grant", args![family.account, proof]);
        self.treasury = vec![(change_mask, change)];
        pay_mask
    }

    pub fn enrol(&mut self, family: &Family, cohort: &str, registration_id: &str) {
        self.operator_call("enrol", args![family.account, cohort, tag(registration_id)]);
    }

    pub fn open_round(&mut self, label: &str) {
        self.operator_call("open_round", args![label]);
    }

    /// Builds the grants for a whole round, chaining treasury change from one to the next.
    pub fn build_round(&mut self, shift: &[(&Family, u64, &str)]) -> Vec<(ComponentAddress, ConfidentialWithdrawProof)> {
        let mut batch = Vec::new();
        for (family, amount, memo) in shift {
            let (proof, _pay_mask, change_mask, change) = self.build_grant(&family.public, *amount, memo);
            self.treasury = vec![(change_mask, change)];
            batch.push((family.account, proof));
        }
        batch
    }

    pub fn outputs_with_commitments(&self, component: ComponentAddress) -> Vec<(PedersenCommitmentBytes, OutputBody)> {
        let store = self.test.read_only_state_store();
        let mut out = Vec::new();
        for vault in store.get_vaults_for_component(component).unwrap().into_values() {
            if *vault.resource_address() != self.resource {
                continue;
            }
            for commitment in vault.get_confidential_commitments().into_iter().flatten() {
                let addr = ConfidentialOutputAddress::new(self.resource, *commitment);
                let body = store.get_confidential_output(addr).unwrap().into_output();
                out.push((*commitment, body));
            }
        }
        out
    }

    pub fn outputs_of(&self, component: ComponentAddress) -> Vec<OutputBody> {
        self.outputs_with_commitments(component).into_iter().map(|(_, b)| b).collect()
    }

    /// Auditor view: sum of all amounts in `component` decryptable with `key` (the view key).
    pub fn audit(&self, component: ComponentAddress, key: &RistrettoSecretKey) -> Option<u64> {
        decrypt_sum(&self.outputs_of(component), key, &GenerateValueLookup::new(0..=BUDGET * 4))
    }

    /// Auditor view, per commitment.
    pub fn audit_each(&self, component: ComponentAddress, key: &RistrettoSecretKey) -> Option<Vec<u64>> {
        self.outputs_of(component)
            .iter()
            .map(|o| decrypt_sum(std::slice::from_ref(o), key, &GenerateValueLookup::new(0..=BUDGET * 4)))
            .collect()
    }

    /// Wallet view: every pay stub in `component` that `secret` can open.
    pub fn read_notices(&self, component: ComponentAddress, secret: &RistrettoSecretKey) -> Vec<GrantNotice> {
        self.outputs_with_commitments(component)
            .into_iter()
            .filter_map(|(commitment, body)| {
                let nonce: RistrettoPublicKey = body.public_nonce.try_from_byte_type().ok()?;
                let decrypted = StealthCryptoApi::new()
                    .decrypt_utxo_data(&body.encrypted_data, &commitment, secret, &nonce, false)
                    .ok()?;
                Some(GrantNotice {
                    commitment,
                    amount: decrypted.mask_and_value.value,
                    mask: decrypted.mask_and_value.mask.clone(),
                    memo: decrypted.memo.as_ref().and_then(|m| m.as_memo_message().map(str::to_string)),
                })
            })
            .collect()
    }

    /// Rebuilds the operator's treasury bookkeeping from chain state and the operator key alone.
    pub fn recover_treasury_from_chain(&mut self) {
        let stubs = self.read_notices(self.hearth, &self.operator_secret.clone());
        self.treasury = stubs.into_iter().map(|s| (s.mask, s.amount)).collect();
    }

    /// Landlord / lender check: does this payslip open a commitment that really sits in the
    /// household wallet? Uses only public chain state plus the grant proof.
    pub fn verify_grant_proof(&self, slip: &GrantProof) -> bool {
        let Some(c) = commit_amount(&slip.mask, Amount::from(slip.amount)) else {
            return false;
        };
        let c: PedersenCommitmentBytes = c.to_byte_type();
        c == slip.commitment &&
            self.outputs_with_commitments(slip.household)
                .iter()
                .any(|(onchain, _)| *onchain == slip.commitment)
    }

    pub fn family_spend(
        &mut self,
        family: &Family,
        stub: &GrantNotice,
        amount: u64,
        to: ComponentAddress,
        to_pk: &RistrettoPublicKey,
    ) -> RistrettoSecretKey {
        let change = stub.amount - amount;
        let out_mask = RistrettoSecretKey::random(&mut rand::rng());
        let change_mask = RistrettoSecretKey::random(&mut rand::rng());
        let output = sealed_witness(amount, &out_mask, to_pk, Some("payment"), &self.auditor_pk);
        let change_out = sealed_witness(change, &change_mask, &family.public, Some("change"), &self.auditor_pk);
        let proof = confidential::create_withdraw_proof(
            &[MaskAndValue { value: stub.amount, mask: stub.mask.clone() }],
            Amount::zero(),
            Some(&output),
            Amount::zero(),
            Some(&change_out),
            Amount::zero(),
        )
        .unwrap();
        let tx = Transaction::builder_localnet(Default::default())
            .call_method(family.account, "withdraw_confidential", args![self.resource, proof])
            .put_last_instruction_output_on_workspace("pay")
            .call_method(to, "deposit", args![Workspace("pay")])
            .build_and_seal(&family.secret);
        self.test.execute_expect_success(tx, vec![family.proof.clone()]);
        out_mask
    }

    /// Old-style helper kept for the original tests: a paycheck with no encrypted stub.
    pub fn plain_grant(&self, amount: u64, revealed: u64) -> ConfidentialWithdrawProof {
        let (mask, value) = self.treasury[0].clone();
        generate_withdraw_proof_with_view_key(&mask, value, amount, Some(value - amount - revealed), revealed, &self.auditor_pk).proof
    }
}

pub fn decrypt_sum<L: ValueLookup>(outputs: &[OutputBody], key: &RistrettoSecretKey, lookup: &L) -> Option<u64> {
    let balances = outputs
        .iter()
        .filter_map(|o| o.viewable_balance.as_ref().map(|vb| vb.try_into().unwrap()))
        .collect::<Vec<ElgamalVerifiableBalance>>();
    if balances.is_empty() {
        return Some(0);
    }
    let decrypted = ElgamalVerifiableBalance::decrypt_many(key, &balances, lookup).ok()?;
    decrypted.into_iter().sum()
}
