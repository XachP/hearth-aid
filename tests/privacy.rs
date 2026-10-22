//! The privacy guarantees for families: encrypted grant notices, single-grant disclosure,
//! one-transaction rounds, and the public impact report. Every test runs against the real engine.

mod common;

use common::*;
use tari_template_test_tooling::{
    crypto::{RistrettoSecretKey, SecretKey as _},
    template_lib_types::{Amount, ComponentAddress},
    transaction::args,
};

#[test]
fn a_family_reads_its_own_grant_notice_from_the_chain() {
    let mut p = setup();
    let fam = p.new_household();
    p.enrol(&fam, "district-3", "REG-0001");
    p.open_round("Round 1");
    let mask = p.grant(&fam, 3_000, "Round 1: 3,000 for 6 people. Cash out at any partner agent.");
    let notices = p.read_notices(fam.account, &fam.secret.clone());
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].amount, 3_000);
    assert_eq!(notices[0].mask, mask);
    assert_eq!(notices[0].memo.as_deref(), Some("Round 1: 3,000 for 6 people. Cash out at any partner agent."));
}

#[test]
fn the_auditor_sees_amounts_but_never_the_private_notice() {
    let mut p = setup();
    let fam = p.new_household();
    p.enrol(&fam, "district-3", "REG-0001");
    p.open_round("Round 1");
    p.grant(&fam, 3_000, "protection case: relocation support");
    assert_eq!(p.audit(fam.account, &p.auditor_secret.clone()), Some(3_000));
    assert!(p.read_notices(fam.account, &p.auditor_secret.clone()).is_empty(), "notice stays sealed");
}

#[test]
fn neighbours_cannot_see_each_others_grants() {
    let mut p = setup();
    let a = p.new_household();
    let b = p.new_household();
    p.enrol(&a, "district-3", "REG-0001");
    p.enrol(&b, "district-3", "REG-0002");
    p.open_round("Round 1");
    p.grant(&a, 3_000, "a");
    p.grant(&b, 1_500, "b");
    assert!(p.read_notices(a.account, &b.secret.clone()).is_empty());
    assert!(p.read_notices(b.account, &a.secret.clone()).is_empty());
    assert_eq!(p.audit(a.account, &b.secret.clone()), None);
}

#[test]
fn a_whole_round_is_paid_atomically_with_one_count_only_event() {
    let mut p = setup();
    let fams: Vec<_> = (0..4).map(|_| p.new_household()).collect();
    for (i, f) in fams.iter().enumerate() {
        p.enrol(f, "district-3", &format!("REG-{i:04}"));
    }
    p.open_round("Round 1: winter kits");
    let amounts = [2_400u64, 900, 1_800, 1_200];
    let plan: Vec<(&Family, u64, &str)> = fams.iter().zip(amounts).map(|(f, a)| (f, a, "winter kit")).collect();
    let batch = p.build_round(&plan);
    let result = p.operator_tx("disburse_round", args![batch]);

    let ev: Vec<_> = result.finalize.events.iter().filter(|e| e.topic().ends_with("RoundDisbursed")).collect();
    assert_eq!(ev.len(), 1);
    let keys: Vec<&str> = ev[0].payload().iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, vec!["grants", "round"]);
    assert_eq!(ev[0].payload().get_str("grants"), Some("4"));
    for e in &result.finalize.events {
        let dump = format!("{:?}", e.payload());
        for a in amounts {
            assert!(!dump.contains(&a.to_string()), "event leaks an amount: {dump}");
        }
    }
    let in_round: u64 = p.test.call_method(p.hearth, "grants_in_round", args![1u64], vec![]);
    assert_eq!(in_round, 4);
    let total: u64 = fams.iter().map(|f| p.audit(f.account, &p.auditor_secret.clone()).unwrap()).sum();
    assert_eq!(total + p.audit(p.hearth, &p.auditor_secret.clone()).unwrap(), BUDGET);
}

#[test]
fn one_bad_grant_rejects_the_whole_round() {
    let mut p = setup();
    let a = p.new_household();
    let b = p.new_household();
    p.enrol(&a, "district-3", "REG-0001");
    p.enrol(&b, "district-3", "REG-0002");
    p.open_round("Round 1");
    let mut batch = p.build_round(&[(&a, 1_000, "a"), (&b, 1_000, "b")]);
    batch.push(batch[0].clone()); // a listed twice
    let reason = p.operator_call_fails("disburse_round", args![batch]);
    assert!(reason.contains("already been paid this round"), "{reason}");
    assert_eq!(p.audit(a.account, &p.auditor_secret.clone()), Some(0), "nobody was paid");
}

#[test]
fn a_family_can_prove_one_grant_to_a_landlord_and_nothing_else() {
    let mut p = setup();
    let fam = p.new_household();
    p.enrol(&fam, "district-3", "REG-0001");
    p.open_round("Round 1");
    p.grant(&fam, 2_000, "r1");
    let n = p.read_notices(fam.account, &fam.secret.clone()).pop().unwrap();
    let proof = GrantProof { household: fam.account, commitment: n.commitment, amount: n.amount, mask: n.mask.clone() };
    assert!(p.verify_grant_proof(&proof));
    let forged = GrantProof { amount: 9_999, ..proof.clone() };
    assert!(!p.verify_grant_proof(&forged), "a padded amount does not open the commitment");
    let wrong = GrantProof { mask: RistrettoSecretKey::random(&mut rng()), ..proof };
    assert!(!p.verify_grant_proof(&wrong));
}

#[test]
fn families_spend_their_grant_confidentially_at_a_merchant() {
    let mut p = setup();
    let fam = p.new_household();
    let shop = p.new_household();
    p.enrol(&fam, "district-3", "REG-0001");
    p.open_round("Round 1");
    p.grant(&fam, 3_000, "r1");
    let n = p.read_notices(fam.account, &fam.secret.clone()).pop().unwrap();
    let shop_pk = shop.public.clone();
    p.family_spend(&fam, &n, 700, shop.account, &shop_pk);
    assert_eq!(p.audit(fam.account, &p.auditor_secret.clone()), Some(2_300));
    assert_eq!(p.read_notices(shop.account, &shop.secret.clone())[0].amount, 700);
}

#[test]
fn operator_recovers_its_treasury_from_chain_state_alone() {
    let mut p = setup();
    let fam = p.new_household();
    p.enrol(&fam, "district-3", "REG-0001");
    p.open_round("Round 1");
    p.grant(&fam, 3_000, "r1");
    p.treasury.clear();
    p.recover_treasury_from_chain();
    assert_eq!(p.treasury_value(), BUDGET - 3_000);
    p.open_round("Round 2");
    p.grant(&fam, 3_000, "r2");
    assert_eq!(p.audit(fam.account, &p.auditor_secret.clone()), Some(6_000));
}

#[test]
fn public_impact_report_has_counts_and_no_amounts() {
    let mut p = setup();
    let a = p.new_household();
    let b = p.new_household();
    p.enrol(&a, "district-3", "REG-0001");
    p.enrol(&b, "district-4", "REG-0002");
    p.open_round("Round 1: shelter");
    let batch = p.build_round(&[(&a, 2_222, "a"), (&b, 3_333, "b")]);
    p.operator_call("disburse_round", args![batch]);
    p.open_round("Round 2: school fees");
    p.grant(&a, 1_111, "a2");

    type Report = (String, u64, u64, Vec<(u64, String, u64)>, u64, u64);
    let r: Report = p.test.call_method(p.hearth, "impact_report", args![], vec![]);
    assert_eq!(r.0, PROGRAMME);
    assert_eq!((r.1, r.2, r.4, r.5), (2, 2, 3, 1));
    assert_eq!(r.3, vec![(1, "Round 1: shelter".to_string(), 2), (2, "Round 2: school fees".to_string(), 1)]);
    let dump = format!("{r:?}");
    for a in ["2222", "3333", "1111"] {
        assert!(!dump.contains(a));
    }
    let reg: Vec<(ComponentAddress, String, bool, u64)> = p.test.call_method(p.hearth, "register", args![], vec![]);
    assert_eq!(reg.len(), 2);
    let raised: Option<Amount> = p.test.call_method(p.hearth, "funds_raised", args![], vec![]);
    assert_eq!(raised, Some(Amount::from(BUDGET)));
}
