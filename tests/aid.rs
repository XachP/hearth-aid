//! Core programme behaviour, run against the real Ootle engine through `tari_template_test_tooling`.
//!
//! Cast: the operator (an NGO, harness default key), the Rahman and Okafor households, the
//! donor's auditor (holds only the view key) and Mallory (an outsider trying to collect).

mod common;

use common::*;
use tari_template_test_tooling::{
    support::confidential::generate_withdraw_proof,
    template_lib_types::Amount,
    transaction::args,
};

#[test]
fn grant_sizes_are_hidden_but_the_auditor_reconciles_every_unit() {
    let mut p = setup();
    let rahman = p.new_household();
    let okafor = p.new_household();
    p.enrol(&rahman, "district-3", "REG-0001");
    p.enrol(&okafor, "district-3", "REG-0002");
    p.open_round("Round 1: shelter and food");
    // Grant size depends on household size and vulnerability: exactly what must stay private.
    p.grant(&rahman, 3_000, "Round 1: 6 people, shelter top-up");
    p.grant(&okafor, 1_500, "Round 1: 2 people");

    let raised: Option<Amount> = p.test.call_method(p.hearth, "funds_raised", args![], vec![]);
    assert_eq!(raised, Some(Amount::from(BUDGET)));
    let issued: u64 = p.test.call_method(p.hearth, "grants_issued", args![], vec![]);
    assert_eq!(issued, 2);

    let a = p.audit(rahman.account, &p.auditor_secret.clone());
    let b = p.audit(okafor.account, &p.auditor_secret.clone());
    let t = p.audit(p.hearth, &p.auditor_secret.clone());
    assert_eq!((a, b, t), (Some(3_000), Some(1_500), Some(5_500)));
    assert_eq!(a.unwrap() + b.unwrap() + t.unwrap(), BUDGET, "grants + treasury == funds raised");

    let (nosy, _) = keypair();
    assert_eq!(p.audit(rahman.account, &nosy), None, "a non-auditor key must not decrypt grants");
}

#[test]
fn the_same_household_cannot_enrol_twice_under_two_wallets() {
    let mut p = setup();
    let first = p.new_household();
    let second_phone = p.new_household();
    p.enrol(&first, "district-3", "REG-0042");
    let reason = p.operator_call_fails("enrol", args![second_phone.account, "district-4", tag("REG-0042")]);
    assert!(reason.contains("duplicate enrolment tag"), "{reason}");
    let n: u64 = p.test.call_method(p.hearth, "household_count", args![], vec![]);
    assert_eq!(n, 1);
}

#[test]
fn raw_ids_are_refused_only_salted_hashes_go_on_chain() {
    let mut p = setup();
    let fam = p.new_household();
    for bad in ["REG-0042", "Fatima Rahman 1987-03-02", &"A".repeat(64), &format!("{}zz", &tag("x")[..62])] {
        let reason = p.operator_call_fails("enrol", args![fam.account, "district-3", bad]);
        assert!(reason.contains("never a raw ID"), "{bad}: {reason}");
    }
    p.enrol(&fam, "district-3", "REG-0042");
    let seen: bool = p.test.call_method(p.hearth, "is_tag_enrolled", args![tag("REG-0042")], vec![]);
    assert!(seen);
}

#[test]
fn no_household_is_paid_twice_in_a_round() {
    let mut p = setup();
    let fam = p.new_household();
    p.enrol(&fam, "district-3", "REG-0001");
    p.open_round("Round 1");
    p.grant(&fam, 1_000, "r1");
    let (proof, ..) = p.build_grant(&fam.public, 1_000, "r1 again");
    let reason = p.operator_call_fails("grant", args![fam.account, proof]);
    assert!(reason.contains("already been paid this round"), "{reason}");

    p.open_round("Round 2");
    p.grant(&fam, 1_000, "r2");
    assert_eq!(p.audit(fam.account, &p.auditor_secret.clone()), Some(2_000));
}

#[test]
fn lost_phone_moves_the_enrolment_without_a_second_entitlement() {
    let mut p = setup();
    let old_phone = p.new_household();
    let new_phone = p.new_household();
    p.enrol(&old_phone, "district-3", "REG-0007");
    p.open_round("Round 1");
    p.grant(&old_phone, 1_200, "r1");

    p.operator_call("replace_wallet", args![old_phone.account, new_phone.account]);
    // Already paid this round: the new wallet inherits that, so no second grant in round 1.
    let (proof, ..) = p.build_grant(&new_phone.public, 1_200, "r1 dup via new phone");
    let reason = p.operator_call_fails("grant", args![new_phone.account, proof]);
    assert!(reason.contains("already been paid this round"), "{reason}");
    // The old wallet is dead.
    let (proof, ..) = p.build_grant(&old_phone.public, 1_200, "old phone");
    p.open_round("Round 2");
    let reason = p.operator_call_fails("grant", args![old_phone.account, proof]);
    assert!(reason.contains("not active"), "{reason}");
    // Next round goes to the new phone.
    p.grant(&new_phone, 1_200, "r2");
    assert_eq!(p.audit(new_phone.account, &p.auditor_secret.clone()), Some(1_200));
    let n: u64 = p.test.call_method(p.hearth, "household_count", args![], vec![]);
    assert_eq!(n, 1, "still one household");
}

#[test]
fn offboarded_households_keep_their_tag_and_cannot_re_enrol() {
    let mut p = setup();
    let fam = p.new_household();
    let other = p.new_household();
    p.enrol(&fam, "district-3", "REG-0009");
    p.operator_call("offboard", args![fam.account]);
    p.open_round("Round 1");
    let (proof, ..) = p.build_grant(&fam.public, 500, "x");
    let reason = p.operator_call_fails("grant", args![fam.account, proof]);
    assert!(reason.contains("not active"), "{reason}");
    let reason = p.operator_call_fails("enrol", args![other.account, "district-3", tag("REG-0009")]);
    assert!(reason.contains("duplicate enrolment tag"), "{reason}");
}

#[test]
fn revealed_grants_are_rejected_so_a_family_is_never_exposed() {
    let mut p = setup();
    let fam = p.new_household();
    p.enrol(&fam, "district-3", "REG-0001");
    p.open_round("Round 1");
    let proof = p.plain_grant(0, 1_000);
    let reason = p.operator_call_fails("grant", args![fam.account, proof]);
    assert!(reason.contains("fully confidential"), "{reason}");
}

#[test]
fn operator_cannot_hide_a_grant_from_the_auditor() {
    let mut p = setup();
    let fam = p.new_household();
    p.enrol(&fam, "district-3", "REG-0001");
    p.open_round("Round 1");
    // Built without the auditor's view key (no viewable balance proof): an off-books grant.
    let (mask, value) = p.treasury[0].clone();
    let proof = generate_withdraw_proof(&mask, 1_000, Some(value - 1_000), 0u64);
    let reason = p.operator_call_fails("grant", args![fam.account, proof.proof]);
    assert!(reason.contains("ViewableBalanceProof is required"), "engine must refuse grants the auditor cannot read: {reason}");
}

#[test]
fn outsiders_cannot_enrol_themselves_or_pay_out() {
    let mut p = setup();
    let mallory = p.new_household();
    p.open_round("Round 1");
    let tx = p
        .test
        .transaction()
        .call_method(p.hearth, "enrol", args![mallory.account, "district-3", tag("FAKE")])
        .build_and_seal(&mallory.secret);
    p.test.execute_expect_failure(tx, vec![mallory.proof.clone()]);

    let (proof, ..) = p.build_grant(&mallory.public, 5_000, "lol");
    let tx = p
        .test
        .transaction()
        .call_method(p.hearth, "grant", args![mallory.account, proof])
        .build_and_seal(&mallory.secret);
    p.test.execute_expect_failure(tx, vec![mallory.proof.clone()]);
    assert_eq!(p.audit(mallory.account, &p.auditor_secret.clone()), Some(0));
}

#[test]
fn donor_funding_grows_the_public_total_only() {
    let mut p = setup();
    let op = p.operator_pk.clone();
    let (statement, _mask, proofs) = budget_statement(5_000, &op, &p.auditor_pk.clone());
    p.operator_call("fund", args!["Anonymous donor #2", statement, proofs]);
    let raised: Option<Amount> = p.test.call_method(p.hearth, "funds_raised", args![], vec![]);
    assert_eq!(raised, Some(Amount::from(BUDGET + 5_000)));
    assert_eq!(p.audit(p.hearth, &p.auditor_secret.clone()), Some(BUDGET + 5_000));
    let fundings: u64 = p.test.call_method(p.hearth, "fundings", args![], vec![]);
    assert_eq!(fundings, 2);
}

#[test]
fn grants_cannot_be_paid_before_a_round_opens() {
    let mut p = setup();
    let fam = p.new_household();
    p.enrol(&fam, "district-3", "REG-0001");
    let (proof, ..) = p.build_grant(&fam.public, 1_000, "early");
    let reason = p.operator_call_fails("grant", args![fam.account, proof]);
    assert!(reason.contains("No aid round is open"), "{reason}");
}
