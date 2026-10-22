//! # Hearth: dignified, confidential cash aid on Tari Ootle
//!
//! Cash transfers are one of the most effective forms of humanitarian aid, and blockchains make
//! them cheap and auditable. But a transparent ledger also publishes *who received how much*:
//! a household's grant size reveals its size, its vulnerability score, sometimes its medical or
//! protection status. That data can be used for extortion, discrimination or targeting. "Do no
//! harm" and data-protection rules (ICRC, GDPR, the Sphere standards) say it must stay private.
//!
//! Hearth keeps donors' trust *and* families' privacy:
//!
//! * **Public (for donors and the community):** the total funds raised, the number of enrolled
//!   households, each aid round's public label, how many grants were paid in each round, and that
//!   no household was paid twice in a round.
//! * **Secret:** every individual grant. Grants are Pedersen commitments, so amounts never appear
//!   in state, events or receipts. The operator cannot leak one by accident: any revealed amount is
//!   rejected by the template.
//! * **Auditable:** the aid token is created with an auditor view key. The donor's auditor can
//!   decrypt every commitment and reconcile `sum(grants) + treasury == funds raised`, with no
//!   power to spend.
//! * **No personal data on-chain, but no double-dipping:** households are enrolled with a salted
//!   hash of their real-world registration ID (an *enrolment tag*). The template refuses a second
//!   account with the same tag, so one family can't enrol twice under two wallets, yet the chain
//!   never learns who they are. If a family loses its phone, `replace_wallet` moves the enrolment
//!   to a new account without creating a second entitlement.
//! * **Encrypted grant notice:** each grant carries a memo (amount, purpose, redemption info)
//!   DH-encrypted to the family's key, so even a basic phone wallet can show what arrived. A family
//!   can prove a single grant to a landlord or clinic by sharing its opening, nothing else.
//!
//! License: MIT

use std::collections::{BTreeMap, BTreeSet};

use tari_template_lib::prelude::*;

#[template]
mod hearth {
    use super::*;
    use tari_template_lib::types::{
        confidential::{ConfidentialOutputStatement, ConfidentialWithdrawProof},
        crypto::{CommitmentValueProof, PedersenCommitmentBytes},
    };

    /// Largest number of grants in one atomic round transaction.
    const MAX_GRANTS_PER_TX: usize = 64;

    pub struct Hearth {
        /// Treasury of confidential aid credits. Only commitments live here.
        treasury: Vault,
        /// The aid operator (NGO programme key) that instantiated the component.
        operator: RistrettoPublicKeyBytes,
        /// Public programme name, e.g. "Sylhet flood relief 2026".
        programme: String,
        /// Enrolled households, keyed by the wallet account that receives grants.
        households: BTreeMap<ComponentAddress, Household>,
        /// Salted hashes of registration IDs already enrolled (dedupe without PII).
        enrolment_tags: BTreeSet<String>,
        /// Current aid round. 0 means no round has opened yet.
        round: u64,
        /// Public label of each round, e.g. "Round 1: shelter and food".
        round_labels: BTreeMap<u64, String>,
        /// Grants paid per round (counts only).
        grants_per_round: BTreeMap<u64, u64>,
        grants_issued: u64,
        /// Number of public funding events (donations minted into the treasury).
        fundings: u64,
    }

    pub struct Household {
        /// Coarse public cohort label, e.g. "district-3". Never an amount or a name.
        pub cohort: String,
        /// Salted hash of the household's registration ID.
        pub tag: String,
        pub active: bool,
        /// Last round this household was paid in. Stops double payment within a round.
        pub last_paid_round: u64,
        pub grants: u64,
    }

    impl Hearth {
        /// Opens an aid programme.
        ///
        /// * `programme`: public name of the programme.
        /// * `auditor_view_key`: public view key of the donor's auditor, fixed on the resource.
        /// * `funds`: confidential output statement for the opening funds, built client side.
        /// * `funds_value_proofs`: value proofs so the total raised is publicly provable.
        pub fn new(
            programme: String,
            auditor_view_key: RistrettoPublicKeyBytes,
            funds: ConfidentialOutputStatement,
            funds_value_proofs: BTreeMap<PedersenCommitmentBytes, CommitmentValueProof>,
        ) -> Component<Self> {
            assert!(!programme.is_empty() && programme.len() <= 96, "Programme name must be 1-96 bytes");
            assert!(
                funds.output_revealed_amount.is_zero() && funds.change_revealed_amount.is_zero(),
                "Opening funds must be confidential commitments, not revealed funds"
            );
            let operator = CallerContext::transaction_signer_public_key();
            let alloc = CallerContext::allocate_component_address(None);
            let this = alloc.get_address();

            let bucket = ResourceBuilder::confidential()
                .with_token_symbol("HEARTH")
                .metadata("name", "Hearth aid credit")
                .metadata("description", "Confidential cash-aid credit. Grant sizes are private; the donor's auditor holds the view key.")
                .metadata("programme", programme.clone())
                // Only this component can mint (via `fund`, which is operator-gated).
                .mintable(rule!(component(this)), LOCKED)
                .burnable(rule!(deny_all), LOCKED)
                .recallable(rule!(deny_all), LOCKED)
                .with_view_key(auditor_view_key)
                .initial_supply_with_value_proofs(funds, funds_value_proofs);

            let operator_only = rule!(public_key(operator));
            emit_event("ProgrammeOpened", metadata!["programme" => programme.clone()]);
            Component::new(Self {
                treasury: Vault::from_bucket(bucket),
                operator,
                programme,
                households: BTreeMap::new(),
                enrolment_tags: BTreeSet::new(),
                round: 0,
                round_labels: BTreeMap::new(),
                grants_per_round: BTreeMap::new(),
                grants_issued: 0,
                fundings: 1,
            })
            .with_address_allocation(alloc)
            .with_access_rules(
                ComponentAccessRules::new()
                    .method("enrol", operator_only.clone())
                    .method("offboard", operator_only.clone())
                    .method("replace_wallet", operator_only.clone())
                    .method("open_round", operator_only.clone())
                    .method("grant", operator_only.clone())
                    .method("disburse_round", operator_only.clone())
                    .method("fund", operator_only.clone())
                    .method("programme", rule!(allow_all))
                    .method("round", rule!(allow_all))
                    .method("round_label", rule!(allow_all))
                    .method("grants_in_round", rule!(allow_all))
                    .method("is_paid_this_round", rule!(allow_all))
                    .method("household_count", rule!(allow_all))
                    .method("is_tag_enrolled", rule!(allow_all))
                    .method("grants_issued", rule!(allow_all))
                    .method("aid_resource", rule!(allow_all))
                    .method("funds_raised", rule!(allow_all))
                    .method("fundings", rule!(allow_all))
                    .method("treasury_commitment_count", rule!(allow_all))
                    .method("impact_report", rule!(allow_all))
                    .method("register", rule!(allow_all))
                    .default(rule!(deny_all)),
            )
            .create()
        }

        /// Enrols a household. `tag` is a salted SHA-256 of its registration ID, as 64 hex chars.
        /// The same tag can never be enrolled twice, even under a different wallet.
        pub fn enrol(&mut self, household_account: ComponentAddress, cohort: String, tag: String) {
            assert!(cohort.len() <= 32, "Cohort label too long (max 32 bytes)");
            assert!(
                tag.len() == 64 && tag.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "Enrolment tag must be a lowercase 64-char hex hash, never a raw ID"
            );
            assert!(!self.households.contains_key(&household_account), "Wallet is already enrolled");
            assert!(!self.enrolment_tags.contains(&tag), "Household is already enrolled (duplicate enrolment tag)");
            self.enrolment_tags.insert(tag.clone());
            self.households.insert(household_account, Household {
                cohort,
                tag,
                active: true,
                last_paid_round: 0,
                grants: 0,
            });
            emit_event("HouseholdEnrolled", metadata!["household" => household_account.to_string()]);
        }

        /// Ends a household's enrolment (moved away, graduated). History and the tag are kept,
        /// so the same family can't re-enrol under a new wallet to collect twice.
        pub fn offboard(&mut self, household_account: ComponentAddress) {
            let h = self.households.get_mut(&household_account).expect("Not an enrolled household");
            assert!(h.active, "Household already offboarded");
            h.active = false;
            emit_event("HouseholdOffboarded", metadata!["household" => household_account.to_string()]);
        }

        /// Lost or stolen phone: moves an enrolment to a new wallet. The old wallet is deactivated
        /// and the new one inherits the same tag and payment history, so this never creates a
        /// second entitlement (a household already paid this round stays paid).
        pub fn replace_wallet(&mut self, old_account: ComponentAddress, new_account: ComponentAddress) {
            assert!(old_account != new_account, "New wallet must differ from the old one");
            assert!(!self.households.contains_key(&new_account), "New wallet is already enrolled");
            let old = self.households.get_mut(&old_account).expect("Not an enrolled household");
            assert!(old.active, "Household is not active");
            old.active = false;
            let moved = Household {
                cohort: old.cohort.clone(),
                tag: old.tag.clone(),
                active: true,
                last_paid_round: old.last_paid_round,
                grants: old.grants,
            };
            self.households.insert(new_account, moved);
            emit_event("WalletReplaced", metadata![
                "old" => old_account.to_string(),
                "new" => new_account.to_string(),
            ]);
        }

        /// Opens a new aid round with a public label. Each active household can be paid once per round.
        pub fn open_round(&mut self, label: String) {
            assert!(!label.is_empty() && label.len() <= 64, "Round label must be 1-64 bytes");
            self.round += 1;
            self.round_labels.insert(self.round, label.clone());
            emit_event("RoundOpened", metadata!["round" => self.round.to_string(), "label" => label]);
        }

        /// Pays one household for the current round (e.g. a late registration).
        pub fn grant(&mut self, household_account: ComponentAddress, grant: ConfidentialWithdrawProof) {
            let round = self.issue_grant(household_account, grant);
            emit_event("GrantPaid", metadata![
                "household" => household_account.to_string(),
                "round" => round.to_string(),
            ]);
        }

        /// Pays a whole round in one atomic transaction. If any grant fails a check (revealed
        /// amount, unknown or inactive household, double payment, duplicate in the batch), nobody
        /// is paid. One `RoundDisbursed` event carries only the round and the head count, so
        /// observers can't infer anything from per-family timing.
        pub fn disburse_round(&mut self, grants: Vec<(ComponentAddress, ConfidentialWithdrawProof)>) {
            assert!(!grants.is_empty(), "A round needs at least one grant");
            assert!(grants.len() <= MAX_GRANTS_PER_TX, "At most 64 grants per transaction");
            let count = grants.len();
            let mut round = self.round;
            for (household, proof) in grants {
                round = self.issue_grant(household, proof);
            }
            emit_event("RoundDisbursed", metadata![
                "round" => round.to_string(),
                "grants" => count.to_string(),
            ]);
        }

        fn issue_grant(&mut self, household_account: ComponentAddress, grant: ConfidentialWithdrawProof) -> u64 {
            assert!(self.round > 0, "No aid round is open; call open_round first");
            assert!(
                grant.revealed_input_amount().is_zero() &&
                    grant.revealed_output_amount().is_zero() &&
                    grant.revealed_change_amount().is_zero(),
                "Grants must be fully confidential: a revealed amount would expose a family's grant"
            );
            assert!(!grant.inputs.is_empty(), "A grant must spend treasury commitments");

            let round = self.round;
            let h = self.households.get_mut(&household_account).expect("Not an enrolled household");
            assert!(h.active, "Household is not active");
            assert!(h.last_paid_round < round, "Household has already been paid this round");
            h.last_paid_round = round;
            h.grants += 1;
            self.grants_issued += 1;
            *self.grants_per_round.entry(round).or_insert(0) += 1;

            let bucket = self.treasury.withdraw_confidential(grant);
            assert_eq!(
                bucket.count_confidential_commitments(),
                1,
                "A grant must contain exactly one confidential output"
            );
            ComponentManager::get(household_account).invoke("deposit", args![bucket]);
            round
        }

        /// Records new donor funding. The amount raised becomes public (total supply), but how it
        /// is split between families does not. `donor` is a public label, e.g. "Anon donor #12".
        pub fn fund(
            &mut self,
            donor: String,
            funds: ConfidentialOutputStatement,
            funds_value_proofs: BTreeMap<PedersenCommitmentBytes, CommitmentValueProof>,
        ) {
            assert!(donor.len() <= 64, "Donor label too long (max 64 bytes)");
            assert!(
                funds.output_revealed_amount.is_zero() && funds.change_revealed_amount.is_zero(),
                "Funding must be confidential commitments, not revealed funds"
            );
            let bucket = ResourceManager::get(self.treasury.resource_address()).mint_confidential(funds, funds_value_proofs);
            self.treasury.deposit(bucket);
            self.fundings += 1;
            emit_event("Funded", metadata!["donor" => donor, "round" => self.round.to_string()]);
        }

        pub fn programme(&self) -> String {
            self.programme.clone()
        }

        pub fn round(&self) -> u64 {
            self.round
        }

        pub fn round_label(&self, round: u64) -> Option<String> {
            self.round_labels.get(&round).cloned()
        }

        pub fn grants_in_round(&self, round: u64) -> u64 {
            self.grants_per_round.get(&round).copied().unwrap_or(0)
        }

        pub fn is_paid_this_round(&self, household_account: ComponentAddress) -> bool {
            self.households
                .get(&household_account)
                .is_some_and(|h| self.round > 0 && h.last_paid_round == self.round)
        }

        pub fn household_count(&self) -> u64 {
            self.households.values().filter(|h| h.active).count() as u64
        }

        pub fn is_tag_enrolled(&self, tag: String) -> bool {
            self.enrolment_tags.contains(&tag)
        }

        pub fn grants_issued(&self) -> u64 {
            self.grants_issued
        }

        pub fn aid_resource(&self) -> ResourceAddress {
            self.treasury.resource_address()
        }

        /// Total funds ever raised (public by design, from supply tracking).
        pub fn funds_raised(&self) -> Option<Amount> {
            ResourceManager::get(self.treasury.resource_address()).total_supply_opt()
        }

        pub fn fundings(&self) -> u64 {
            self.fundings
        }

        pub fn treasury_commitment_count(&self) -> u64 {
            u64::from(self.treasury.commitment_count())
        }

        /// Public impact report for donors: (programme, active households, rounds, grants per
        /// round, total grants, funding events). Counts only, never an amount per family.
        #[allow(clippy::type_complexity)]
        pub fn impact_report(&self) -> (String, u64, u64, Vec<(u64, String, u64)>, u64, u64) {
            let rounds = self
                .round_labels
                .iter()
                .map(|(r, l)| (*r, l.clone(), self.grants_in_round(*r)))
                .collect();
            (self.programme.clone(), self.household_count(), self.round, rounds, self.grants_issued, self.fundings)
        }

        /// Public register: (wallet, cohort, active, grants received). No amounts, no identities.
        pub fn register(&self) -> Vec<(ComponentAddress, String, bool, u64)> {
            self.households
                .iter()
                .map(|(a, h)| (*a, h.cohort.clone(), h.active, h.grants))
                .collect()
        }
    }
}
