# Hearth threat model

## Assets
1. **Per-household grant amount**: a proxy for household size, disability, illness and protection status.
2. **Household identity**: registration ID, name, phone.
3. **Programme funds**.
4. **Donor trust**: whether the money reached real, unique households.

## Adversaries and what they get

| Adversary | Capability | Result |
|---|---|---|
| Public observer, data broker, armed group | Reads all chain state, events and receipts | Funds raised, cohort labels, household count and grants per round. **No amounts**, because grants are Pedersen commitments and revealed grants are rejected by the template. |
| Curious neighbour (another household) | Has its own key and sees the chain | Only its own notice, because each notice is encrypted to its recipient's key. |
| Donor's auditor | Resource view key | All amounts and the treasury, so it can reconcile. It **cannot** spend, and **cannot** read private notes, which go to the household key only. |
| Double-dipper | Registers a second wallet | Rejected: the salted enrolment tag is unique forever (`duplicate enrolment tag`). |
| Phone thief | Holds the old phone | The operator calls `replace_wallet`. The new wallet inherits paid status, so no second payout. Funds already in the stolen wallet are not recoverable (as with cash). |
| Rogue operator staff | Operator badge | Can enrol and pay, but **cannot** pay the same household twice in a round, cannot hide a grant from the auditor (the view key is locked on the resource), and cannot rewrite the public funds total. Every call is a signed on-chain tx. |
| Outsider | No badge | Cannot enrol or pay anyone (tested). |

## Not protected (honest limits)
* **Ghost beneficiaries created by the operator.** The chain proves uniqueness of tags, not that a tag belongs to a real person. Field verification and the donor's auditor sampling households remain necessary.
* **Salt compromise.** Tags are `sha256(salt | registration_id)`. If the salt leaks, someone holding a list of candidate IDs can test them. The salt must stay with the agency (an HSM in production) and differ per programme.
* **Cohort labels are public.** Keep cohorts coarse (district, not street), otherwise a cohort of one household reveals that household.
* **Timing and count metadata.** The number of grants per round is public by design. Very small rounds narrow down who was paid.
* **Network-level metadata** (IP addresses) is outside the template's scope.
* **Key loss by the auditor** blocks reconciliation but does not lose funds.
* **Testnet only.** Esmeralda is a test network. The code has not been audited.
