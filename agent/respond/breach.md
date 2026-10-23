# Path: a vendor or package was breached → keys to rotate

Follow `common.md` throughout. A breach is not fixed by a release: what is at stake is the user's keys that the vendor held or that passed through the compromised package.

1. **What happened**, from the vendor's own notice and the news: what was accessed (env vars, tokens, source, customer data), since when, which customers, and what the vendor tells customers to do (tokens it already invalidated, keys it says to rotate).
2. **Which of the user's keys are at stake:** the `atRisk` list in the case (from the rotation map, and the CI secrets and secret-named env vars of the places that deploy on the vendor), checked against what the vendor says was accessed. Add any the repo shows the vendor stores (deploy configs, `.env.example` names, CI secret names). Names and places only.
3. **Tell the user**: one `urgent` line (e.g. "Railway breach: rotate the 6 billing-api keys it stores; list in the report"). In the report, priority places first: each key to rotate, every place it is stored (so the new value goes everywhere the old one was), and the order (database and payment keys before low-value ones; the deploy token before redeploying with new values), and what to check for abuse (provider dashboards, bills, logs).
4. **Change nothing.** Never rotate, revoke or edit a key, and never show a value. A malicious package version is the exception that has a code fix: moving to a clean version follows `update.md` in mode UPDATE or ACT and `propose.md` otherwise, and the keys on the machines that installed it still need rotating.

Nothing waits on a release, so there is usually no `cvecondor-wait` block.
