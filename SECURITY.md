# Security policy

## Supported versions

Only the latest release and the current protected `main` branch receive
security fixes. Pre-release branches, local verification artifacts, and images
not published by this repository's release workflow are unsupported.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/szl-holdings/szl-defensive-control-plane/security/advisories/new).
Do not open a public issue containing an exploit procedure, credential, signing
key, customer data, or unpatched vulnerability detail.

Include, when available:

- The affected version, Git commit, and container digest.
- The impacted entrypoint, endpoint, event schema, or connector path.
- Minimal reproduction steps and the expected versus observed result.
- Whether confidentiality, integrity, availability, tenant isolation,
  approval binding, execution idempotency, or evidence verification is affected.
- Any temporary mitigation already applied.

Never include real production credentials or sensitive event payloads. Use a
redacted or synthetic fixture.

## Scope and safe handling

Good-faith research against a locally controlled instance using synthetic data
is welcome. Do not test against customer systems, shared infrastructure, or
third-party services without explicit authorization. Do not persist, disclose,
or use data obtained outside the authorized test scope.

The maintainers will coordinate validation, remediation, release, and public
disclosure through the private advisory. No response-time or bounty commitment
is implied by this policy.
