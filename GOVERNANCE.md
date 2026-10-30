# Governance

Zombie Killer uses a maintainer-led, contribution-friendly model during alpha.

## Roles

- **Users** report reproducible behavior and propose improvements.
- **Contributors** submit DCO-signed changes under the applicable repository license.
- **Reviewers** evaluate tests, documentation, security boundaries, accessibility, and platform behavior.
- **Maintainers** merge changes, manage releases and policies, moderate the community, and appoint or remove reviewers/maintainers.

Current maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md). `CODEOWNERS` routes review but does not grant governance authority by itself.

## Decisions

Routine changes are accepted through reviewed pull requests. Maintainers seek documented consensus for changes to destructive behavior, data collection, network boundaries, licensing, governance, protocol compatibility, or release trust. If consensus is not reached, the lead maintainer decides and records the rationale in the issue or pull request.

Security fixes may be developed privately and merged with limited detail until coordinated disclosure. Emergency release actions still require passing available verification; checks may not be silently disabled.

## Maintainer changes

New maintainers should demonstrate sustained, careful contributions; respect privacy and responsible-use boundaries; review across more than one subsystem; and use protected accounts with strong authentication. The lead maintainer records appointments/removals in `MAINTAINERS.md`. Inactivity alone does not imply wrongdoing; access may be removed to reduce supply-chain risk.

## Releases

Only maintainers may declare an official release. Version changes, changelog, source integrity, SBOM, dependency review, secret scanning, and platform builds must pass. Signing and notarization require human-controlled credentials and are never performed from an untrusted pull request. Alpha releases may remain source-only or unsigned when clearly labeled.

Donations confer no vote, priority, ownership, support, warranty, or release authority. See [DONATIONS.md](DONATIONS.md).
