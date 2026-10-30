# Zombie Killer Engine Third-Party Notices

This file applies only to the Zombie Killer Engine Python wheel and source distribution. Those archives contain project Python source, package metadata, and the package-local `LICENSE`, `NOTICE`, and `THIRD_PARTY_NOTICES.md` files. They do not bundle the desktop application, its assets, a native sidecar, or the engine's runtime dependencies.

The engine declares the following direct runtime dependencies:

| Distribution | Pinned version | Upstream-declared license |
| --- | --- | --- |
| psutil | 7.2.2 | BSD-3-Clause |
| Pydantic | 2.13.4 | MIT |
| Typer | 0.27.1 | MIT |

These packages are resolved and installed as separate distributions and remain governed by their own metadata and legal files. The identifiers above summarize upstream metadata for the pinned direct releases; this is not a complete transitive dependency or license inventory. Inspect the resolved environment and every distribution's installed metadata before redistribution.

Build and test tools are not included in the wheel. A separately assembled native sidecar is a different artifact with CPython and platform-runtime components; it requires the platform-specific binary and license review described by the source repository.
