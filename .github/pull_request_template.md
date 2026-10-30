## Summary

<!-- What changes for users or contributors? -->

## Related issue

<!-- Link an issue or explain why one is unnecessary. -->

## Safety and privacy

- [ ] No new data source, outbound network path, telemetry, provider integration, or generic command surface
- [ ] Or: the trust-boundary change is explained and `docs/threat-model.md` is updated
- [ ] Destructive behavior remains plan/digest/expiry/revalidation/receipt based
- [ ] Tests and fixtures contain no real secrets, prompts, memory, or private process data

## Verification

<!-- List exact commands and results. -->

- [ ] Failing test observed before implementation
- [ ] `pnpm verify`
- [ ] Relevant Python and/or Rust checks
- [ ] `pnpm secret:scan`
- [ ] Documentation and changelog updated where needed

## Platforms and limitations

<!-- State platforms tested, explicit skips, partial coverage, and remaining gaps. -->

## DCO

- [ ] Every commit contains a `Signed-off-by:` line certifying the repository `DCO`
