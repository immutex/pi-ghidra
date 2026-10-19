## Summary

<!-- What failure mode does this change fix? -->

## Changes

<!-- Bullet the behavior changes, not the file list. -->

## Verification

- [ ] `npm run check`
- [ ] `npm test`
- [ ] `npm run pack:check`
- [ ] `npm run test:integration` (required when `PiGhidra.java` or the cache/runtime path changed)

Commands and observed output:

```text

```

## Checklist

- [ ] The action surface is updated in `src/runtime.ts`, `src/schema.ts`,
      `PiGhidra.java`, the README, and the skill.
- [ ] User-visible changes are in `CHANGELOG.md`.
- [ ] No secrets, proprietary binaries, or machine-specific paths are included.
- [ ] New validation fails closed and names the offending field.
