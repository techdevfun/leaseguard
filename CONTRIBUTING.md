# Contributing to leaseguard

Small, focused contributions are welcome.

- Keep it zero-dependency and single-file (`leaseguard.js`). If a feature
  needs a library, it probably belongs in a different tool.
- Every new gate behavior needs a test in `tests/`. Run `npm test`.
- The security model is "stops accidents and casual misuse". Do not claim
  more than that in docs or PRs — a determined local adversary with the
  same file permissions can mint leases. Say it plainly.
- Match the existing CLI style: exit codes 0 = ran, 1 = usage error,
  2 = denied (no lease/policy), 3 = bad/expired lease, 4 = policy deny.
