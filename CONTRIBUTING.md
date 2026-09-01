# Contributing to idunn

Pull requests are welcome — bug reports, failing test cases, documentation fixes
and features all count. If a change is large or reshapes the public API, open an
issue first so the design can be discussed before you spend time on it.

## Licensing of contributions

`idunn` is dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).

Unless you explicitly state otherwise, any contribution you intentionally submit
for inclusion in this project, as defined in the Apache-2.0 license — code,
documentation, tests, or anything else — shall be dual-licensed under those same
terms, with no additional terms or conditions.

By opening a pull request you also confirm that you have the right to license
the contribution that way: it is your own work, or you have permission to
submit it (for example, it is not code your employer owns without their
approval, and it is not copied from an incompatibly licensed project).

## AI assistance and agentic pull requests

Using an AI assistant is **not** forbidden here. Using one as a substitute for
understanding the code is.

- **Fully agentic pull requests are not accepted.** A PR that an agent produced
  and opened without a human reading the result will be closed. The same goes
  for a PR whose author cannot explain what it does when asked.
- **You must have read and understood every single line you submit** — including
  the lines an assistant wrote for you. If you would not be comfortable
  defending a line in review, delete it or rewrite it until you would be.
- **You take responsibility for the contribution as your own work.** From the
  project's point of view the author of the PR is the human who opened it; how
  the diff was produced does not change who is accountable for it.
- You do not need to disclose that you used AI assistance, and there is no
  penalty for having used it. What matters is that the result is code you stand
  behind.

This matters more than usual for this crate: `idunn` handles authentication
credentials and token verification, where a plausible-looking but subtly wrong
check is a security bug rather than a cosmetic one.

## Before you open a pull request

The project uses [`just`](https://github.com/casey/just) for its dev commands;
see the `justfile` for the full list.

```sh
cargo test                # tests (dev-dependencies force the `reqwest` feature on)
just clippy               # clippy over all targets and features, warnings denied
cargo fmt --all           # formatting
just check-features       # every feature in isolation still compiles
just cargo-deny           # license / advisory / source checks
just coverage             # local HTML coverage report
```

Guidelines for the change itself:

- Keep the public API documented. Public items carry doc comments explaining
  what a caller is guaranteed, not just what the code does.
- New behaviour needs tests. Security-relevant behaviour (signature checks,
  claim validation, redaction of secrets) needs tests for the *rejection* path,
  not only the happy path.
- Never log or `Debug`-print token or key material; the existing redaction
  tests are there to keep that true.
- If a change encodes a non-obvious design decision, add the reasoning to
  [`docs/architecture.md`](docs/architecture.md) rather than burying it in a
  commit message.
- Keep commits focused, with a message that explains *why* the change is being
  made.
