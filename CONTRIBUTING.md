# Contributing to CALIPER

Four members, four workstreams, one frozen interface between them. This file is
the mechanics; `README.md` is what the project is and `docs/proposal.txt` is why.

## The one thing that will bite you first

**`main` is protected. You cannot push to it.** Branch, push the branch, open a
pull request:

```sh
git switch -c socket-families        # a short topic name
# ... work, commit ...
git push -u origin socket-families
gh pr create --base main             # or the link git prints
```

Every pull request needs **A's approval** before it can merge — A owns every
path in `.github/CODEOWNERS`, and GitHub does not let you approve your own. This
is deliberate: A is the integrator and is reviewing the project as a whole. It
is not a comment on anyone's work.

Three status checks must pass: `scripts`, `engine`, `control`. Your branch also
has to be up to date with `main` before the merge button lights up — rebase, do
not merge, so history stays linear:

```sh
git fetch origin && git rebase origin/main
```

If review comments are left on your pull request, they must be **resolved**
before it merges.

## Claiming work

Every issue title carries its workstream letter — `[A]`, `[B]`, `[C]`, `[D]`.
Issues are created unassigned. Take yours:

```sh
gh issue edit <number> --add-assignee <your-handle>
```

One milestone per freeze gate. Work the milestone you are in; if you finish
early, the next issue in your letter is the next one to take, not one from
someone else's letter.

## The specs are frozen

`spec/probe.md` and `spec/fingerprint.md` are the contract all four workstreams
develop against, which is the only reason they can proceed in parallel.

- `spec/probe.md` is **frozen**. Changing it needs team agreement.
- `spec/fingerprint.md` is fixed for now and **finally frozen at the end of
  week 9** (issue #28). Until then a change is cheap; after it, a change is a
  new format version.

Each file has a `## Decisions` section giving not just the decision but the
reasoning and its proposal citation. Read that before proposing a change — it
tells you whether you are correcting a mistake or reversing a choice.

## Running things

**Engine (Rust).** Linux only — the tests fork, install seccomp filters and
read exit statuses. `rust-toolchain.toml` pins the channel and both musl
targets, so `rustup` installs what you need on first use.

```sh
cd engine
cargo build --release --target x86_64-unknown-linux-musl
cargo test --target x86_64-unknown-linux-musl
cargo clippy --all-targets --target x86_64-unknown-linux-musl -- -D warnings
cargo fmt --all --check
```

On a Mac, work inside the VM — `scripts/dev-vm.yaml` is a Lima config with
snapshot rollback, which §12 asks for because a probe can destabilise a host:

```sh
limactl start --name caliper scripts/dev-vm.yaml
limactl shell caliper
```

`engine/README.md` covers the build path, the syscall baseline and why the
engine is written the way it is.

**Control plane (Go).** `cd control && go build ./... && go vet ./... && go test ./...`

**Probe image.** `docker build -t caliper-probe engine/` then
`docker run --rm caliper-probe --noop`.

## Commits

Present tense, say what changed and why, and wrap the body. The why matters more
than the what — the diff already shows the what. Where a decision is involved,
name the proposal section or spec decision it follows.

Do not add trailers: no `Co-Authored-By`, no generated-by footers. The commit
history is the team's own work and is assessed as such.

## Safety, because of what this project is

CALIPER probes kernel entry points. Two rules from proposal §6.2 are not
negotiable:

1. A probe establishes that an entry point is **reachable** and stops there. No
   exploit code, and no operation whose success confers privilege. Where an
   enumeration interface can answer the question without executing the probed
   operation, it is preferred — `IORING_REGISTER_PROBE` over submitting queue
   entries.
2. Every probe declares its side effects and how they are reclaimed. Fork
   isolation handles anything descriptor-shaped; anything outliving a process
   declares its rollback. A probe that can make the kernel autoload a module
   declares that too — it cannot be rolled back.

Develop inside a disposable VM. See `SECURITY.md` for what counts as a
vulnerability in this project and how to report one.
