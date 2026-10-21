# Seccomp test data

`moby-default.json` is the relevant, unmodified rule subset of Moby's
[`profiles/seccomp/default.json`](https://github.com/moby/profiles/blob/main/seccomp/default.json),
copied on 2026-10-22. It retains the real RuntimeDefault fields that the
generator must preserve and transform: default action and errno, architecture
map, capability and architecture gates, and the `SCMP_CMP_LT` / `SCMP_CMP_EQ`
socket rules. It intentionally omits unrelated allow-list entries to keep the
fixture readable.
