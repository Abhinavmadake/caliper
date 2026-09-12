// The CALIPER control plane. See README.md for what lives here and why Go.
//
// The `go` directive is deliberately conservative: CI resolves `stable`, and a
// newer toolchain accepts an older directive, so this does not need bumping
// every release.
module github.com/Abhinavmadake/caliper/control

go 1.23
