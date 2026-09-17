
# Fuzzing

The `Fuzzing/` package holds libFuzzer harnesses built with [swift-fuzz](https://github.com/brokenhandsio/swift-fuzz): `Hash` feeds arbitrary salts and passwords through `Bcrypt.hash` and checks that anything it produces verifies, and `Verify` feeds arbitrary bytes through `Bcrypt.verify` as a stored hash. Both must throw a `BcryptError` or succeed, never trap. They need a swift.org toolchain, since Xcode's has no libFuzzer runtime.

```sh
cd Fuzzing
swift package --disable-sandbox --allow-writing-to-package-directory fuzz --list
swift package --disable-sandbox --allow-writing-to-package-directory fuzz Hash --time 60
swift package --disable-sandbox --allow-writing-to-package-directory fuzz Hash --coverage
```

`--disable-sandbox` is only needed on macOS. The committed `Corpus/` is replayed on every pull request by the `fuzz` workflow, which then fuzzes each target for two minutes, and for twenty minutes on a weekly schedule. A crash lands in `Fuzzing/Crashes/<target>/` and is uploaded as a workflow artifact.
