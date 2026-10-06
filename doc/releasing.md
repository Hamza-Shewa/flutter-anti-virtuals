# Releasing

1. Update `version` in `pubspec.yaml` and `ios/flutter_anti_virtuals.podspec`,
   and put the release notes under a matching `## <version>` heading at the top
   of `CHANGELOG.md`.
2. Merge to `main` once CI is green. CI runs the Dart analysis and tests, builds
   the Android and iOS example (compiling the Kotlin and Swift code), runs the
   Kotlin unit tests and `dart pub publish --dry-run`.
3. Tag and push: `git tag v<version> && git push origin v<version>`. The
   *Publish to pub.dev* workflow publishes it.

One-time setup: on pub.dev, open the package's **Admin** tab, enable
**Automated publishing** with GitHub Actions for this repository and the tag
pattern `v{{version}}`. The workflow runs in a GitHub environment called
`pub.dev`; add a required reviewer to that environment if a release should need
a manual approval. The very first release of a package has to be uploaded once
by hand with `dart pub publish` by an account that will own it.
