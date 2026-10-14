# Releasing

This repository publishes two packages to pub.dev: the plugin
(`flutter_anti_virtuals`, at the root) and the server-side verifier
(`anti_virtuals_verifier`, in `packages/anti_virtuals_verifier`). Each one has
its own version, changelog and tag.

## The plugin

1. Bump the version in all three places: `version` in `pubspec.yaml`,
   `s.version` in `ios/flutter_anti_virtuals.podspec` and `version` in
   `android/build.gradle.kts`. Put the release notes under a matching
   `## <version>` heading at the top of `CHANGELOG.md`.
2. Merge to `main` once CI is green. CI runs the Dart analysis and tests, builds
   the Android and iOS example (compiling the Kotlin and Swift code), runs the
   Kotlin and Swift unit tests, the integration tests on an emulator and a
   Simulator, and `dart pub publish --dry-run`.
3. Tag the merge commit and push the tag:

   ```sh
   git checkout main && git pull
   git tag v<version>
   git push origin v<version>
   ```

   The "Publish to pub.dev" workflow (`.github/workflows/publish.yml`) picks up
   the tag and publishes that version.

A published version can't be deleted from pub.dev. It can only be retracted,
and only during the first 7 days, so check the version and the changelog before
pushing the tag.

## The verifier

1. Bump `version` in `packages/anti_virtuals_verifier/pubspec.yaml` and add a
   `## <version>` heading to its `CHANGELOG.md`.
2. Merge to `main` once CI is green (the "Verifier package" job analyzes and
   tests it and runs the dry run).
3. Tag and push with the package name in front of the version:

   ```sh
   git tag anti_virtuals_verifier-v<version>
   git push origin anti_virtuals_verifier-v<version>
   ```

   The "Publish anti_virtuals_verifier to pub.dev" workflow
   (`.github/workflows/publish_verifier.yml`) publishes it from the package
   folder.

## One-time setup on pub.dev

pub.dev only accepts automated uploads for a package that already exists, so
the first version of each package has to be uploaded by hand, by the account
that will own it:

```sh
dart pub publish                      # the plugin, from the repository root
cd packages/anti_virtuals_verifier
dart pub publish                      # the verifier
```

After that, open the package's Admin tab on pub.dev, enable automated publishing
from GitHub Actions for this repository and set the tag pattern:

| Package | Tag pattern |
| --- | --- |
| `flutter_anti_virtuals` | `v{{version}}` |
| `anti_virtuals_verifier` | `anti_virtuals_verifier-v{{version}}` |

Both workflows run in a GitHub environment called `pub.dev`. Add a required
reviewer to that environment (Settings, Environments) if every release should
wait for a manual approval. No token is stored in GitHub, since pub.dev trusts
the workflow through OpenID Connect.
