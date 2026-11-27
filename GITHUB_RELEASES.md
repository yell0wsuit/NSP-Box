# Publishing releases

Downloads are available on the repository's [Releases page](https://github.com/smarkyie/NSP-Box/releases). Each release includes a portable Windows ZIP, a source ZIP and SHA-256 checksums.

## Publish a version

1. Commit changes to `main`, update `VERSION` in `src/engine.py`, and add a matching entry in `CHANGELOG.md`.
2. Open **Actions → Build and release Windows app → Run workflow**, select the intended branch, and run it. Branch dispatches publish `v<version>-prerelease+<run number>` and are marked as GitHub prereleases. To publish a stable release, push the matching `v<version>` tag instead. Explicit numbered prerelease tags are also accepted.
3. The workflow runs the synthetic tests, builds the portable EXE, and checks PNG/WEBP/ICO/AVIF artwork with NSP in single-file and package-folder modes. It then assembles the application, source, notices and checksums.
4. A successful job publishes a release tagged at its source commit. Existing releases are not overwritten; start a new workflow run for a new prerelease (rerunning an already published run keeps its number), or bump the app version for a new stable release. Archive names, release notes and BUILD_INFO release_version use the resolved release version; app_version remains the source application version.

Release notes include lawful-use and ownership notices and the current emulator-patch instructions, memory-setting guidance and companion workaround for unpatched builds. Keep these notices and the required dependency licenses with redistributed copies.

## Release contents

`package_release.py` selects application files explicitly. Game dumps, generated game packages, local build reports, game artwork, firmware, retail keys and emulator binaries are excluded. Review the selected files and current compatibility notes before publishing.

Builds run on GitHub's Windows runner using the workflow's temporary repository token. Generated `build/`, `dist/`, `release/` and `test-work/` directories are ignored by Git. See [BUILD.md](BUILD.md) for local builds.
