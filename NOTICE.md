# Notices

The distributed jar and release bundle contain only original code licensed under
the Apache License 2.0 — see [LICENSE](LICENSE). No third-party code is bundled
or redistributed in either artifact.

Build and test tooling is used to build this project but is not included in any
distributed artifact:

- Apache Maven and its plugins (Apache License 2.0) drive the build.
- JUnit Jupiter and the JUnit Platform (Eclipse Public License 2.0), with their
  test-scope support libraries (Apache License 2.0), run the test suite.
- GitHub Actions runners execute the CI and release workflows; the workflow's
  pinned third-party actions are governed by their own licenses.

A Maven enforcer rule fails the build if any dependency ever enters compile or
runtime scope, so the "not included in any distributed artifact" statement above
holds by construction, not just by current accident. If you rebuild from source,
Maven downloads this tooling onto your machine and it is governed by its own
license — this file does not relicense any of it.
