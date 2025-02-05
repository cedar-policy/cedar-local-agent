# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

- Update to Cedar 4 (requires breaking change)

### Changed

- Remove dependency on `cedar-policy-core`, `cedar-policy-formatter`, and `cedar-policy-validator`.
- Update `thiserror` and `derive_builder` versions

### Fixed

- Remove unused deps

## 2.0.0 - 2024-03-13
Cedar Local Agent Version: 2.0.0
- Upgrade to Cedar dependencies to 3.1.0.
- Added derive Clone to RefreshRate struct.
- Add cause for entity and policy provider errors
- Add support for partial evaluation
- Add better provider parsing error messages

## 1.0.0 - 2023-12-14
Cedar Local Agent Version: 1.0.0
- Initial release of `cedar-local-agent`.
