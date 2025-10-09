# 🚀 Release Process

This document describes the automatic semantic versioning and release process for the zigeth library.

## 📋 Overview

The zigeth library uses **semantic versioning** (SemVer) and **automatic releases** triggered on merges to the `master` branch.

### Version Format

Versions follow the format: `vMAJOR.MINOR.PATCH`

- **MAJOR**: Breaking changes or significant new features
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, documentation updates

Examples: `v0.1.0`, `v1.2.3`, `v2.0.0`

## 🔄 Automatic Release Workflow

### How It Works

1. **Merge to Master**: When a PR is merged to `master`, the workflow checks if a release should be created
2. **Version Determination**: Automatically determines version bump based on commit messages
3. **Tag Creation**: Creates a git tag with the new version
4. **Build**: Builds release artifacts for all platforms (Linux, macOS, Windows)
5. **Release**: Creates a GitHub release with artifacts and changelog
6. **Version Update**: Updates `build.zig.zon` with the new version

### Triggering a Release

A release is automatically triggered when:

1. ✅ A pull request is merged to `master` (merge commit detected)
2. ✅ Commit message contains `[release]`, `[major]`, `[minor]`, or `[patch]`
3. ✅ Conventional commit prefixes are used: `feat:`, `fix:`
4. ✅ Manual workflow dispatch

### Skipping a Release

To skip automatic release on merge:

- Add `[skip release]`, `[no release]`, or `[skip ci]` to commit message

Example:
```
git commit -m "docs: update README [skip release]"
```

## 📝 Commit Message Conventions

### Version Bump Types

The type of version bump is determined from the commit message:

#### MAJOR (Breaking Changes)
```
[major] Complete API redesign
BREAKING CHANGE: Removed deprecated functions
```

#### MINOR (New Features)
```
[minor] Add WebSocket provider
feat: Implement middleware layer
feature: Add hardware wallet support
```

#### PATCH (Bug Fixes)
```
[patch] Fix memory leak in RLP decoder
fix: Correct gas estimation calculation
bugfix: Handle edge case in signature verification
```

### Conventional Commits

The workflow supports conventional commit prefixes:

- `feat:` or `feature:` → **MINOR** bump
- `fix:` or `bugfix:` → **PATCH** bump
- `BREAKING CHANGE:` → **MAJOR** bump
- `[major]`, `[minor]`, `[patch]` → Explicit bump

## 🎯 Manual Release

You can manually trigger a release from the GitHub Actions UI:

1. Go to **Actions** → **Automatic Release on Master**
2. Click **Run workflow**
3. Select branch: `master`
4. Choose version bump: `major`, `minor`, or `patch`
5. Click **Run workflow**

## 📦 Release Artifacts

Each release includes:

### Platform Artifacts

- **Linux x86_64**: `zigeth-linux-x86_64.tar.gz`
- **Linux ARM64**: `zigeth-linux-aarch64.tar.gz`
- **macOS x86_64**: `zigeth-macos-x86_64.tar.gz`
- **macOS ARM64**: `zigeth-macos-aarch64.tar.gz`
- **Windows x86_64**: `zigeth-windows-x86_64.zip`

### Release Notes

Automatically generated including:

- Changelog of commits since last release
- Project status and statistics
- Module completion status
- Quick start guide
- Installation instructions

## 🔖 Version Management

### Current Version

The current version is stored in:

1. **VERSION file**: `VERSION` (plain text: `0.1.0`)
2. **build.zig.zon**: `.version = "0.1.0"`
3. **Git tags**: `v0.1.0`

### Version Update Process

The workflow automatically:

1. Reads the latest git tag
2. Determines the version bump
3. Calculates the new version
4. Updates `build.zig.zon`
5. Commits the update with `[skip ci]`
6. Creates and pushes the new tag
7. Triggers the release build

## 🛠️ Workflow Files

### `.github/workflows/auto-release.yml`

Main workflow that:
- Determines if release should happen
- Calculates new version
- Creates git tag
- Builds artifacts
- Creates GitHub release
- Updates version in code

### `.github/workflows/release.yml`

Called when tags are pushed:
- Builds release artifacts
- Creates GitHub release
- Can also be triggered manually

### `.github/workflows/ci.yml`

Runs on every PR:
- Linting
- Testing
- Build verification
- Documentation generation

## 📋 Release Checklist

Before merging to master:

- [ ] All tests passing
- [ ] Code formatted (`zig build fmt`)
- [ ] Linting clean (`zig build lint`)
- [ ] Documentation updated
- [ ] CHANGELOG updated (optional)
- [ ] Commit message follows conventions

## 🎯 Examples

### Feature Release (MINOR)

```bash
git commit -m "feat: Add WebSocket subscription support"
git push origin feature-branch

# After PR merge to master:
# → Automatically releases v0.2.0 (if current is v0.1.0)
```

### Bug Fix Release (PATCH)

```bash
git commit -m "fix: Correct nonce calculation in pending transactions"
git push origin bugfix-branch

# After PR merge to master:
# → Automatically releases v0.1.1 (if current is v0.1.0)
```

### Breaking Change Release (MAJOR)

```bash
git commit -m "refactor: Redesign wallet API

BREAKING CHANGE: Wallet.init() now requires SignerConfig parameter"
git push origin breaking-change

# After PR merge to master:
# → Automatically releases v1.0.0 (if current is v0.1.0)
```

### Update Without Release

```bash
git commit -m "docs: Fix typo in README [skip release]"
git push origin docs-update

# After PR merge to master:
# → No release created
```

## 🔍 Monitoring Releases

### Check Release Status

View release status at:
- **Actions**: https://github.com/ch4r10t33r/zigeth/actions
- **Releases**: https://github.com/ch4r10t33r/zigeth/releases
- **Tags**: https://github.com/ch4r10t33r/zigeth/tags

### Release Notifications

GitHub will:
- Create a release on the Releases page
- Send notifications to watchers
- Update the latest release badge
- Make artifacts available for download

## 🐛 Troubleshooting

### Release Not Created

Check if:
- Commit message contains skip keywords
- Workflow has correct permissions
- Branch protection rules are configured
- GitHub Actions are enabled

### Build Failures

- Check Actions logs for errors
- Verify Zig version compatibility
- Ensure all tests pass in CI
- Check for platform-specific issues

### Version Conflicts

If a version already exists:
- The workflow will fail
- Manually delete the tag: `git push --delete origin vX.Y.Z`
- Re-run the workflow

## 📚 Additional Resources

- **Semantic Versioning**: https://semver.org/
- **Conventional Commits**: https://www.conventionalcommits.org/
- **GitHub Actions**: https://docs.github.com/en/actions
- **Zig Build System**: https://ziglang.org/learn/build-system/

## 🎉 Initial Development Release

The library is currently at **v0.1.0** (initial development release) with:

- ✅ 334 tests passing
- ✅ 12/12 modules complete
- ✅ 100% feature complete
- ✅ Production-ready

Ready for the Ethereum ecosystem! 🚀

