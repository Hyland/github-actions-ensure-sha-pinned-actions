# github-actions-ensure-sha-pinned-actions

[![Last release](https://img.shields.io/github/v/release/hyland/github-actions-ensure-sha-pinned-actions)](https://github.com/hyland/github-actions-ensure-sha-pinned-actions/releases/latest)
[![CI](https://github.com/hyland/github-actions-ensure-sha-pinned-actions/actions/workflows/test.yml/badge.svg)](https://github.com/hyland/github-actions-ensure-sha-pinned-actions/actions/workflows/test.yml)
[![Release](https://github.com/hyland/github-actions-ensure-sha-pinned-actions/actions/workflows/release.yml/badge.svg)](https://github.com/hyland/github-actions-ensure-sha-pinned-actions/actions/workflows/release.yml)
[![GitHub contributors](https://img.shields.io/github/contributors/hyland/github-actions-ensure-sha-pinned-actions)](https://github.com/hyland/github-actions-ensure-sha-pinned-actions/graphs/contributors)

Ensures all GitHub Actions in your workflows use SHA-pinned versions instead of tag references for enhanced supply chain security. This action converts tag references (e.g., `v1.0.0`) to SHA hashes while preserving semantic version comments.

**Key Features:**

- **SHA Pinning**: Automatically converts tag references to SHA hashes with version comments
- **Allowlist Support**: Skip specific actions from conversion using flexible pattern matching
- **Dry Run Mode**: Preview changes without modifying files
- **Discovery Mode**: Fast scanning without API calls

**Security Benefits:**

- Prevents malicious updates to existing tags
- Ensures reproducible builds with exact action versions
- Maintains clear audit trail of action versions
- Preserves human-readable version information in comments
- Secure token handling via environment variables only (no command-line exposure)

## Table of Contents

- [GitHub Action](#github-action)
- [Pre-commit Hook](#pre-commit-hook)
- [Development](#development)
- [Release](#release)

## GitHub Action

**Basic Usage:**

```yaml
- name: Ensure SHA pinned actions
  uses: hyland/github-actions-ensure-sha-pinned-actions@22ca7a8cf33e873ba1d6fbcd2b71fa0ec5006b17 # v1.1.0
```

**With Allowlist:**

```yaml
- name: Ensure SHA pinned actions
  uses: hyland/github-actions-ensure-sha-pinned-actions@22ca7a8cf33e873ba1d6fbcd2b71fa0ec5006b17 # v1.1.0
  with:
    allowlist: |
      actions/*
      microsoft/*
      Alfresco/alfresco-build-tools/*
```

**Advanced Configuration:**

```yaml
- name: Ensure SHA pinned actions
  uses: hyland/github-actions-ensure-sha-pinned-actions@22ca7a8cf33e873ba1d6fbcd2b71fa0ec5006b17 # v1.1.0
  with:
    allowlist: |
      actions/checkout@*
      actions/setup-*
    dry-run: "true"
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

**Example Conversion:**

```yaml
# Before
uses: actions/checkout@v4
uses: actions/setup-node@v3
uses: docker/build-push-action@v4.1.1

# After
uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
uses: actions/setup-node@64ed1c7eab4cce3362f8c340dee64e5eaeef8f7c # v3.6.0
uses: docker/build-push-action@2cdde995de11925a030ce8070c3d77a52ffcf1c0 # v4.1.1
```

## Pre-commit Hook

The same feature can be achieved with [pre-commit](https://pre-commit.com/).

### Installation

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/hyland/github-actions-ensure-sha-pinned-actions
    rev: 22ca7a8cf33e873ba1d6fbcd2b71fa0ec5006b17 # v1.1.0
    hooks:
      - id: gha-sha-convert
```

### Configuration

#### Environment Variables

- `GITHUB_TOKEN` (required): GitHub personal access token with `repo` scope

#### Arguments

- `--force`: Force conversion even if reference already uses SHA with semver comment

Example with force flag:

```yaml
- id: gha-sha-convert
  args: ["--force"]
```

## Development

### Install and Test Instructions

### Requirements

- Python 3.9+ (3.9-3.13 supported)
- GitHub token with `repo` scope
- Internet connection (for GitHub API calls)

### Setup

```bash
# Activate the virtualenv
python -m venv venv
source venv/bin/activate
# Install python dependencies
python -m pip install -U pip
python -m pip install -r requirements.txt
```

To deactivate the virtualenv after usage:

```bash
deactivate
```

To help with code quality, [pre-commit](https://pre-commit.com/) is leveraged and run on CI.
To run pre-commit locally:

```bash
pre-commit run -a
```

To setup pre-commit for automated checks before commit:

```bash
python -m pip install -U --user pre-commit
pre-commit install
```

To run unit tests for the GitHub Actions SHA converter (no network connection required):

```bash
python -m unittest test_gha_sha_convert -v
```

For local development or testing of the pre-commit hook, see the sample configuration file at `.pre-commit-hooks-dev.yaml`.

### Usage

#### As Pre-commit Hook

```bash
# Install pre-commit
pip install pre-commit

# Install the hooks
pre-commit install

# Run on all files
pre-commit run gha-sha-convert --all-files
```

#### Manual Execution

```bash
# Process all workflow files in current directory
python gha_sha_convert.py

# Process specific files
python gha_sha_convert.py .github/workflows/ci.yml

# Force re-processing of already converted actions
python gha_sha_convert.py --force

# Discovery mode - scan without making changes
python gha_sha_convert.py --discovery

# Dry run mode - show what would be changed
python gha_sha_convert.py --dry-run

# Process specific directory paths
python gha_sha_convert.py --path .github/workflows --path .github/actions
```

Environment Variables:

- `GITHUB_TOKEN`: GitHub personal access token for API access (required for conversions)

Command Line Options:

- `--force`: Force re-processing of already converted actions
- `--path PATH`: Specify custom search paths (can be used multiple times)
- `--discovery`: Discovery mode - scan files without making API calls or changes
- `--dry-run`: Dry run mode - make API calls but don't modify files (requires token)

GitHub Token Setup:

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Create a new token with `public_repo` scope (or `repo` for private repositories)
3. Set the token as an environment variable:

```bash
export GITHUB_TOKEN=your_token_here
```

### Error Handling

The hook handles various error conditions gracefully:

- **Rate limiting**: Exits with appropriate error code
- **Missing tags**: Skips with warning
- **Network errors**: Continues with other references
- **Invalid responses**: Skips with error message

### Performance

- Uses response caching to minimize API calls
- Only processes each unique reference once per run
- Skips references that are already in SHA format with semver comments

### Security Considerations

- Requires GitHub token - store securely as environment variable only
- Token must be provided via `GITHUB_TOKEN` environment variable for security
- Only fetches from GitHub's official API
- Validates SHA format before updating files
- Preserves file permissions and encoding

## Release

To create a new release, simply merge a PR that is labelled with either `release/major` / `release/minor` / `release/patch`, following semantic versioning:

- `release/patch`: a bump in the third number will be required if you are bug fixing an existing
  action.
- `release/minor`: a bump in the second number will be required if you introduced a new action or
  improved an existing action, ensuring backward compatibility.
- `release/major`: a bump in the first number will be required if there are major changes in the
  repository layout, or if users are required to change their workflow config
  when upgrading to the new version of an existing action.

Alternatively, you can run the [release workflow](https://github.com/hyland/github-actions-ensure-sha-pinned-actions/actions/workflows/release.yml) manually, specifying the desired release type.
