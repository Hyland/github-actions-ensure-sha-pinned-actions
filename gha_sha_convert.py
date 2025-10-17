#!/usr/bin/env python
"""GitHub Actions SHA Converter.

Converts GitHub Actions to use SHA-pinned versions for security.
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logger = logging.getLogger(__name__)


class GitHubActionsConverter:
    """Converts GitHub Actions references to SHA-pinned versions."""

    def __init__(
        self,
        token: str | None = None,
        force: bool = False,
        allowlist: list[str] | None = None,
    ):
        """Initialize the converter.

        Args:
            token: GitHub token for API access
            force: Force conversion even if already using SHA
            allowlist: List of action patterns to exclude from conversion
        """
        self.token = token or os.environ.get('GITHUB_TOKEN')
        self.force = force
        self.discovery_mode = False
        self.dry_run_mode = False
        self.exclude_first_party = False
        self.allowlist = allowlist or []
        self.session = self._create_session()
        self.cache: dict[str, str] = {}
        self.auth_failures = 0  # Track authentication failures

        # Pre-compile regex patterns for better performance
        self.action_pattern = re.compile(r'uses:\s*([^@\s]+)@([^\s#]+)(?:\s*#\s*([^\s]+))?')
        self.sha_pattern = re.compile(r'^[a-f0-9]{40}$')
        self.semver_pattern = re.compile(r'^v?\d+\.\d+\.\d+')

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy."""
        session = requests.Session()
        retry_strategy = Retry(
            total=3, status_forcelist=[429, 500, 502, 503, 504], backoff_factor=1,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        if self.token:
            session.headers.update({'Authorization': f"token {self.token}"})

        return session

    def find_yaml_files(self, base_path: Path) -> list[Path]:
        """Find all YAML workflow and action files."""
        patterns = [
            'action.yml',
            'action.yaml',
            '.github/workflows/*.yml',
            '.github/workflows/*.yaml',
            '.github/actions/*/action.yml',
            '.github/actions/*/action.yaml',
        ]

        files = []
        for pattern in patterns:
            files.extend(base_path.glob(pattern))
        return files

    def extract_owner_repo(self, action_ref: str) -> str:
        """Extract owner/repo from action reference.

        Args:
            action_ref: Action reference like 'owner/repo/subpath'

        Returns:
            Owner/repo portion
        """
        parts = action_ref.split('/')
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return action_ref

    def is_semver(self, version: str) -> bool:
        """Check if version string is semantic version."""
        return bool(self.semver_pattern.match(version))

    def is_sha(self, version: str) -> bool:
        """Check if version string is a SHA hash."""
        return bool(self.sha_pattern.match(version))

    def is_first_party_action(self, action_ref: str) -> bool:
        """Check if action is from a first-party/trusted organization."""
        first_party_orgs = [
            'actions/',
            'microsoft/',
            'azure/',
            'github/',
            'docker/',
            'aws-actions/',
            'google-github-actions/',
            'hashicorp/',
        ]
        return any(action_ref.startswith(org) for org in first_party_orgs)

    def is_allowlisted(self, action_ref: str) -> bool:
        """Check if action matches any allowlist pattern."""
        if not self.allowlist:
            return False

        # Extract the full action reference for matching
        import fnmatch

        for pattern in self.allowlist:
            pattern = pattern.strip()
            if not pattern or pattern.startswith('#'):
                continue

            # Support wildcard matching
            if fnmatch.fnmatch(action_ref, pattern):
                return True

            # Support exact matching
            if action_ref == pattern:
                return True

            # Support owner/* patterns
            if pattern.endswith('/*') and action_ref.startswith(pattern[:-1]):
                return True

        return False

    def get_sha_for_tag(self, owner_repo: str, tag: str) -> str | None:
        """Get SHA hash for a given tag.

        Args:
            owner_repo: Repository in format 'owner/repo'
            tag: Git tag name

        Returns:
            SHA hash or None if not found
        """
        cache_key = f"{owner_repo}@{tag}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        try:
            # First try getting the tag reference
            url = f"https://api.github.com/repos/{owner_repo}/git/refs/tags/{tag}"
            response = self.session.get(url)

            if response.status_code == 404:
                logger.warning('Tag %s not found for %s', tag, owner_repo)
                return None
            elif response.status_code == 401:
                logger.error(
                    'GitHub API authentication failed for %s@%s (status 401)',
                    owner_repo, tag,
                )
                self.auth_failures += 1
                return None
            elif response.status_code == 429:
                logger.error('GitHub API rate limit exceeded')
                sys.exit(1)
            elif response.status_code >= 400:
                logger.error(
                    'GitHub API request failed with status %d for %s@%s',
                    response.status_code, owner_repo, tag,
                )
                return None

            data = response.json()

            # Handle both single tag and array responses
            if isinstance(data, list):
                data = data[0]

            obj_type = data.get('object', {}).get('type')

            if obj_type == 'tag':
                # Annotated tag - need to get the commit it points to
                tag_url = data['object']['url']
                tag_response = self.session.get(tag_url)
                if tag_response.status_code == 200:
                    tag_data = tag_response.json()
                    sha = tag_data.get('object', {}).get('sha')
                else:
                    logger.warning('Failed to resolve annotated tag %s for %s', tag, owner_repo)
                    return None
            else:
                # Direct commit reference
                sha = data.get('object', {}).get('sha')

            if sha and len(sha) == 40:
                self.cache[cache_key] = sha
                return sha

        except requests.exceptions.RequestException as e:
            logger.error('GitHub API request failed for %s@%s: %s', owner_repo, tag, e)
        except Exception as e:
            logger.error('Unexpected error getting SHA for %s@%s: %s', owner_repo, tag, e)

        return None

    def find_best_version_for_sha(
        self, owner_repo: str, sha: str, current_ref: str,
    ) -> str:
        """Find the best semantic version for a SHA.

        Args:
            owner_repo: Repository in format 'owner/repo'
            sha: SHA hash to find version for
            current_ref: Current reference being used

        Returns:
            Best version string for comments
        """
        try:
            url = f"https://api.github.com/repos/{owner_repo}/tags"
            response = self.session.get(url)

            if response.status_code == 401:
                logger.error(
                    'GitHub API authentication failed for %s (status 401)',
                    owner_repo,
                )
                self.auth_failures += 1
                return current_ref
            elif response.status_code != 200:
                return current_ref

            tags = response.json()
            matching_tags = [
                tag['name'] for tag in tags if tag.get('commit', {}).get('sha') == sha
            ]

            if not matching_tags:
                return current_ref

            # Try to find a semantic version that matches the pattern
            if current_ref and not self.is_semver(current_ref):
                dots = current_ref.count('.')
                if dots == 0:
                    pattern = re.compile(
                        rf"{re.escape(current_ref)}\.\d+\.\d+",
                    )
                elif dots == 1:
                    pattern = re.compile(rf"{re.escape(current_ref)}\.\d+")
                else:
                    pattern = None

                if pattern:
                    pattern_matches = [
                        tag for tag in matching_tags if pattern.match(tag)
                    ]
                    if pattern_matches:
                        return sorted(pattern_matches, reverse=True)[0]

            # Sort tags and return the first (most recent) semantic version
            semver_tags = [tag for tag in matching_tags if self.is_semver(tag)]
            if semver_tags:
                # Sort by semantic version properly - higher versions first
                def version_key(v):
                    """Extracts a tuple of integers from a semantic version string for sorting.

                    Args:
                        v: Version string (e.g., 'v1.2.3' or '1.2.3-beta')

                    Returns:
                        Tuple of integers representing the version (major, minor, patch)
                    """
                    # Remove 'v' prefix if present and split into parts
                    clean_v = v.lstrip('v')
                    try:
                        # Only take the main version parts (ignore pre-release suffixes)
                        main_version = clean_v.split('-')[0]
                        parts = [int(x) for x in main_version.split('.')]
                        # Pad to 3 parts if needed
                        while len(parts) < 3:
                            parts.append(0)
                        return tuple(parts)
                    except Exception:
                        return (0, 0, 0)

                return sorted(semver_tags, key=version_key, reverse=True)[0]

            # Fall back to any version
            return sorted(matching_tags, reverse=True)[0]

        except requests.exceptions.RequestException as e:
            logger.error('GitHub API request failed for %s@%s: %s', owner_repo, sha, e)
            return current_ref
        except Exception as e:
            logger.error('Unexpected error finding version for %s@%s: %s', owner_repo, sha, e)
            return current_ref

    def process_file(self, file_path: Path) -> int:
        """Process a single YAML file.

        Args:
            file_path: Path to the YAML file

        Returns:
            Number of changes made
        """
        logger.info('Processing file: %s', file_path)

        try:
            content = file_path.read_text()
        except OSError as e:
            logger.error('Error reading file %s: %s', file_path, e)
            return 0

        # Find all action references using pre-compiled pattern
        matches = self.action_pattern.findall(content)

        if not matches:
            logger.debug('No action references found in %s', file_path)
            return 0

        covered: set[str] = set()
        changes = 0

        for action_ref, version, comment_version in matches:
            # Handle case where comment_version might be None
            comment_version = comment_version or ''

            original_line = f"uses: {action_ref}@{version}"
            if comment_version:
                original_line += f" # {comment_version}"

            if original_line in covered:
                logger.debug('Skipping %s, already processed', original_line)
                continue

            covered.add(original_line)

            # Check if this is a first-party action that should be excluded
            if self.exclude_first_party and self.is_first_party_action(action_ref):
                logger.info('Skipping first-party action: %s', action_ref)
                continue

            # Check if this action is allowlisted (should be excluded)
            if self.is_allowlisted(action_ref):
                logger.info('Skipping allowlisted action: %s', action_ref)
                continue

            owner_repo = self.extract_owner_repo(action_ref)

            # In discovery mode, just report what would be processed
            if self.discovery_mode:
                ref = comment_version if comment_version else version
                status = (
                    'SHA+semver'
                    if (
                        self.is_sha(version)
                        and comment_version
                        and self.is_semver(comment_version)
                    )
                    else 'needs conversion'
                )
                logger.info('Found: %s@%s (%s)', action_ref, version, status)
                # Count actions that need conversion as changes for validation
                if status == 'needs conversion':
                    changes += 1
                continue

            # Determine the reference to use for SHA lookup
            ref = comment_version if comment_version else version

            # Skip if already using SHA and has semantic version comment
            if (
                self.is_sha(version)
                and not self.force
                and comment_version
                and self.is_semver(comment_version)
            ):
                logger.debug(
                    '%s@%s # %s already using SHA with semver, skipping',
                    owner_repo, version, comment_version,
                )
                continue

            # Get SHA for the reference
            if self.is_sha(version) and not self.force:
                sha = version
            else:
                if not self.token:
                    logger.warning('No GitHub token provided, skipping API calls for %s', action_ref)
                    continue

                sha = self.get_sha_for_tag(owner_repo, ref)
                if not sha:
                    logger.warning('Could not resolve SHA for %s@%s', owner_repo, ref)
                    continue

            # Find best version for comment
            final_version = self.find_best_version_for_sha(
                owner_repo, sha, ref,
            )

            # Create the replacement
            new_line = f"uses: {action_ref}@{sha} # {final_version}"

            if original_line != new_line:
                if self.dry_run_mode:
                    logger.info("Would update: '%s' -> '%s'", original_line, new_line)
                    changes += 1
                else:
                    logger.info("Updating '%s' -> '%s'", original_line, new_line)
                    content = content.replace(original_line, new_line)
                    changes += 1

        if changes > 0 and not self.discovery_mode and not self.dry_run_mode:
            try:
                file_path.write_text(content)
                logger.info('Updated %s with %d changes', file_path, changes)
            except OSError as e:
                logger.error('Error writing file %s: %s', file_path, e)
                return 0

        return changes

    def process_directory(self, base_path: Path) -> int:
        """Process all YAML files in a directory.

        Args:
            base_path: Base directory to search

        Returns:
            Total number of changes made
        """
        yaml_files = self.find_yaml_files(base_path)

        if not yaml_files:
            logger.info('No YAML workflow or action files found in %s', base_path)
            return 0

        total_changes = 0
        for file_path in yaml_files:
            try:
                changes = self.process_file(file_path)
                total_changes += changes
            except Exception as e:
                logger.error('Error processing file %s: %s', file_path, e)
                # Continue processing other files

        return total_changes


def main():
    """Main entry point for the pre-commit hook."""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s',
        handlers=[logging.StreamHandler()],
    )

    parser = argparse.ArgumentParser(
        description='Convert GitHub Actions to use SHA-pinned versions',
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force conversion even if already using SHA',
    )
    parser.add_argument(
        '--token', help='GitHub token (default: GITHUB_TOKEN environment variable)',
    )
    parser.add_argument(
        '--path',
        action='append',
        help='Path to search for workflow files (can be specified multiple times)',
    )
    parser.add_argument(
        '--discovery',
        action='store_true',
        help='Discovery mode: scan files but make no API calls or changes',
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging',
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Dry run mode: make API calls but no file changes',
    )
    parser.add_argument(
        '--exclude-first-party',
        action='store_true',
        help='Exclude first-party actions (actions/, microsoft/, azure/, etc.)',
    )
    parser.add_argument(
        '--allowlist',
        help='Path to file containing allowlist patterns (one per line) or comma-separated patterns',
    )
    parser.add_argument(
        'files',
        nargs='*',
        help='Specific files to process (default: search workflow directories)',
    )

    args = parser.parse_args()

    # Set up verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Get GitHub token
    token = args.token or os.environ.get('GITHUB_TOKEN')

    if args.discovery:
        logger.info('Discovery mode: scanning files without API calls or changes')
        token = None
    elif not token:
        if args.dry_run:
            logger.error('--dry-run requires a GitHub token')
            sys.exit(1)
        else:
            logger.warning('GITHUB_TOKEN not set. Limited functionality available.')

    # Parse allowlist if provided
    allowlist = []
    if args.allowlist:
        try:
            # Check if it's a file path
            allowlist_path = Path(args.allowlist)
            if allowlist_path.exists():
                # Read from file
                allowlist_content = allowlist_path.read_text().strip()
                allowlist = [
                    line.strip()
                    for line in allowlist_content.split('\n')
                    if line.strip() and not line.strip().startswith('#')
                ]
                logger.info(
                    'Loaded %d patterns from allowlist file: %s',
                    len(allowlist), allowlist_path,
                )
            else:
                # Treat as comma-separated patterns
                allowlist = [
                    pattern.strip()
                    for pattern in args.allowlist.split(',')
                    if pattern.strip()
                ]
                logger.info(
                    'Using %d allowlist patterns from command line',
                    len(allowlist),
                )

            if allowlist:
                logger.debug('Allowlist patterns: %s', allowlist)
        except Exception as e:
            logger.error('Error processing allowlist: %s', e)
            sys.exit(1)

    # Initialize converter
    converter = GitHubActionsConverter(
        token=token, force=args.force, allowlist=allowlist,
    )
    converter.discovery_mode = args.discovery
    converter.dry_run_mode = args.dry_run
    converter.exclude_first_party = args.exclude_first_party

    total_changes = 0
    files_processed = 0
    errors_encountered = 0

    if args.files:
        # Process specific files
        for file_path in args.files:
            path = Path(file_path)
            if path.exists() and path.suffix in ['.yml', '.yaml']:
                try:
                    changes = converter.process_file(path)
                    total_changes += changes
                    files_processed += 1
                except Exception as e:
                    logger.error('Error processing file %s: %s', file_path, e)
                    errors_encountered += 1
    else:
        # Process directories
        search_paths = args.path or ['.']

        for search_path in search_paths:
            try:
                path = Path(search_path)
                if path.is_file() and path.suffix in ['.yml', '.yaml']:
                    changes = converter.process_file(path)
                    total_changes += changes
                    files_processed += 1
                elif path.is_dir():
                    changes = converter.process_directory(path)
                    total_changes += changes
                    # Count files in directory
                    files_processed += len(converter.find_yaml_files(path))
            except Exception as e:
                logger.error('Error processing %s: %s', search_path, e)
                errors_encountered += 1

    # Print summary
    if args.discovery:
        logger.info('Discovery complete: %d files scanned', files_processed)
    elif args.dry_run:
        logger.info(
            'Dry run complete: %d files processed, %d potential changes',
            files_processed, total_changes,
        )
    else:
        logger.info(
            'Processing complete: %d files processed, %d changes made',
            files_processed, total_changes,
        )

    if errors_encountered > 0:
        logger.warning('Errors encountered: %d', errors_encountered)

    if converter.auth_failures > 0:
        logger.error(
            'Authentication failures: %d (check GITHUB_TOKEN permissions)',
            converter.auth_failures,
        )

    # Exit code handling
    if errors_encountered > 0 or converter.auth_failures > 0:
        sys.exit(2)  # Error exit code
    elif total_changes > 0:
        # Exit 1 if changes are needed (discovery mode, dry-run mode, or normal mode)
        # This indicates non-compliance and should fail CI/pre-commit checks
        sys.exit(1)  # Changes needed or validation issues found (pre-commit convention)
    else:
        sys.exit(0)  # Success - no changes needed


if __name__ == '__main__':
    main()
