#!/usr/bin/env python
"""Unit tests for GitHub Actions SHA Converter."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from gha_sha_convert import GitHubActionsConverter


class TestGitHubActionsConverter(unittest.TestCase):
    """Test cases for GitHubActionsConverter."""

    def setUp(self):
        """Set up test fixtures."""
        self.converter = GitHubActionsConverter(
            token='fake-token', force=False,
        )

    def test_extract_owner_repo(self):
        """Test owner/repo extraction from action references."""
        test_cases = [
            ('actions/checkout', 'actions/checkout'),
            ('actions/checkout/subpath', 'actions/checkout'),
            ('owner/repo/path/to/action', 'owner/repo'),
            ('simple-action', 'simple-action'),
        ]

        for action_ref, expected in test_cases:
            with self.subTest(action_ref=action_ref):
                result = self.converter.extract_owner_repo(action_ref)
                self.assertEqual(result, expected)

    def test_is_semver(self):
        """Test semantic version detection."""
        test_cases = [
            ('v1.2.3', True),
            ('1.2.3', True),
            ('v1.2.3-alpha', True),
            ('v1.2', False),
            ('v1', False),
            ('main', False),
            ('abcd1234', False),
        ]

        for version, expected in test_cases:
            with self.subTest(version=version):
                result = self.converter.is_semver(version)
                self.assertEqual(result, expected)

    def test_is_sha(self):
        """Test SHA hash detection."""
        test_cases = [
            ('a' * 40, True),
            ('1234567890abcdef1234567890abcdef12345678', True),
            ('v1.2.3', False),
            ('main', False),
            ('a' * 39, False),  # Too short
            ('a' * 41, False),  # Too long
            ('G' * 40, False),  # Invalid character
        ]

        for version, expected in test_cases:
            with self.subTest(version=version):
                result = self.converter.is_sha(version)
                self.assertEqual(result, expected)

    def test_find_yaml_files(self):
        """Test YAML file discovery."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create test directory structure
            workflows_dir = tmp_path / '.github' / 'workflows'
            actions_dir = tmp_path / '.github' / 'actions'
            my_action_dir = actions_dir / 'my-action'
            workflows_dir.mkdir(parents=True)
            my_action_dir.mkdir(parents=True)

            # Create test files matching the new patterns
            (workflows_dir / 'test.yml').touch()  # .github/workflows/*.yml
            (workflows_dir / 'test.yaml').touch()  # .github/workflows/*.yaml
            (my_action_dir / 'action.yml').touch()  # .github/actions/*/action.yml
            (my_action_dir / 'action.yaml').touch()  # .github/actions/*/action.yaml
            (tmp_path / 'action.yml').touch()  # root level action.yml
            (tmp_path / 'action.yaml').touch()  # root level action.yaml

            # Files that should NOT be found
            (actions_dir / 'other.yml').touch()  # Direct in actions dir (not nested)
            (tmp_path / 'other.yml').touch()  # Random YAML file
            (my_action_dir / 'other.yml').touch()  # Wrong filename in action dir

            files = self.converter.find_yaml_files(tmp_path)
            file_paths = [str(f.relative_to(tmp_path)) for f in files]

            # Should find these files
            self.assertIn('.github/workflows/test.yml', file_paths)
            self.assertIn('.github/workflows/test.yaml', file_paths)
            self.assertIn('.github/actions/my-action/action.yml', file_paths)
            self.assertIn('.github/actions/my-action/action.yaml', file_paths)
            self.assertIn('action.yml', file_paths)
            self.assertIn('action.yaml', file_paths)

            # Should NOT find these files
            self.assertNotIn('.github/actions/other.yml', file_paths)
            self.assertNotIn('other.yml', file_paths)
            self.assertNotIn('.github/actions/my-action/other.yml', file_paths)

    @patch('gha_sha_convert.requests.Session.get')
    def test_get_sha_for_tag_direct_commit(self, mock_get):
        """Test getting SHA for a tag that points directly to a commit."""
        # Mock API response for direct commit reference
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'object': {'type': 'commit', 'sha': 'a' * 40},
        }
        mock_get.return_value = mock_response

        sha = self.converter.get_sha_for_tag('owner/repo', 'v1.0.0')
        self.assertEqual(sha, 'a' * 40)

        # Verify caching
        sha2 = self.converter.get_sha_for_tag('owner/repo', 'v1.0.0')
        self.assertEqual(sha2, 'a' * 40)
        self.assertEqual(mock_get.call_count, 1)  # Should be cached

    @patch('gha_sha_convert.requests.Session.get')
    def test_get_sha_for_tag_annotated_tag(self, mock_get):
        """Test getting SHA for an annotated tag."""
        # Mock API responses for annotated tag
        tag_response = Mock()
        tag_response.status_code = 200
        tag_response.json.return_value = {
            'object': {
                'type': 'tag',
                'url': 'https://api.github.com/repos/owner/repo/git/tags/abc123',
            },
        }

        commit_response = Mock()
        commit_response.status_code = 200
        commit_response.json.return_value = {'object': {'sha': 'b' * 40}}

        mock_get.side_effect = [tag_response, commit_response]

        sha = self.converter.get_sha_for_tag('owner/repo', 'v1.0.0')
        self.assertEqual(sha, 'b' * 40)
        self.assertEqual(mock_get.call_count, 2)

    @patch('gha_sha_convert.requests.Session.get')
    def test_get_sha_for_tag_not_found(self, mock_get):
        """Test handling of tag not found."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        sha = self.converter.get_sha_for_tag('owner/repo', 'nonexistent')
        self.assertIsNone(sha)

    @patch('gha_sha_convert.requests.Session.get')
    def test_get_sha_for_tag_auth_failure(self, mock_get):
        """Test handling of authentication failure (401)."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        # Should increment auth_failures counter
        initial_failures = self.converter.auth_failures
        sha = self.converter.get_sha_for_tag('owner/repo', 'v1.0.0')

        self.assertIsNone(sha)
        self.assertEqual(self.converter.auth_failures, initial_failures + 1)

    @patch('gha_sha_convert.requests.Session.get')
    def test_find_best_version_for_sha_auth_failure(self, mock_get):
        """Test handling of authentication failure in version lookup."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        # Should increment auth_failures counter and return current_ref
        initial_failures = self.converter.auth_failures
        result = self.converter.find_best_version_for_sha('owner/repo', 'a' * 40, 'v1.0.0')

        self.assertEqual(result, 'v1.0.0')  # Should return current_ref
        self.assertEqual(self.converter.auth_failures, initial_failures + 1)

    @patch('gha_sha_convert.requests.Session.get')
    def test_find_best_version_for_sha(self, mock_get):
        """Test finding best semantic version for a SHA."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {'name': 'v1.2.3', 'commit': {'sha': 'a' * 40}},
            {'name': 'v1.2.4', 'commit': {'sha': 'b' * 40}},
            {'name': 'v1.3.0', 'commit': {'sha': 'a' * 40}},
            {'name': '1.2.3-alpha', 'commit': {'sha': 'a' * 40}},
        ]
        mock_get.return_value = mock_response

        # Should return the most recent semantic version when no pattern matching
        version = self.converter.find_best_version_for_sha(
            'owner/repo', 'a' * 40, 'main',  # Use a non-versioned ref
        )
        self.assertEqual(version, 'v1.3.0')

    def test_process_file_basic(self):
        """Test basic file processing."""
        test_content = """name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3.1.0 # v3.1.0
"""

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.yml', delete=False,
        ) as tmp_file:
            tmp_file.write(test_content)
            tmp_file.flush()

            with patch.object(
                self.converter, 'get_sha_for_tag',
            ) as mock_get_sha, patch.object(
                self.converter, 'find_best_version_for_sha',
            ) as mock_find_version:

                mock_get_sha.return_value = 'a' * 40
                mock_find_version.return_value = 'v3.1.0'

                changes = self.converter.process_file(Path(tmp_file.name))

                # Read back the file content
                updated_content = Path(tmp_file.name).read_text()

                # Should have SHA references now
                self.assertIn(f"actions/checkout@{'a' * 40}", updated_content)
                self.assertIn(
                    f"actions/setup-node@{'a' * 40}", updated_content,
                )
                self.assertGreater(changes, 0)

            # Clean up
            os.unlink(tmp_file.name)

    def test_process_file_already_sha(self):
        """Test processing file with existing SHA references."""
        sha = 'a' * 40
        test_content = f"""name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{sha} # v3.1.0
"""

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.yml', delete=False,
        ) as tmp_file:
            tmp_file.write(test_content)
            tmp_file.flush()

            changes = self.converter.process_file(Path(tmp_file.name))

            # Should not make changes if already using SHA with semver
            self.assertEqual(changes, 0)

            # Clean up
            os.unlink(tmp_file.name)

    def test_process_file_force_mode(self):
        """Test processing file in force mode."""
        sha = 'a' * 40
        test_content = f"""name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{sha} # v3.1.0
"""

        converter = GitHubActionsConverter(token='fake-token', force=True)

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.yml', delete=False,
        ) as tmp_file:
            tmp_file.write(test_content)
            tmp_file.flush()

            with patch.object(
                converter, 'get_sha_for_tag',
            ) as mock_get_sha, patch.object(
                converter, 'find_best_version_for_sha',
            ) as mock_find_version:

                mock_get_sha.return_value = 'b' * 40  # Different SHA
                mock_find_version.return_value = 'v3.2.0'  # Different version

                changes = converter.process_file(Path(tmp_file.name))

                # Should make changes even with existing SHA in force mode
                updated_content = Path(tmp_file.name).read_text()
                self.assertIn(f"actions/checkout@{'b' * 40}", updated_content)
                self.assertIn('v3.2.0', updated_content)
                self.assertGreater(changes, 0)

            # Clean up
            os.unlink(tmp_file.name)

    def test_process_directory(self):
        """Test processing an entire directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Create test directory structure
            workflows_dir = tmp_path / '.github' / 'workflows'
            workflows_dir.mkdir(parents=True)

            # Create test workflow file
            test_content = """name: Test
on: [push]
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
"""
            (workflows_dir / 'test.yml').write_text(test_content)

            with patch.object(
                self.converter, 'get_sha_for_tag',
            ) as mock_get_sha, patch.object(
                self.converter, 'find_best_version_for_sha',
            ) as mock_find_version:

                mock_get_sha.return_value = 'a' * 40
                mock_find_version.return_value = 'v3.0.0'

                total_changes = self.converter.process_directory(tmp_path)

                self.assertGreater(total_changes, 0)


class TestMainFunction(unittest.TestCase):
    """Test the main function and CLI interface."""

    @patch('gha_sha_convert.GitHubActionsConverter')
    @patch('sys.argv', ['gha_sha_convert.py', '--force'])
    def test_main_with_force_flag(self, mock_converter_class):
        """Test main function with force flag."""
        mock_converter = Mock()
        mock_converter.process_directory.return_value = 0
        mock_converter.find_yaml_files.return_value = []
        mock_converter.discovery_mode = False
        mock_converter.dry_run_mode = False
        mock_converter.auth_failures = 0  # Add auth_failures attribute
        mock_converter_class.return_value = mock_converter

        with patch('os.environ.get', return_value='fake-token'):
            from gha_sha_convert import main

            with self.assertRaises(SystemExit) as cm:
                main()

            # Should exit with 0 for no changes
            self.assertEqual(cm.exception.code, 0)
            mock_converter_class.assert_called_once_with(
                token='fake-token', force=True, allowlist=[],
            )

    @patch('gha_sha_convert.GitHubActionsConverter')
    @patch('sys.argv', ['gha_sha_convert.py', 'test.yml'])
    def test_main_with_specific_files(self, mock_converter_class):
        """Test main function with specific files."""
        mock_converter = Mock()
        mock_converter.process_file.return_value = 1
        mock_converter.auth_failures = 0  # Add auth_failures attribute
        mock_converter_class.return_value = mock_converter

        # Create a temporary test file
        with tempfile.NamedTemporaryFile(suffix='.yml', delete=False) as tmp_file:
            tmp_file.write(b'test content')
            tmp_file.flush()

            try:
                with patch('sys.argv', ['gha_sha_convert.py', tmp_file.name]):
                    with patch('os.environ.get', return_value='fake-token'):
                        from gha_sha_convert import main

                        with self.assertRaises(SystemExit) as cm:
                            main()

                        # Should exit with 1 for changes made
                        self.assertEqual(cm.exception.code, 1)
            finally:
                os.unlink(tmp_file.name)


class TestNewFeatures(unittest.TestCase):
    """Test new features added from TODO comments."""

    def setUp(self):
        """Set up test fixtures."""
        self.converter = GitHubActionsConverter(
            token='fake-token', force=False,
        )

    def test_discovery_mode(self):
        """Test discovery mode functionality."""
        self.converter.discovery_mode = True

        test_content = """name: Test
on: [push]
jobs:
  test:
    steps:
      - uses: actions/checkout@v3
"""

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.yml', delete=False,
        ) as tmp_file:
            tmp_file.write(test_content)
            tmp_file.flush()

            changes = self.converter.process_file(Path(tmp_file.name))

            # Discovery mode should report issues that need conversion
            self.assertEqual(changes, 1)  # actions/checkout@v3 needs conversion

            # File content should remain unchanged
            updated_content = Path(tmp_file.name).read_text()
            self.assertEqual(updated_content, test_content)

            # Clean up
            os.unlink(tmp_file.name)

    @patch('sys.argv', ['gha_sha_convert.py', '--discovery'])
    def test_main_discovery_mode(self):
        """Test main function with discovery mode."""
        with patch('gha_sha_convert.GitHubActionsConverter') as mock_converter_class:
            mock_converter = Mock()
            mock_converter.find_yaml_files.return_value = []
            mock_converter.process_directory.return_value = 0
            mock_converter.auth_failures = 0  # Add auth_failures attribute
            mock_converter_class.return_value = mock_converter

            from gha_sha_convert import main

            with self.assertRaises(SystemExit) as cm:
                main()

            # Should exit with 0 for discovery mode
            self.assertEqual(cm.exception.code, 0)
            # Should be called with no token in discovery mode
            mock_converter_class.assert_called_once_with(
                token=None, force=False, allowlist=[],
            )

    @patch('sys.argv', ['gha_sha_convert.py', '--dry-run'])
    def test_main_auth_failure_exit_code(self):
        """Test main function exits with code 2 when authentication failures occur."""
        with patch('gha_sha_convert.GitHubActionsConverter') as mock_converter_class:
            mock_converter = Mock()
            mock_converter.find_yaml_files.return_value = []
            mock_converter.process_directory.return_value = 0
            mock_converter.auth_failures = 3  # Simulate authentication failures
            mock_converter_class.return_value = mock_converter

            with patch('os.environ.get', return_value='fake-token'):
                from gha_sha_convert import main

                with self.assertRaises(SystemExit) as cm:
                    main()

                # Should exit with 2 for authentication failures
                self.assertEqual(cm.exception.code, 2)

    @patch('sys.argv', ['gha_sha_convert.py'])
    def test_main_combined_errors_exit_code(self):
        """Test main function exits with code 2 when both file errors and auth failures occur."""
        with patch('gha_sha_convert.GitHubActionsConverter') as mock_converter_class:
            mock_converter = Mock()
            mock_converter.find_yaml_files.return_value = []
            mock_converter.process_directory.side_effect = Exception('File error')
            mock_converter.auth_failures = 1  # Also has auth failures
            mock_converter_class.return_value = mock_converter

            with patch('os.environ.get', return_value='fake-token'):
                from gha_sha_convert import main

                with self.assertRaises(SystemExit) as cm:
                    main()

                # Should exit with 2 for errors (either type)
                self.assertEqual(cm.exception.code, 2)

    def test_is_allowlisted(self):
        """Test allowlist pattern matching."""
        allowlist = [
            'actions/*',
            'Alfresco/alfresco-build-tools/*',
            'specific/action@v1.0.0',
        ]
        converter = GitHubActionsConverter(allowlist=allowlist)

        # Test wildcard patterns
        self.assertTrue(converter.is_allowlisted('actions/checkout'))
        self.assertTrue(converter.is_allowlisted('actions/setup-python'))
        self.assertTrue(
            converter.is_allowlisted('Alfresco/alfresco-build-tools/action'),
        )

        # Test exact patterns
        self.assertTrue(converter.is_allowlisted('specific/action@v1.0.0'))

        # Test non-matching patterns
        self.assertFalse(converter.is_allowlisted('other/action'))
        self.assertFalse(converter.is_allowlisted('specific/action@v2.0.0'))

    def test_allowlist_processing(self):
        """Test that allowlisted actions are skipped during processing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(
                """
name: Test Workflow
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: my-org/custom-action@v1.0.0
""",
            )
            temp_file = f.name

        try:
            allowlist = ['actions/*']
            converter = GitHubActionsConverter(allowlist=allowlist)
            converter.discovery_mode = True

            # Should process only the non-allowlisted action
            changes = converter.process_file(Path(temp_file))
            self.assertEqual(changes, 1)  # my-org/custom-action@v1.0.0 needs conversion

            # Test the actual allowlist behavior by checking output
            # The allowlisted action should be skipped
            content = Path(temp_file).read_text()
            # Should remain unchanged
            self.assertIn('actions/checkout@v3', content)
            self.assertIn(
                'my-org/custom-action@v1.0.0', content,
            )  # Should remain unchanged

        finally:
            os.unlink(temp_file)


class TestModeSelectionLogic(unittest.TestCase):
    """Test cases for mode selection logic in main function."""

    def setUp(self):
        """Set up test fixtures."""
        # Clear any cached modules
        if 'gha_sha_convert' in sys.modules:
            del sys.modules['gha_sha_convert']

    @patch('sys.argv', ['gha_sha_convert.py', '--dry-run'])
    @patch('os.environ.get', return_value='fake-token')
    def test_dry_run_mode_with_token(self, mock_env):
        """Test dry-run mode with token available."""
        with patch('gha_sha_convert.GitHubActionsConverter') as mock_converter_class:
            mock_converter = Mock()
            mock_converter.find_yaml_files.return_value = []
            mock_converter.process_directory.return_value = 0
            mock_converter.auth_failures = 0
            mock_converter_class.return_value = mock_converter

            from gha_sha_convert import main

            with self.assertRaises(SystemExit):
                main()

            # Should be called with token and dry_run_mode=True
            mock_converter_class.assert_called_once_with(
                token='fake-token', force=False, allowlist=[],
            )
            self.assertTrue(mock_converter.dry_run_mode)
            self.assertFalse(mock_converter.discovery_mode)

    @patch('sys.argv', ['gha_sha_convert.py', '--dry-run'])
    @patch('os.environ.get', return_value=None)
    def test_dry_run_mode_without_token_fallback_to_discovery(self, mock_env):
        """Test dry-run mode without token falls back to discovery mode."""
        with patch('gha_sha_convert.GitHubActionsConverter') as mock_converter_class:
            mock_converter = Mock()
            mock_converter.find_yaml_files.return_value = []
            mock_converter.process_directory.return_value = 0
            mock_converter.auth_failures = 0
            mock_converter_class.return_value = mock_converter

            from gha_sha_convert import main

            with self.assertRaises(SystemExit):
                main()

            # Should be called with no token and discovery_mode=True
            mock_converter_class.assert_called_once_with(
                token=None, force=False, allowlist=[],
            )
            self.assertTrue(mock_converter.discovery_mode)
            self.assertFalse(mock_converter.dry_run_mode)

    @patch('sys.argv', ['gha_sha_convert.py', '--discovery'])
    @patch('os.environ.get', return_value='fake-token')
    def test_discovery_mode_ignores_token(self, mock_env):
        """Test discovery mode ignores token and sets discovery_mode=True."""
        with patch('gha_sha_convert.GitHubActionsConverter') as mock_converter_class:
            mock_converter = Mock()
            mock_converter.find_yaml_files.return_value = []
            mock_converter.process_directory.return_value = 0
            mock_converter.auth_failures = 0
            mock_converter_class.return_value = mock_converter

            from gha_sha_convert import main

            with self.assertRaises(SystemExit):
                main()

            # Should be called with no token even when token is available
            mock_converter_class.assert_called_once_with(
                token=None, force=False, allowlist=[],
            )
            self.assertTrue(mock_converter.discovery_mode)
            self.assertFalse(mock_converter.dry_run_mode)

    @patch('sys.argv', ['gha_sha_convert.py'])
    @patch('os.environ.get', return_value='fake-token')
    def test_normal_mode_with_token(self, mock_env):
        """Test normal mode with token available."""
        with patch('gha_sha_convert.GitHubActionsConverter') as mock_converter_class:
            mock_converter = Mock()
            mock_converter.find_yaml_files.return_value = []
            mock_converter.process_directory.return_value = 0
            mock_converter.auth_failures = 0
            mock_converter_class.return_value = mock_converter

            from gha_sha_convert import main

            with self.assertRaises(SystemExit):
                main()

            # Should be called with token and both modes=False
            mock_converter_class.assert_called_once_with(
                token='fake-token', force=False, allowlist=[],
            )
            self.assertFalse(mock_converter.discovery_mode)
            self.assertFalse(mock_converter.dry_run_mode)

    @patch('sys.argv', ['gha_sha_convert.py'])
    @patch('os.environ.get', return_value=None)
    def test_normal_mode_without_token(self, mock_env):
        """Test normal mode without token."""
        with patch('gha_sha_convert.GitHubActionsConverter') as mock_converter_class:
            mock_converter = Mock()
            mock_converter.find_yaml_files.return_value = []
            mock_converter.process_directory.return_value = 0
            mock_converter.auth_failures = 0
            mock_converter_class.return_value = mock_converter

            from gha_sha_convert import main

            with self.assertRaises(SystemExit):
                main()

            # Should be called with no token and both modes=False
            mock_converter_class.assert_called_once_with(
                token=None, force=False, allowlist=[],
            )
            self.assertFalse(mock_converter.discovery_mode)
            self.assertFalse(mock_converter.dry_run_mode)

    @patch('sys.argv', ['gha_sha_convert.py', '--dry-run', '--discovery'])
    @patch('os.environ.get', return_value='fake-token')
    def test_dry_run_takes_precedence_over_discovery(self, mock_env):
        """Test that dry-run mode takes precedence when both flags are provided."""
        with patch('gha_sha_convert.GitHubActionsConverter') as mock_converter_class:
            mock_converter = Mock()
            mock_converter.find_yaml_files.return_value = []
            mock_converter.process_directory.return_value = 0
            mock_converter.auth_failures = 0
            mock_converter_class.return_value = mock_converter

            from gha_sha_convert import main

            with self.assertRaises(SystemExit):
                main()

            # Should be in dry-run mode, not discovery mode (dry-run takes precedence)
            mock_converter_class.assert_called_once_with(
                token='fake-token', force=False, allowlist=[],
            )
            self.assertTrue(mock_converter.dry_run_mode)
            self.assertFalse(mock_converter.discovery_mode)


if __name__ == '__main__':
    unittest.main()
