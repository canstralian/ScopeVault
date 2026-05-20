#!/usr/bin/env python3
"""
Tests for cli.py — covers code changed in this PR:
  - ALLOWED_TOOLS constant
  - is_allowed_tool()
  - run_cmd() (list-based cmd, shlex.join logging, no shell=True)
  - attack() tool-allowlist enforcement
"""
import os
import sys
import shlex
import tempfile
import types
import unittest
import warnings
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Import cli.py safely: the module runs parser.parse_args() at the top level,
# so we must provide a minimal argv before importing.
# ---------------------------------------------------------------------------
def _import_cli():
    import importlib.util
    cli_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli.py")
    spec = importlib.util.spec_from_file_location("cli", cli_path)
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules *before* exec so that patch("cli.X") resolves
    # to this module object rather than attempting a fresh import.
    sys.modules["cli"] = mod
    with patch("sys.argv", ["cli"]):
        spec.loader.exec_module(mod)
    return mod


cli = _import_cli()


class TestAllowedTools(unittest.TestCase):
    """Tests for the ALLOWED_TOOLS constant."""

    def test_allowed_tools_contains_expected_tools(self):
        expected = {"nuclei", "sqlmap", "ffuf", "nikto", "nmap"}
        self.assertEqual(cli.ALLOWED_TOOLS, expected)

    def test_allowed_tools_is_a_set(self):
        self.assertIsInstance(cli.ALLOWED_TOOLS, set)


class TestIsAllowedTool(unittest.TestCase):
    """Tests for is_allowed_tool()."""

    # --- happy-path: every tool in ALLOWED_TOOLS ---

    def test_nuclei_is_allowed(self):
        self.assertTrue(cli.is_allowed_tool("nuclei"))

    def test_sqlmap_is_allowed(self):
        self.assertTrue(cli.is_allowed_tool("sqlmap"))

    def test_ffuf_is_allowed(self):
        self.assertTrue(cli.is_allowed_tool("ffuf"))

    def test_nikto_is_allowed(self):
        self.assertTrue(cli.is_allowed_tool("nikto"))

    def test_nmap_is_allowed(self):
        self.assertTrue(cli.is_allowed_tool("nmap"))

    # --- rejection: tools not in the allowlist ---

    def test_unknown_tool_rejected(self):
        self.assertFalse(cli.is_allowed_tool("curl"))

    def test_wget_rejected(self):
        self.assertFalse(cli.is_allowed_tool("wget"))

    def test_empty_string_rejected(self):
        self.assertFalse(cli.is_allowed_tool(""))

    def test_bash_rejected(self):
        self.assertFalse(cli.is_allowed_tool("bash"))

    # --- path-traversal / directory-prefix attempts ---

    def test_absolute_path_to_allowed_tool_rejected(self):
        self.assertFalse(cli.is_allowed_tool("/usr/bin/nuclei"))

    def test_relative_path_to_allowed_tool_rejected(self):
        self.assertFalse(cli.is_allowed_tool("../nuclei"))

    def test_subdirectory_path_to_allowed_tool_rejected(self):
        self.assertFalse(cli.is_allowed_tool("tools/nuclei"))

    def test_dotslash_prefix_rejected(self):
        # e.g. ./nuclei — basename is "nuclei" but the caller passes "./nuclei"
        # os.path.basename("./nuclei") == "nuclei" which IS in ALLOWED_TOOLS,
        # but the full value "./nuclei" != "nuclei", so is_allowed_tool returns False.
        self.assertFalse(cli.is_allowed_tool("./nuclei"))

    def test_double_dot_leading_slash_rejected(self):
        self.assertFalse(cli.is_allowed_tool("/nuclei"))

    # --- case sensitivity ---

    def test_uppercase_tool_name_rejected(self):
        self.assertFalse(cli.is_allowed_tool("Nuclei"))

    def test_mixed_case_rejected(self):
        self.assertFalse(cli.is_allowed_tool("NMAP"))

    # --- boundary / regression ---

    def test_tool_name_with_spaces_rejected(self):
        self.assertFalse(cli.is_allowed_tool("nmap -sV"))

    def test_tool_name_with_semicolon_rejected(self):
        # Injection attempt embedded in tool name
        self.assertFalse(cli.is_allowed_tool("nmap;id"))


class TestRunCmd(unittest.TestCase):
    """Tests for run_cmd() — new list-based behaviour, shlex.join logging, no shell=True."""

    def setUp(self):
        # run_cmd does not call p.wait(); suppress the resulting ResourceWarnings
        # that Python emits when the subprocess object is GC'd while still running.
        warnings.simplefilter("ignore", ResourceWarning)

    def _run_with_templog(self, cmd):
        """Helper: run cmd, return (log_contents, return_value)."""
        with tempfile.NamedTemporaryFile(mode="r", suffix=".log", delete=False) as tf:
            log_path = tf.name
        try:
            cli.run_cmd(cmd, log_path)
            with open(log_path) as f:
                contents = f.read()
        finally:
            os.unlink(log_path)
        return contents

    def test_log_header_uses_shlex_join(self):
        """The log must contain the shlex-joined command, not a raw string."""
        cmd = ["echo", "hello world"]
        log = self._run_with_templog(cmd)
        expected_header = f"\n$ {shlex.join(cmd)}\n"
        self.assertIn(expected_header, log)

    def test_log_header_format_with_simple_command(self):
        cmd = ["echo", "test"]
        log = self._run_with_templog(cmd)
        self.assertIn("\n$ echo test\n", log)

    def test_output_is_written_to_log(self):
        """Subprocess stdout should be captured and appended to the log file."""
        cmd = ["echo", "captured_output"]
        log = self._run_with_templog(cmd)
        self.assertIn("captured_output", log)

    def test_runs_without_shell_true(self):
        """run_cmd must NOT use shell=True — verify by passing a list and checking it runs."""
        # If shell=True were used with a list, the behaviour differs; passing a list
        # directly to Popen without shell=True is the correct, safe path.
        # We test indirectly: the command works correctly as a list.
        cmd = ["echo", "no shell"]
        log = self._run_with_templog(cmd)
        self.assertIn("no shell", log)

    def test_popen_called_without_shell(self):
        """Verify shell=True is not passed to Popen."""
        cmd = ["echo", "mock_test"]
        mock_process = MagicMock()
        mock_process.stdout = iter([b"mock_test\n"])

        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
            log_path = tf.name
        try:
            with patch("subprocess.Popen", return_value=mock_process) as mock_popen:
                cli.run_cmd(cmd, log_path)
                mock_popen.assert_called_once_with(
                    cmd,
                    stdout=unittest.mock.ANY,
                    stderr=unittest.mock.ANY,
                )
                # Confirm shell keyword was NOT passed as True
                _, kwargs = mock_popen.call_args
                self.assertNotEqual(kwargs.get("shell"), True)
        finally:
            os.unlink(log_path)

    def test_appends_to_existing_log(self):
        """run_cmd opens in append mode; pre-existing content must be preserved."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as tf:
            tf.write("existing content\n")
            log_path = tf.name
        try:
            cli.run_cmd(["echo", "new line"], log_path)
            with open(log_path) as f:
                contents = f.read()
            self.assertIn("existing content", contents)
            self.assertIn("new line", contents)
        finally:
            os.unlink(log_path)

    def test_multiword_args_quoted_in_log(self):
        """shlex.join must quote arguments that contain spaces."""
        cmd = ["echo", "hello world"]
        log = self._run_with_templog(cmd)
        # shlex.join(["echo", "hello world"]) == "echo 'hello world'"
        self.assertIn("'hello world'", log)


class TestAttackToolValidation(unittest.TestCase):
    """Tests for the is_allowed_tool guard added to attack()."""

    def _make_args(self, tool, extra="", tag="safe", allow=False, base="/tmp", target="example.com"):
        args = types.SimpleNamespace(
            tool=tool,
            extra=extra,
            tag=tag,
            allow=allow,
            base=base,
            target=target,
        )
        return args

    def _patch_attack_deps(self):
        """Return a stack of patches that prevent filesystem/subprocess side-effects."""
        return [
            patch("cli.latest_run", return_value="/tmp/fake_run"),
            patch("cli.run_cmd"),
        ]

    def test_attack_raises_for_unlisted_tool(self):
        args = self._make_args(tool="curl")
        patches = self._patch_attack_deps()
        with patches[0], patches[1]:
            with self.assertRaises(Exception) as ctx:
                cli.attack(args)
        self.assertIn("not in the allowed list", str(ctx.exception))

    def test_attack_raises_for_path_prefixed_tool(self):
        args = self._make_args(tool="/usr/bin/nuclei")
        patches = self._patch_attack_deps()
        with patches[0], patches[1]:
            with self.assertRaises(Exception) as ctx:
                cli.attack(args)
        self.assertIn("not in the allowed list", str(ctx.exception))

    def test_attack_raises_for_relative_path_tool(self):
        args = self._make_args(tool="../nuclei")
        patches = self._patch_attack_deps()
        with patches[0], patches[1]:
            with self.assertRaises(Exception) as ctx:
                cli.attack(args)
        self.assertIn("not in the allowed list", str(ctx.exception))

    def test_attack_raises_for_dotslash_tool(self):
        args = self._make_args(tool="./nuclei")
        patches = self._patch_attack_deps()
        with patches[0], patches[1]:
            with self.assertRaises(Exception) as ctx:
                cli.attack(args)
        self.assertIn("not in the allowed list", str(ctx.exception))

    def test_attack_error_message_includes_tool_name(self):
        bad_tool = "wget"
        args = self._make_args(tool=bad_tool)
        patches = self._patch_attack_deps()
        with patches[0], patches[1]:
            with self.assertRaises(Exception) as ctx:
                cli.attack(args)
        self.assertIn(repr(bad_tool), str(ctx.exception))

    def test_attack_succeeds_with_allowed_tool(self):
        args = self._make_args(tool="nuclei", extra="-t http/cves/")
        with patch("cli.latest_run", return_value="/tmp/fake_run"), \
             patch("cli.run_cmd") as mock_run:
            cli.attack(args)
            mock_run.assert_called_once_with(
                ["nuclei", "-t", "http/cves/"],
                "/tmp/fake_run/attack.log",
            )

    def test_attack_passes_extra_args_split_correctly(self):
        """shlex.split should tokenize --extra into separate list elements."""
        args = self._make_args(tool="nmap", extra="-sV -p 80,443")
        with patch("cli.latest_run", return_value="/tmp/fake_run"), \
             patch("cli.run_cmd") as mock_run:
            cli.attack(args)
            mock_run.assert_called_once_with(
                ["nmap", "-sV", "-p", "80,443"],
                "/tmp/fake_run/attack.log",
            )

    def test_attack_with_empty_extra(self):
        """When --extra is empty, run_cmd should receive only [tool]."""
        args = self._make_args(tool="ffuf", extra="")
        with patch("cli.latest_run", return_value="/tmp/fake_run"), \
             patch("cli.run_cmd") as mock_run:
            cli.attack(args)
            mock_run.assert_called_once_with(
                ["ffuf"],
                "/tmp/fake_run/attack.log",
            )

    def test_attack_disruptive_guard_still_fires_before_tool_check(self):
        """The disruptive guard (pre-existing) must still raise before the tool check."""
        args = self._make_args(tool="curl", tag="disruptive", allow=False)
        patches = self._patch_attack_deps()
        with patches[0], patches[1]:
            with self.assertRaises(Exception) as ctx:
                cli.attack(args)
        self.assertEqual(str(ctx.exception), "Disruptive actions not allowed")

    def test_attack_allowed_disruptive_still_validates_tool(self):
        """Even with --allow on a disruptive tag, the tool must be in ALLOWED_TOOLS."""
        args = self._make_args(tool="wget", tag="disruptive", allow=True)
        patches = self._patch_attack_deps()
        with patches[0], patches[1]:
            with self.assertRaises(Exception) as ctx:
                cli.attack(args)
        self.assertIn("not in the allowed list", str(ctx.exception))

    def test_attack_all_allowed_tools_accepted(self):
        """Every tool in ALLOWED_TOOLS must pass the guard without raising."""
        for tool in cli.ALLOWED_TOOLS:
            with self.subTest(tool=tool):
                args = self._make_args(tool=tool, extra="")
                with patch("cli.latest_run", return_value="/tmp/fake_run"), \
                     patch("cli.run_cmd"):
                    # Should not raise
                    cli.attack(args)


if __name__ == "__main__":
    unittest.main()
