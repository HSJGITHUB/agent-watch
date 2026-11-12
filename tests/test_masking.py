import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import masking as m  # noqa: E402


def j(*parts):
    """Assemble synthetic tokens at runtime to avoid false alarms from secret scanners."""
    return "".join(parts)


FAKE = {
    "slack_b": j("xo", "xb-", "1234567890-abcdefghijkl"),
    "slack_p": j("xo", "xp-", "1234567890-abcdefghijkl"),
    "slack_c": j("xo", "xc-", "1234567890-abcdefghijkl"),
    "slack_d": j("xo", "xd-", "1234567890-abcdefghijkl"),
    "xapp": j("xa", "pp-", "1-A0123-456789-abcdef"),
    "openai": j("s", "k-", "abcdefghijklmnop1234"),
    "anthropic": j("s", "k-ant-", "api03-abcdefghijklmnopqr"),
    "proj": j("s", "k-proj-", "abcdefghijklmnopqrst"),
    "github": j("gh", "p_", "abcdefghijklmnopqrstuvwxyz0123456789"),
    "gho": j("gh", "o_", "abcdefghijklmnopqrstuvwxyz0123456789"),
    "gh_pat": j("github", "_pat_", "abcdefghijklmnopqrstuv_wxyz"),
    "meta": j("EA", "A", "BwzLixnjYBAOabcdefghijklmnop"),
    "aws": j("AK", "IA", "ABCDEFGHIJKLMNOP"),
    "aws_s": j("AS", "IA", "ABCDEFGHIJKLMNOP"),
    "google": j("AI", "za", "SyA1234567890abcdefghijklmnopqrstuv"),
    "ya29": j("ya", "29.", "a0AfH6SMBabcdefghijklmnopqr"),
    "refresh": j("1", "//", "0gabcdefghijklmnopqrstuvwxyz"),
    "gocspx": j("GOC", "SPX-", "abcdefghijklmnop"),
    "shopify": j("sh", "pat_", "0123456789abcdef0123456789abcdef"),
    "stripe": j("s", "k_live_", "abcdefghij1234567890"),
    "stripe_t": j("r", "k_test_", "abcdefghij1234567890"),
    "amazon": j("At", "za|", "IwEBIabcdefghijklmnopqrstuvwxyz"),
    "jwt": j("ey", "JhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0.", "abcdefghijklmnopqrstuv"),
    "klaviyo": j("p", "k_", "0123456789abcdef0123456789abcdef01"),
    "hf": j("h", "f_", "abcdefghijklmnopqrstuvwxyz012345"),
    "whsec": j("wh", "sec_", "abcdefghijklmnopqrstuvwxyz012345"),
}


class TokenPatterns(unittest.TestCase):
    def test_every_fake_token_is_masked(self):
        for name, value in FAKE.items():
            with self.subTest(name):
                out = m.safe_text(f"Before {value} after", 400)
                self.assertNotIn(value, out)
                self.assertIn("Before", out)

    def test_private_key_block(self):
        raw = j("-----BEGIN RSA ", "PRIVATE KEY-----\nabc\ndef\n-----END RSA ", "PRIVATE KEY----- end")
        out = m.mask_patterns(raw)
        self.assertNotIn("abc", out)
        self.assertIn("[KEY]", out)

    def test_url_credentials(self):
        out = m.mask_patterns(j("postgres://user:", "hunter2pass", "@db.example.com/x"))
        self.assertNotIn("hunter2pass", out)

    def test_email(self):
        self.assertEqual(m.mask_patterns("Email someone@example.com end"), "Email [EMAIL] end")

    def test_bearer(self):
        out = m.mask_patterns(j("Authorization ", "Bearer abcdefgh12345678"))
        self.assertNotIn("abcdefgh12345678", out)

    def test_env_assignment(self):
        for key in ("API_TOKEN", "CLIENT_SECRET", "MY_PASSWORD", "OPENAI_KEY", "DB_PASS", "HTTP_AUTH", "AWS_CRED_X"):
            with self.subTest(key):
                out = m.mask_patterns(j(key, "=", "plainvalue1"))
                self.assertNotIn("plainvalue1", out)

    def test_cli_flags(self):
        for flag in ("--token ", "--password=", "--api-key ", "-key ", "--secret="):
            with self.subTest(flag):
                self.assertNotIn("plainvalue1", m.mask_patterns(j("tool ", flag, "plainvalue1")))

    def test_generic_key_value(self):
        for s in ('api_key: "plainvalue1"', "token=plainvalue1", "password: plainvalue1", '"client_secret":"plainvalue1"'):
            with self.subTest(s):
                self.assertNotIn("plainvalue1", m.mask_patterns(s))


class CriticRegressions(unittest.TestCase):
    """Seventeen masking regressions from independent review."""

    def assert_gone(self, raw, *secrets):
        out = m.safe_text(raw, 400)
        for s in secrets:
            self.assertNotIn(s, out, raw)

    def test_authorization_token_header(self):
        self.assert_gone(j("Authorization: Token ", "abcdef123456"), "abcdef123456")

    def test_cookie_second_pair(self):
        self.assert_gone(j("Cookie: a=1; sessionid=", "supersecretvalue"), "supersecretvalue")

    def test_x_header(self):
        self.assert_gone(j("X-Shopify-Access-Token: ", "abcdef123456"), "abcdef123456")

    def test_curl_user(self):
        self.assert_gone(j("curl -u alice:", "hunter2 https://x.io"), "hunter2")
        self.assert_gone(j("curl --user alice:", "hunter2 https://x.io"), "hunter2")
        self.assert_gone(j("curl -X POST -u 'alice:", "hunter 2' https://x.io"), "hunter 2")

    def test_git_push_u_is_not_curl(self):
        self.assertIn("origin", m.mask_patterns("git push -u origin main"))

    def test_quoted_password_with_space(self):
        self.assert_gone(j('password = "my ', 'secret pass"'), "secret pass")
        self.assert_gone(j("'pwd': '", "two words'"), "two words")

    def test_aws_secret_with_slash(self):
        self.assert_gone(j("wJalrXUtnFEMI/", "K7MDENG/", "bPxRfiCYEXAMPLEKEY"), "K7MDENG", "bPxRfiCY")

    def test_hex_next_to_korean(self):
        self.assert_gone(j("키", "0123456789abcdef0123456789abcdef", "입니다"), "0123456789abcdef")

    def test_query_params(self):
        self.assert_gone(j("https://x.io/a?key=", "abc123&b=1"), "abc123")
        self.assert_gone(j("https://x.io/a?b=1&sig=", "abc123"), "abc123")

    def test_sshpass(self):
        self.assert_gone(j("sshpass -p ", "hunter2 ssh host"), "hunter2")

    def test_mysql(self):
        self.assert_gone(j("mysql -u root -p", "hunter2 db"), "hunter2")

    def test_bare_klaviyo(self):
        self.assert_gone(FAKE["klaviyo"], FAKE["klaviyo"])

    def test_mixed_24_no_slash(self):
        v = j("aB3dE5gH7jK9mN1pQ3", "sT5vW7xY")
        self.assert_gone(f"Value {v} end", v)


class Preservation(unittest.TestCase):
    def test_korean(self):
        self.assertEqual(m.safe_text("단위 테스트 실행", 80), "단위 테스트 실행")

    def test_uuid_kept(self):
        u = "fed77eea-5d07-4711-b236-e929ee072eb9"
        self.assertIn(u, m.mask_patterns(f"Session {u}"))

    def test_plain_path_kept(self):
        p = "workspace/sample_project/agent_watch/static"
        self.assertEqual(m.mask_patterns(p), p)

    def test_capitalized_path_kept(self):
        p = "Users/sample/AppData/Local/Programs/Python/Current/Scripts/foo"
        self.assertEqual(m.mask_patterns(p), p)

    def test_git_style_slug_kept(self):
        p = "sample-feature-branch-20261030"
        self.assertEqual(m.mask_patterns(p), p)

    def test_token_counts_not_masked(self):
        self.assertEqual(m.mask_patterns("max_tokens: 1234"), "max_tokens: 1234")

    def test_long_alpha_word_kept(self):
        s = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
        self.assertEqual(m.mask_patterns(s), s)


class SafeText(unittest.TestCase):
    def test_truncation_after_mask(self):
        self.assertLessEqual(len(m.safe_text("가" * 500, 80)), 81)

    def test_secret_on_precut_boundary(self):
        limit = 80
        cap = max(limit * 4, 512)
        secret = FAKE["github"]
        raw = "x " * ((cap - 10) // 2) + secret
        out = m.safe_text(raw, 2000)
        self.assertNotIn(secret[:12], out)

    def test_precut_then_mask_shrink_does_not_expose_tail(self):
        cap = max(100 * 4, 512)
        tail = "BOUNDARYFRAGMENT"
        raw = (FAKE["github"] + " ") * 30
        raw = raw[: cap - len(tail)] + tail + "x" * 200
        self.assertNotIn(tail, m.safe_text(raw, 2000))

    def test_surrogate_and_control(self):
        out = m.safe_text("a\ud800b\x00c", 20)
        self.assertEqual(out, "abc")

    def test_first_line(self):
        self.assertEqual(m.safe_text("\n\nFirst line\nSecond line", 80, first_line=True), "First line")

    def test_path_shortening(self):
        self.assertEqual(m.safe_text("C:\\Users\\sample\\.claude\\x.txt", 80), "~/.claude/x.txt")
        self.assertEqual(m.safe_text("c:/users/sample/.claude", 80), "~/.claude")
        self.assertEqual(m.safe_text("\\\\files.example\\shared\\a b", 80), "UNC:/a b")

    def test_scratchpad(self):
        self.assertEqual(m.path_display("C:\\Users\\sample\\AppData\\Local\\Temp\\claude\\c--x\\sid\\scratchpad\\a.txt"), "(scratchpad)")


class Denylist(unittest.TestCase):
    def test_all_words(self):
        for w in m.TITLE_DENYLIST:
            with self.subTest(w):
                self.assertTrue(m.is_denied(f"Before {w} after"))

    def test_case_insensitive(self):
        self.assertTrue(m.is_denied("CLIENT-X draft"))
        self.assertTrue(m.is_denied("projectx report"))

    def test_field_replaced(self):
        self.assertEqual(m.field("client-x notes", 80), m.PRIVATE)

    def test_clean(self):
        self.assertFalse(m.is_denied("Run tests"))

    def test_insight_over_masking_accepted(self):
        self.assertTrue(m.is_denied("personnel_notes"))


class ToolWhitelist(unittest.TestCase):
    def s(self, name, inp):
        return m.summarize_tool_input(name, inp)

    def test_bash_description(self):
        self.assertEqual(self.s("Bash", {"description": "Unit tests", "command": "x"}), "Unit tests")

    def test_bash_first_token_only(self):
        self.assertEqual(self.s("Bash", {"command": j("python deploy.py --user alice --passwd ", "hunter2")}), "python")

    def test_bash_env_prefix_skipped(self):
        self.assertEqual(self.s("Bash", {"command": j("API_TOKEN=", "abc123 /usr/bin/curl x")}), "curl")

    def test_bash_background_prefix(self):
        self.assertEqual(self.s("Bash", {"description": "Server", "run_in_background": True}), "[bg] Server")

    def test_powershell(self):
        self.assertEqual(self.s("PowerShell", {"command": "Get-Item foo"}), "Get-Item")

    def test_read_edit_write_basename(self):
        for t in ("Read", "Edit", "Write"):
            self.assertEqual(self.s(t, {"file_path": "C:\\a\\b\\c.py", "content": "hidden", "old_string": "hidden"}), "c.py")

    def test_notebook(self):
        self.assertEqual(self.s("NotebookEdit", {"notebook_path": "/a/b.ipynb"}), "b.ipynb")

    def test_grep_glob(self):
        self.assertEqual(self.s("Grep", {"pattern": "foo.*bar"}), "foo.*bar")
        self.assertEqual(self.s("Glob", {"pattern": "**/*.py"}), "**/*.py")

    def test_agent(self):
        self.assertEqual(self.s("Agent", {"description": "Research", "subagent_type": "Explore", "prompt": "hidden"}), "Research (Explore)")

    def test_workflow_none(self):
        self.assertIsNone(self.s("Workflow", {"script": "hidden"}))

    def test_webfetch_host_only(self):
        self.assertEqual(self.s("WebFetch", {"url": "https://example.com/a?token=1"}), "example.com")

    def test_search(self):
        self.assertEqual(self.s("WebSearch", {"query": "Query"}), "Query")
        self.assertEqual(self.s("ToolSearch", {"query": "select:Bash"}), "select:Bash")

    def test_skill_excludes_args(self):
        self.assertEqual(self.s("Skill", {"skill": "run", "args": "hidden"}), "run")

    def test_task_tools(self):
        self.assertEqual(self.s("TaskStop", {"task_id": "b123"}), "b123")
        self.assertEqual(self.s("TaskOutput", {"task_id": "b123"}), "b123")

    def test_send_message(self):
        self.assertEqual(self.s("SendMessage", {"to": "scout", "message": "hidden"}), "scout")

    def test_monitor(self):
        self.assertEqual(self.s("Monitor", {"description": "Watch logs"}), "Watch logs")

    def test_structured_output(self):
        self.assertEqual(self.s("StructuredOutput", {"x": "hidden"}), "(submit final result)")

    def test_artifact(self):
        for t in ("Artifact", "ArtifactData", "ArtifactComments"):
            self.assertEqual(self.s(t, {"action": "read", "x": "hidden"}), "read")

    def test_mcp_dynamic_name(self):
        self.assertEqual(self.s("mcp__alpha__beta_gamma", {"secret": "hidden"}), "alpha/beta_gamma")

    def test_unknown_default_deny(self):
        self.assertIsNone(self.s("SomeNewTool", {"command": "hidden"}))

    def test_description_denylist(self):
        self.assertEqual(self.s("Bash", {"description": "Save client-x"}), m.PRIVATE)


class JsUnescape(unittest.TestCase):
    def test_newline_and_quote(self):
        self.assertEqual(m.js_unescape('a\\nb\\"c'), 'a\nb"c')

    def test_double_backslash(self):
        self.assertEqual(m.js_unescape("a\\\\nb"), "a\\nb")

    def test_first_line_after_unescape(self):
        raw = m.js_unescape("python - <<'PY'\\nimport os\\nprint(1)\\nPY")
        self.assertEqual(m.safe_text(raw, 80, first_line=True), "python - <<'PY'")




# Privacy fixtures explicitly opt into neutral terms; production defaults stay empty.
def setUpModule():
    import masking
    global _previous_title_terms
    _previous_title_terms = masking.TITLE_DENYLIST
    masking.configure_title_denylist(("ProjectX", "client-x", "salary", "personnel", "interview", "legal", "🔒"))


def tearDownModule():
    import masking
    masking.configure_title_denylist(_previous_title_terms)

if __name__ == "__main__":
    unittest.main()
