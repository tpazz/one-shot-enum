"""Unit tests for one-shot-enum's pure logic (no network).

Covers target expansion, port parsing, AI-surface / agent-profile inference,
loot paths, stale-loot detection, and - most importantly - that
write_llm_enum_loot() emits JSON that PathFinder's llm_enum parser accepts (the
handoff seam between the two tools).

Run:  python -m pytest tests/    (or  python -m unittest discover tests)
"""

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace

# one-shot-enum.py has a hyphen, so load it by path rather than importing.
ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("one_shot_enum", ROOT / "one-shot-enum.py")
ose = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ose)
ose.set_color_mode(False)  # keep test output clean


def make_service(**overrides):
    """A complete Service dict (matches the fields the tool populates)."""
    svc = {
        "port": 80, "protocol": "tcp", "service": "http", "product": "",
        "version": "", "extrainfo": "", "tunnel": "", "scripts": "",
    }
    svc.update(overrides)
    return svc

# PathFinder lives in a sibling dir; the round-trip test needs it. Skip gracefully
# if it isn't present so this suite still runs standalone.
PATHFINDER_DIR = ROOT.parent / "PathFinder"
_HAS_PATHFINDER = PATHFINDER_DIR.is_dir()
if _HAS_PATHFINDER and str(PATHFINDER_DIR) not in sys.path:
    sys.path.insert(0, str(PATHFINDER_DIR))


class TargetExpansionTests(unittest.TestCase):
    def test_single_ip(self):
        self.assertEqual(ose.normalize_targets(["10.10.10.5"]), ["10.10.10.5"])

    def test_short_range_expands(self):
        self.assertEqual(
            set(ose.normalize_targets(["10.10.10.10-12"])),
            {"10.10.10.10", "10.10.10.11", "10.10.10.12"},
        )

    def test_dedup_and_sort(self):
        out = ose.normalize_targets(["10.10.10.20", "10.10.10.5", "10.10.10.5"])
        self.assertEqual(out, ["10.10.10.5", "10.10.10.20"])


class PortParsingTests(unittest.TestCase):
    def test_list_and_range(self):
        self.assertEqual(ose.parse_port_spec("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_result_is_sorted_deduped(self):
        out = ose.parse_port_spec("80,22,22,443")
        self.assertEqual(out, sorted(set(out)))

    def test_invalid_port_raises(self):
        for bad in ["70000", "abc", "80-20", "0"]:
            with self.assertRaises(ValueError):
                ose.parse_port_spec(bad)


class AiSurfaceInferenceTests(unittest.TestCase):
    def _surfaces(self, paths):
        llm_enum = {"endpoints": [{"method": "GET", "path": p} for p in paths], "probe_hits": []}
        return {s["key"] for s in ose.infer_ai_surfaces(make_service(), llm_enum)}

    def test_openai_compatible_detected(self):
        self.assertIn("openai-compatible", self._surfaces(["/v1/chat/completions"]))

    def test_ollama_detected(self):
        self.assertIn("ollama", self._surfaces(["/api/tags", "/api/chat"]))

    def test_no_false_surface_on_plain_http(self):
        self.assertEqual(self._surfaces(["/index.html", "/about"]), set())

    def test_object_store_minio_detected(self):
        self.assertIn("object-store", self._surfaces(["/minio/health/live"]))


class ProbeResponseInterestTests(unittest.TestCase):
    def test_accepts_400_and_422_for_custom_agents(self):
        # A GET on a body-required POST route (custom FastAPI/Starlette agents).
        self.assertTrue(ose.is_interesting_probe_response({"status": 400}))
        self.assertTrue(ose.is_interesting_probe_response({"status": 422}))

    def test_rejects_404_and_500(self):
        self.assertFalse(ose.is_interesting_probe_response({"status": 404}))
        self.assertFalse(ose.is_interesting_probe_response({"status": 500}))

    def test_missing_status_not_interesting(self):
        self.assertFalse(ose.is_interesting_probe_response({}))


class AgentProfileInferenceTests(unittest.TestCase):
    def _profile(self, paths):
        return ose.infer_agent_profile({"endpoints": [{"method": "GET", "path": p} for p in paths]})

    def test_multi_agent_architecture(self):
        p = self._profile(["/.well-known/agent.json", "/agents", "/a2a"])
        self.assertEqual(p["architecture"], "multi-agent")

    def test_vector_store_architecture(self):
        p = self._profile(["/collections", "/collections/x/points/scroll"])
        self.assertEqual(p["architecture"], "vector-store")

    def test_empty_when_nothing_recognisable(self):
        self.assertEqual(self._profile(["/index.html"]), {})


class GeneratedCommandTests(unittest.TestCase):
    """Generated bash commands: redirected tools use tee (so the --run idle-timeout
    sees output), and operator-controlled paths are shlex-quoted."""

    def _commands(self, loot="loot", wordlist="/wl.txt", power=False, web_service=None):
        web = web_service or make_service(port=80, service="http")
        smb = make_service(port=445, service="microsoft-ds")
        nfs = make_service(port=2049, service="nfs")
        redis = make_service(port=6379, service="redis")
        rsync = make_service(port=873, service="rsync")
        smtp = make_service(port=25, service="smtp")
        snmp = make_service(port=161, service="snmp", protocol="udp")
        sugg = ose.suggest_for_host("10.0.0.5", [web, smb, nfs, redis, rsync, smtp], [snmp],
                                    loot, wordlist, "/users.txt", power=power)
        return {s["tool"]: s["command"] for s in sugg}

    def _suggestions(self, services):
        return ose.suggest_for_host("10.0.0.5", services, [], "loot", "/wl.txt", "/users.txt")

    def test_default_web_commands_are_lean(self):
        cmds = self._commands()
        self.assertIn("curl", cmds)
        self.assertIn("ffuf", cmds)
        self.assertIn("nikto", cmds)
        self.assertIn("whatweb", cmds)
        self.assertNotIn("gobuster", cmds)
        self.assertNotIn("wpscan", cmds)
        self.assertNotIn("nuclei", cmds)
        self.assertNotIn("sqlmap", cmds)
        self.assertIn(f"-maxtime {ose.DEFAULT_FFUF_MAXTIME}", cmds["ffuf"])

    def test_every_runnable_suggestion_declares_its_output_file(self):
        services = [
            make_service(port=80, service="http"),
            make_service(port=445, service="microsoft-ds"),
            make_service(port=2049, service="nfs"),
            make_service(port=6379, service="redis"),
            make_service(port=873, service="rsync"),
            make_service(port=25, service="smtp"),
            make_service(port=389, service="ldap", extrainfo="Domain: corp.local"),
        ]
        suggestions = ose.suggest_for_host(
            "10.0.0.5", services, [make_service(port=161, service="snmp", protocol="udp")],
            "loot", "/wl.txt", "/users.txt", power=True,
        )
        runnable = ose.runnable_suggestions(suggestions)
        self.assertTrue(runnable)
        self.assertTrue(all(s["output_file"] for s in runnable))

    def test_wordpress_detection_adds_wpscan(self):
        wp = make_service(port=80, service="http", scripts="http-wordpress-users wp-content")
        cmds = self._commands(web_service=wp)
        self.assertIn("wpscan", cmds)
        self.assertIn("wpscan --url http://10.0.0.5:80", cmds["wpscan"])
        self.assertIn("loot/10.0.0.5/wpscan_80.json", cmds["wpscan"])

    def test_power_adds_nuclei_only(self):
        cmds = self._commands(power=True)
        self.assertIn("nuclei -u http://10.0.0.5:80", cmds["nuclei"])
        self.assertIn("loot/10.0.0.5/nuclei_80.jsonl", cmds["nuclei"])
        self.assertNotIn("sqlmap", cmds)

    def test_smbmap_and_snmpcheck_use_tee_not_redirect(self):
        cmds = self._commands()
        self.assertIn("| tee ", cmds["smbmap"])
        self.assertNotIn(" > ", cmds["smbmap"])
        self.assertIn("| tee ", cmds["snmp-check"])
        self.assertNotIn(" > ", cmds["snmp-check"])
        self.assertIn("| tee ", cmds["showmount"])
        self.assertNotIn(" > ", cmds["showmount"])
        self.assertIn("| tee ", cmds["redis-cli"])
        self.assertIn("| tee ", cmds["rsync"])
        self.assertIn("| tee ", cmds["smtp-user-enum"])

    def test_nfs_suggestion_feeds_pathfinder_parser(self):
        cmds = self._commands()
        self.assertIn("showmount -e 10.0.0.5", cmds["showmount"])
        self.assertIn("loot/10.0.0.5/nfs_10.0.0.5.txt", cmds["showmount"])

    def test_redis_rsync_smtp_suggestions_feed_pathfinder_parsers(self):
        cmds = self._commands()
        self.assertIn("redis-cli -h 10.0.0.5 -p 6379 INFO", cmds["redis-cli"])
        self.assertIn("loot/10.0.0.5/redis_6379.txt", cmds["redis-cli"])
        self.assertIn("rsync --list-only rsync://10.0.0.5/", cmds["rsync"])
        self.assertIn("loot/10.0.0.5/rsync_10.0.0.5.txt", cmds["rsync"])
        self.assertIn("smtp-user-enum -M VRFY -U /users.txt -t 10.0.0.5 -p 25", cmds["smtp-user-enum"])
        self.assertIn("loot/10.0.0.5/smtp_user_enum_25.txt", cmds["smtp-user-enum"])

    def test_loot_dir_with_spaces_is_quoted(self):
        cmds = self._commands(loot="my loot")
        # shlex.quote wraps a spaced path in single quotes so it stays one argument.
        self.assertIn("'my loot", cmds["ffuf"])
        self.assertIn("'my loot", cmds["smbmap"])

    def test_wordlist_with_spaces_is_quoted(self):
        cmds = self._commands(wordlist="/opt/word lists/raft.txt")
        self.assertIn("'/opt/word lists/raft.txt'", cmds["ffuf"])

    def test_default_paths_are_not_over_quoted(self):
        # Clean default paths need no quoting - shlex.quote leaves them bare.
        cmds = self._commands()
        self.assertIn("loot/10.0.0.5/ffuf_80.json", cmds["ffuf"])
        self.assertNotIn("'loot", cmds["ffuf"])

    def test_ad_placeholder_commands_are_not_runnable(self):
        suggestions = self._suggestions([make_service(port=88, service="kerberos-sec")])
        cmds = {s["tool"]: s["command"] for s in suggestions}

        self.assertIn("kerbrute", cmds)
        self.assertIn("impacket-GetNPUsers", cmds)
        self.assertIn("<domain>", cmds["kerbrute"])
        self.assertIn("<domain>", cmds["impacket-GetNPUsers"])

        runnable_tools = {s["tool"] for s in ose.runnable_suggestions(suggestions)}
        self.assertNotIn("kerbrute", runnable_tools)
        self.assertNotIn("impacket-GetNPUsers", runnable_tools)

    def test_ad_domain_from_ldap_makes_userenum_runnable(self):
        ldap = make_service(
            port=389,
            service="ldap",
            product="Microsoft Windows Active Directory LDAP",
            extrainfo="Domain: researchmco.ai, Site: Default-First-Site-Name",
        )
        suggestions = self._suggestions([ldap])
        cmds = {s["tool"]: s["command"] for s in suggestions}

        self.assertIn("kerbrute userenum -d researchmco.ai", cmds["kerbrute"])
        self.assertIn("impacket-GetNPUsers researchmco.ai/", cmds["impacket-GetNPUsers"])

        runnable_tools = {s["tool"] for s in ose.runnable_suggestions(suggestions)}
        self.assertIn("kerbrute", runnable_tools)
        self.assertIn("impacket-GetNPUsers", runnable_tools)

    def test_ad_domain_from_rdp_ntlm_info_is_used(self):
        rdp = make_service(
            port=3389,
            service="ms-wbt-server",
            scripts="rdp-ntlm-info: DNS_Domain_Name: researchmco.ai\nDNS_Computer_Name: DC01.researchmco.ai",
        )
        kerberos = make_service(port=88, service="kerberos-sec")
        suggestions = self._suggestions([kerberos, rdp])
        cmds = {s["tool"]: s["command"] for s in suggestions}

        self.assertIn("kerbrute userenum -d researchmco.ai", cmds["kerbrute"])
        self.assertIn("impacket-GetNPUsers researchmco.ai/", cmds["impacket-GetNPUsers"])

    def test_generated_script_comments_placeholder_commands(self):
        suggestions = self._suggestions([make_service(port=88, service="kerberos-sec")])
        with tempfile.TemporaryDirectory() as d:
            paths = ose.write_recon_scripts(Path(d), suggestions, "loot")
            bash = next(p for p in paths if p.name == "pathfinder_recon.sh").read_text(encoding="utf-8")

        self.assertIn("# kerbrute userenum -d <domain>", bash)
        self.assertIn("# impacket-GetNPUsers <domain>/", bash)
        self.assertIn("edit placeholders", bash)

    def test_generated_script_leaves_inferred_domain_userenum_live(self):
        ldap = make_service(port=389, service="ldap", extrainfo="Domain: researchmco.ai, Site: Default-First-Site-Name")
        suggestions = self._suggestions([ldap])
        with tempfile.TemporaryDirectory() as d:
            paths = ose.write_recon_scripts(Path(d), suggestions, "loot")
            bash = next(p for p in paths if p.name == "pathfinder_recon.sh").read_text(encoding="utf-8")

        self.assertIn("kerbrute userenum -d researchmco.ai", bash)
        self.assertIn("impacket-GetNPUsers researchmco.ai/", bash)
        self.assertNotIn("# kerbrute userenum -d researchmco.ai", bash)
        self.assertNotIn("# impacket-GetNPUsers researchmco.ai/", bash)

    def test_ad_domain_inference_falls_back_to_cert_common_name(self):
        rdp = make_service(port=3389, service="ms-wbt-server", scripts="ssl-cert: Subject: commonName=DC01.researchmco.ai")
        self.assertEqual(ose.infer_ad_domain([rdp]), "researchmco.ai")

    def test_run_worker_preserves_piped_command_exit_status_on_posix(self):
        command, executable = ose._command_with_pipefail(
            "showmount -e 10.0.0.5 | tee loot/10.0.0.5/nfs.txt",
            os_name="posix",
            bash_path="/bin/bash",
        )
        self.assertEqual(executable, "/bin/bash")
        self.assertTrue(command.startswith("set -o pipefail\n"))

    def test_run_worker_leaves_unpiped_commands_unchanged(self):
        command = "nxc smb 10.0.0.5 --shares --log loot/10.0.0.5/nxc.log"
        wrapped, executable = ose._command_with_pipefail(
            command,
            os_name="posix",
            bash_path="/bin/bash",
        )
        self.assertEqual(wrapped, command)
        self.assertIsNone(executable)

    def test_status_row_truncates_long_tool_and_progress(self):
        row = ose._format_job_row({
            "tool": "impacket-GetNPUsers",
            "host": "192.168.102.13",
            "state": "interrupted",
            "last": ":: Progress: [2440/29999] :: Job [1/1] :: 2 req/sec :: Duration: [really long]",
            "start": 90.0,
            "end": None,
        }, now=100.0, width=72)
        self.assertLessEqual(len(row), 72)
        self.assertIn("impacket-GetNPUsers", row)
        self.assertIn("192.168.102.13", row)

    def test_status_line_strips_terminal_controls_from_ffuf_progress(self):
        cleaned = ose._clean_status_line(
            "\x1b[2K\r:: Progress: [2440/29999] :: Job [1/1] :: 2 req/sec :: Duration: ["
        )
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\r", cleaned)
        self.assertIn("Progress", cleaned)

    def test_running_status_row_has_marker_without_shifting_tool_name(self):
        running = ose._format_job_row({
            "tool": "ffuf",
            "host": "192.168.102.13",
            "state": "running",
            "last": "",
            "start": 90.0,
            "end": None,
        }, now=100.0, width=90)
        done = ose._format_job_row({
            "tool": "ffuf",
            "host": "192.168.102.13",
            "state": "done",
            "last": "",
            "start": 90.0,
            "end": 100.0,
        }, now=100.0, width=90)

        self.assertTrue(running.startswith("> ffuf"))
        self.assertTrue(done.startswith("  ffuf"))
        self.assertEqual(running.index("ffuf"), done.index("ffuf"))

    def test_run_scheduler_keeps_two_same_host_jobs_active_until_tail(self):
        suggestions = [
            {
                "host": "10.0.0.5",
                "group": "test",
                "tool": f"tool{i}",
                "command": f"fake-tool job{i}",
                "parser": "test_parser",
                "pending": False,
                "gated": False,
                "shell": "bash",
                "note": "",
            }
            for i in range(4)
        ]
        active = 0
        max_active = 0
        starts = []
        probe_lock = ose.threading.Lock()

        def fake_worker(job, lock, tty):
            nonlocal active, max_active
            with lock:
                job["state"] = "running"
                job["start"] = ose.time.time()
                job["last_output"] = job["start"]
            with probe_lock:
                active += 1
                max_active = max(max_active, active)
                starts.append(job["tool"])
            ose.time.sleep(0.05)
            with probe_lock:
                active -= 1
            with lock:
                job["rc"] = 0
                job["end"] = ose.time.time()
                job["state"] = "done"

        original_worker = ose._run_worker
        original_which = ose.shutil.which
        original_plan = ose._print_run_plan
        ose._run_worker = fake_worker
        ose.shutil.which = lambda _binary: "fake-tool"
        ose._print_run_plan = lambda _live: None
        try:
            with tempfile.TemporaryDirectory() as d, redirect_stdout(io.StringIO()):
                result = ose.run_suggestions(
                    suggestions,
                    d,
                    "wordlist-not-in-command",
                    "userlist-not-in-command",
                    idle_timeout=0,
                )
        finally:
            ose._run_worker = original_worker
            ose.shutil.which = original_which
            ose._print_run_plan = original_plan

        self.assertEqual(result["ran"], 4)
        self.assertEqual(max_active, ose.PER_HOST_LANE)
        self.assertEqual(starts, ["tool0", "tool1", "tool2", "tool3"])


class LootPathTests(unittest.TestCase):
    def test_host_loot_dir(self):
        self.assertEqual(ose.host_loot_dir("loot", "10.10.10.5"), "loot/10.10.10.5")

    def test_safe_name_preserves_ip(self):
        self.assertEqual(ose.safe_name("10.10.10.5"), "10.10.10.5")

    def test_generated_suggestions_carry_unquoted_output_paths(self):
        loot = "loot/o'ne host"
        suggestions = ose._web_suggestions("10.0.0.5", make_service(port=80), loot, "words.txt")
        expected = {
            "curl": f"{loot}/webpage_http_80.html",
            "whatweb": f"{loot}/whatweb_80.json",
            "ffuf": f"{loot}/ffuf_80.json",
            "nikto": f"{loot}/nikto_80.json",
        }
        self.assertEqual({s["tool"]: s["output_file"] for s in suggestions}, expected)
        self.assertTrue(all(s["output_file"] not in s["command"] for s in suggestions))

    def test_provenance_manifest_records_exact_command_and_relative_output(self):
        with tempfile.TemporaryDirectory() as directory:
            loot = Path(directory) / "loot"
            output = loot / "10.0.0.5" / "kerbrute.txt"
            output.parent.mkdir(parents=True)
            output.write_text("alice\n", encoding="utf-8")
            command = f"kerbrute userenum -d corp.local users.txt -o {output}"
            manifest = ose._write_pathfinder_provenance(str(loot), [{
                "host": "10.0.0.5", "tool": "kerbrute", "parser": "kerbrute_txt",
                "output_file": str(output), "command": command, "state": "done",
            }])
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["records"][0]["output_file"], "10.0.0.5/kerbrute.txt")
        self.assertEqual(payload["records"][0]["command"], command)
        self.assertEqual(payload["records"][0]["status"], "done")

    def test_unchanged_stale_output_keeps_previous_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            loot = Path(directory) / "loot"
            output = loot / "10.0.0.5" / "ffuf.json"
            output.parent.mkdir(parents=True)
            output.write_text("old", encoding="utf-8")
            old_job = {
                "host": "10.0.0.5", "tool": "ffuf", "parser": "ffuf_json",
                "output_file": str(output), "command": "ffuf old-command", "state": "done",
                "output_before": None,
            }
            ose._write_pathfinder_provenance(str(loot), [old_job])
            unchanged = ose._output_fingerprint(str(output))
            skipped_job = dict(old_job, command="ffuf current-command", state="skip:no-tool",
                               output_before=unchanged)
            manifest = ose._write_pathfinder_provenance(str(loot), [skipped_job])
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(payload["records"][0]["command"], "ffuf old-command")
        self.assertEqual(payload["records"][0]["status"], "done")


class PathFinderBridgeTests(unittest.TestCase):
    def test_run_pathfinder_passes_scan_flags(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pf = root / "PathFinder"
            (pf / "main").mkdir(parents=True)
            (pf / "main" / "pathfinder.py").write_text("", encoding="utf-8")
            loot = root / "loot"
            loot.mkdir()
            out = root / "custom_findings.json"
            cache = root / "github_cache.json"

            calls = []
            original_run = ose.subprocess.run
            ose.subprocess.run = lambda cmd, cwd=None: calls.append((cmd, cwd))
            try:
                ose.run_pathfinder(
                    str(pf), str(loot),
                    top=10,
                    min_likelihood="medium",
                    show_all=True,
                    hide_discovery=True,
                    hide_findings=True,
                    validate_credentials=True,
                    target_host="10.0.0.5",
                    output_json=str(out),
                    verbose=2,
                    max_vulns=25,
                    offline=True,
                    skip_github=True,
                    skip_searchsploit=True,
                    github_cache=str(cache),
                    no_color=True,
                    oscp=True,
                )
            finally:
                ose.subprocess.run = original_run

            self.assertEqual(len(calls), 1)
            cmd, cwd = calls[0]
            self.assertEqual(cwd, str(pf))
            self.assertIn(str(out), cmd)
            self.assertIn("--target-host", cmd)
            self.assertIn("10.0.0.5", cmd)
            self.assertEqual(cmd.count("-v"), 2)
            self.assertIn("--max-vulns", cmd)
            self.assertIn("25", cmd)
            self.assertIn("--offline", cmd)
            self.assertIn("--skip-github", cmd)
            self.assertIn("--skip-searchsploit", cmd)
            self.assertIn("--github-cache", cmd)
            self.assertIn(str(cache), cmd)
            self.assertIn("--no-color", cmd)
            self.assertIn("--oscp", cmd)
            self.assertNotIn("--ai-only", cmd)
            self.assertNotIn("--ai-brief", cmd)
            self.assertIn("--top", cmd)
            self.assertIn("10", cmd)
            self.assertIn("--min-likelihood", cmd)
            self.assertIn("medium", cmd)
            self.assertIn("--show-all", cmd)
            self.assertIn("--hide-discovery", cmd)
            self.assertIn("--hide-findings", cmd)
            self.assertIn("--validate-credentials", cmd)

    @unittest.skipUnless(_HAS_PATHFINDER, "PathFinder sibling repo not present")
    def test_provenance_manifest_is_consumed_by_pathfinder_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            loot = Path(directory) / "loot"
            host_dir = loot / "10.0.0.5"
            host_dir.mkdir(parents=True)
            output = host_dir / "ffuf_80.json"
            command = "ffuf -u http://10.0.0.5/FUZZ -w words.txt -of json -o loot/10.0.0.5/ffuf_80.json"
            output.write_text(json.dumps({
                "commandline": command,
                "results": [{
                    "input": {"FUZZ": "admin"}, "status": 200, "length": 10,
                    "url": "http://10.0.0.5/admin", "host": "10.0.0.5:80",
                }],
            }), encoding="utf-8")
            ose._write_pathfinder_provenance(str(loot), [{
                "host": "10.0.0.5", "tool": "ffuf", "parser": "ffuf_json",
                "output_file": str(output), "command": command, "state": "done",
            }])
            result = subprocess.run(
                [sys.executable, "-m", "main.pathfinder", "scan", str(loot),
                 "--offline", "--no-color"],
                capture_output=True, text=True, cwd=PATHFINDER_DIR,
            )
        self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
        self.assertIn("Discovery:", result.stdout)
        self.assertIn("ffuf", result.stdout)
        self.assertIn(command, result.stdout)

    def test_default_uses_full_active_ai_options(self):
        opts = ose._llm_enum_options(SimpleNamespace(pathfinder=False, llm_endpoint=False))

        self.assertEqual(opts, {
            "endpoint_only": False,
            "probe_all_http": True,
            "ai_paths_mode": True,
            "active": True,
        })

    def test_suggest_uses_full_active_ai_options(self):
        opts = ose._llm_enum_options(SimpleNamespace(pathfinder_suggest=True, pathfinder=False, llm_endpoint=False))

        self.assertEqual(opts, {
            "endpoint_only": False,
            "probe_all_http": True,
            "ai_paths_mode": True,
            "active": True,
        })

    def test_llm_endpoint_remains_quick_ai_peek(self):
        opts = ose._llm_enum_options(SimpleNamespace(pathfinder=False, llm_endpoint=True))

        self.assertEqual(opts, {
            "endpoint_only": True,
            "probe_all_http": False,
            "ai_paths_mode": False,
            "active": False,
        })

    def test_llm_endpoint_can_override_pathfinder_mode(self):
        original_argv = sys.argv
        try:
            sys.argv = ["one-shot-enum.py", "10.0.0.5", "--pathfinder", "--llm-endpoint"]
            args = ose.parse_args()
        finally:
            sys.argv = original_argv

        self.assertTrue(args.pathfinder)
        self.assertTrue(args.llm_endpoint)

    def test_old_pathfinder_and_ai_mode_flags_are_not_accepted(self):
        original_argv = sys.argv
        try:
            for flag in ("--run", "--suggest", "--ai-paths", "--ai-active", "--ai-only", "--ai-brief"):
                sys.argv = ["one-shot-enum.py", "10.0.0.5", flag]
                with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                    ose.parse_args()
        finally:
            sys.argv = original_argv

    def test_pathfinder_only_flags_require_pathfinder_mode(self):
        original_argv = sys.argv
        try:
            for extra in (
                ["--max-vulns", "0"],
                ["--offline"],
                ["--target-host", "10.0.0.5"],
                ["--output-json", "findings.json"],
                ["--top", "10"],
                ["--hide-discovery"],
                ["--hide-findings"],
                ["--validate-credentials"],
            ):
                sys.argv = ["one-shot-enum.py", "10.0.0.5", *extra]
                with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                    ose.parse_args()
        finally:
            sys.argv = original_argv

    def test_pathfinder_flags_parse_with_pathfinder_mode(self):
        original_argv = sys.argv
        try:
            sys.argv = [
                "one-shot-enum.py", "10.0.0.5", "--pathfinder",
                "--max-vulns", "0",
                "--offline", "--skip-github", "--skip-searchsploit",
                "--github-cache", "cache.json", "--target-host", "10.0.0.5",
                "--output-json", "findings.json", "-vv", "--oscp",
                "--top", "10", "--min-likelihood", "medium", "--show-all",
                "--hide-discovery", "--hide-findings",
                "--validate-credentials",
            ]
            args = ose.parse_args()
        finally:
            sys.argv = original_argv

        self.assertTrue(args.pathfinder)
        self.assertEqual(args.max_vulns, 0)
        self.assertTrue(args.offline)
        self.assertTrue(args.skip_github)
        self.assertTrue(args.skip_searchsploit)
        self.assertEqual(args.github_cache, "cache.json")
        self.assertEqual(args.target_host, "10.0.0.5")
        self.assertEqual(args.output_json, "findings.json")
        self.assertEqual(args.verbose, 2)
        self.assertTrue(args.oscp)
        self.assertEqual(args.top, 10)
        self.assertEqual(args.min_likelihood, "medium")
        self.assertTrue(args.show_all)
        self.assertTrue(args.hide_discovery)
        self.assertTrue(args.hide_findings)
        self.assertTrue(args.validate_credentials)


class StaleLootTests(unittest.TestCase):
    def test_warns_only_for_unexpected_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            loot = Path(d) / "loot"
            for sub in ("10.10.10.5", "10.10.10.99", "_logs"):
                (loot / sub).mkdir(parents=True)
            # Capture whether a warning fired by monkeypatching the module's warn().
            fired = []
            original = ose.warn
            ose.warn = lambda msg: fired.append(msg)
            try:
                ose.warn_stale_loot(str(loot), ["10.10.10.5"])
                self.assertTrue(any("10.10.10.99" in m for m in fired))
                self.assertFalse(any("_logs" in m for m in fired))
                fired.clear()
                ose.warn_stale_loot(str(loot), ["10.10.10.5", "10.10.10.99"])
                self.assertEqual(fired, [])
            finally:
                ose.warn = original

    def test_missing_dir_is_silent(self):
        original = ose.warn
        fired = []
        ose.warn = lambda msg: fired.append(msg)
        try:
            ose.warn_stale_loot("definitely-not-a-real-loot-dir", ["x"])
            self.assertEqual(fired, [])
        finally:
            ose.warn = original


class LlmEnumLootSchemaTests(unittest.TestCase):
    """The write_llm_enum_loot() -> PathFinder parse_llm_enum_json() seam."""

    def _service_with_surface(self):
        return make_service(
            port=11434,
            llm_enum={
                "base_url": "http://10.0.0.5:11434",
                "endpoints": [{"method": "GET", "path": "/api/tags"}],
                "probe_hits": [{"path": "/api/tags", "status": 200, "content_type": "application/json"}],
                "probe_count": 5,
                "chat_path": "/api/chat",
                "openapi_url": "", "openapi_status": 404, "openapi_error": "",
                "ai_surfaces": [{"key": "ollama", "label": "Ollama API", "confidence": "high",
                                 "evidence": ["/api/tags"], "next_steps": ["GET /api/tags"]}],
                "agent_profile": {"role": "Conversational agent / chatbot", "architecture": "single-agent",
                                  "framework": "", "capabilities": ["conversational"], "evidence": {}},
                "vector_store": {}, "mcp_tools": {}, "agent_cards": [],
            },
        )

    def test_writes_expected_payload_shape(self):
        with tempfile.TemporaryDirectory() as d:
            invocation = "python one-shot-enum.py 10.0.0.5 --pathfinder --user token:secret"
            written = ose.write_llm_enum_loot(
                "10.0.0.5", self._service_with_surface(), d,
                discovery_command=invocation,
            )
            self.assertIsNotNone(written)
            payload = json.loads(Path(written).read_text(encoding="utf-8"))
            self.assertEqual(payload["tool"], "one-shot-enum")
            self.assertEqual(payload["discovery_command"], invocation)
            self.assertEqual(payload["type"], "llm_enum")
            self.assertEqual(payload["host"], "10.0.0.5")
            self.assertEqual(payload["port"], 11434)
            self.assertTrue(payload["ai_surfaces"])

    def test_returns_none_without_ai_signal(self):
        svc = {"port": 80, "service": "http", "product": "", "version": "", "extrainfo": "",
               "scripts": "", "llm_enum": {"base_url": "http://x", "ai_surfaces": [], "agent_profile": {}}}
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(ose.write_llm_enum_loot("x", svc, d))

    @unittest.skipUnless(_HAS_PATHFINDER, "PathFinder sibling repo not present")
    def test_pathfinder_parses_written_loot(self):
        from parsers.initial_foothold.llm_enum_parser import parse_llm_enum_json
        from main.finding_schema import validate_findings
        with tempfile.TemporaryDirectory() as d:
            invocation = "python one-shot-enum.py 10.0.0.5 --pathfinder --password hunter2"
            written = ose.write_llm_enum_loot(
                "10.0.0.5", self._service_with_surface(), d,
                discovery_command=invocation,
            )
            findings = parse_llm_enum_json(str(written))
            validate_findings(findings)  # raises if schema-incompatible
            self.assertTrue(findings)
            self.assertTrue(all(f["entity_type"] == "ai_service" for f in findings))
            self.assertTrue(all(f["attributes"]["discovery_command"] == invocation
                                for f in findings))
            self.assertIn("ollama", [f["name"] for f in findings])


if __name__ == "__main__":
    unittest.main()
