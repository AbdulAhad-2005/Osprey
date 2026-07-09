"""
Nmap wrapper for the AI-Pentesting-Tool network capability domain.

This is a thin, dependency-free Python wrapper around the `nmap` binary. It is
meant to be exposed to an LLM (the network-phase agent) as a set of callable
tools. Every public method returns a normalised, JSON-serialisable dict so the
result can be summarised, stored in the engagement graph, or fed back into the
planner without any additional parsing on the caller's side.

Design goals
------------
- **Defined functions** for the common scans and evasion techniques described in
  the project's nmap guide (host discovery, SYN/connect/UDP/NULL/FIN/XMAS/ACK,
  idle, FTP bounce, version/OS detection, timing, fragmentation, source-port,
  MTU, bad-checksum, decoys, output formats).
- **A custom escape hatch** (`custom_scan`) so the LLM can pass arbitrary flags
  of its choice when it needs to bypass a firewall/IDS or do something the
  defined helpers do not cover.
- **Safe execution**: commands are run without a shell (`shell=False`) and the
  target is passed after a `--` separator so it can never be interpreted as a
  flag. Custom flags are tokenised with `shlex`.
- **Structured output**: results are always requested as XML on stdout and
  parsed into hosts/ports/services/os so the caller gets machine-readable data
  plus the raw XML for evidence.

Note on privileges: several scans (-sS, -sU, -sN/-sF/-sX, -O, -sI ...) require
raw-socket / administrator privileges. On POSIX set ``privileged=True`` (or pass
``sudo=True`` to the constructor) to prefix ``sudo``; on Windows run the host
process elevated with Npcap installed.
"""

from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Union


# Nmap timing templates, name -> flag value. Higher == faster/louder.
TIMING_TEMPLATES = {
    "paranoid": 0,   # T0 - very slow, best for IDS evasion
    "sneaky": 1,     # T1
    "polite": 2,     # T2
    "normal": 3,     # T3 - nmap default
    "aggressive": 4, # T4
    "insane": 5,     # T5 - fastest, loudest
}


class NmapError(RuntimeError):
    """Raised when the nmap binary is missing or a target is invalid."""


@dataclass
class EvasionOptions:
    """
    Firewall / IDS evasion knobs, mapped 1:1 to the techniques in the guide.

    All fields are optional; only the ones that are set contribute flags to the
    final command. Any method that accepts scans also accepts these so the LLM
    can layer evasion onto a defined scan instead of falling back to a fully
    custom command.
    """

    timing: Optional[Union[int, str]] = None      # 0-5 or a TIMING_TEMPLATES name -> -T<n>
    fragment: bool = False                         # -f  (fragment packets)
    mtu: Optional[int] = None                      # --mtu <n> (multiple of 8)
    source_port: Optional[int] = None              # -g / --source-port <port>
    decoys: Optional[Union[str, Iterable[str]]] = None  # -D  e.g. "RND:10" or list of IPs
    spoof_mac: Optional[str] = None                # --spoof-mac <mac|vendor|0>
    spoof_source: Optional[str] = None             # -S <ip> (spoof source address)
    interface: Optional[str] = None                # -e <iface>
    bad_checksum: bool = False                     # --badsum
    data_length: Optional[int] = None              # --data-length <n> (append random data)
    no_dns: bool = False                           # -n  (skip DNS resolution, faster/quieter)

    def to_args(self) -> list[str]:
        args: list[str] = []
        if self.timing is not None:
            args.append(f"-T{_resolve_timing(self.timing)}")
        if self.fragment:
            args.append("-f")
        if self.mtu is not None:
            args += ["--mtu", str(int(self.mtu))]
        if self.source_port is not None:
            args += ["-g", str(int(self.source_port))]
        if self.decoys is not None:
            decoy_val = self.decoys if isinstance(self.decoys, str) else ",".join(self.decoys)
            args += ["-D", decoy_val]
        if self.spoof_mac is not None:
            args += ["--spoof-mac", str(self.spoof_mac)]
        if self.spoof_source is not None:
            args += ["-S", str(self.spoof_source)]
        if self.interface is not None:
            args += ["-e", str(self.interface)]
        if self.bad_checksum:
            args.append("--badsum")
        if self.data_length is not None:
            args += ["--data-length", str(int(self.data_length))]
        if self.no_dns:
            args.append("-n")
        return args


def _resolve_timing(timing: Union[int, str]) -> int:
    if isinstance(timing, str):
        key = timing.strip().lower()
        if key in TIMING_TEMPLATES:
            return TIMING_TEMPLATES[key]
        if key.isdigit():
            timing = int(key)
        else:
            raise NmapError(
                f"Unknown timing template '{timing}'. "
                f"Use 0-5 or one of {list(TIMING_TEMPLATES)}."
            )
    timing = int(timing)
    if not 0 <= timing <= 5:
        raise NmapError("Timing template must be between 0 (paranoid) and 5 (insane).")
    return timing


@dataclass
class ScanResult:
    """
    Normalised result of a single nmap invocation.

    Completeness guarantee: the summary agent must be able to see *everything*
    nmap produced, not just the fields the parser understands. So a result always
    carries three independent views of the same run:

    - ``raw_output``  - the full human-readable ("normal") report, exactly what a
      pentester would read on screen. This is the primary, loss-free view.
    - ``raw_xml``     - the complete XML, for evidence bundling and re-parsing.
    - ``hosts``/``summary`` - the structured extraction for the graph/planner.

    ``raw_stderr`` additionally carries nmap's warnings/errors. Nothing nmap
    emits is dropped.
    """

    command: str
    success: bool
    returncode: Optional[int]
    duration_seconds: float
    hosts: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""          # full human-readable normal output (stdout)
    raw_xml: str = ""             # full XML output
    raw_stderr: str = ""          # warnings / errors
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "success": self.success,
            "returncode": self.returncode,
            "duration_seconds": round(self.duration_seconds, 3),
            "summary": self.summary,
            "hosts": self.hosts,
            "raw_output": self.raw_output,
            "raw_xml": self.raw_xml,
            "raw_stderr": self.raw_stderr,
            # Back-compat alias: earlier callers read `raw_stdout`.
            "raw_stdout": self.raw_output,
            "error": self.error,
        }


class NmapScanner:
    """
    Callable wrapper around the nmap binary.

    Example
    -------
    >>> scanner = NmapScanner()
    >>> result = scanner.syn_scan("scanme.nmap.org", ports="1-1000")
    >>> result["summary"]["hosts_up"]
    """

    def __init__(
        self,
        nmap_path: str = "nmap",
        default_timeout: int = 600,
        sudo: bool = False,
    ) -> None:
        """
        Parameters
        ----------
        nmap_path:
            Path to (or name of) the nmap executable. Defaults to ``nmap`` on PATH.
        default_timeout:
            Seconds before a scan is killed. Per-call ``timeout`` overrides this.
        sudo:
            If True, prefix commands with ``sudo`` on POSIX systems. Individual
            scans that require privilege will also honour this.
        """
        resolved = shutil.which(nmap_path) or nmap_path
        if shutil.which(nmap_path) is None and not _looks_like_path(nmap_path):
            raise NmapError(
                f"nmap executable '{nmap_path}' not found on PATH. Install nmap "
                f"or pass an explicit nmap_path."
            )
        self.nmap_path = resolved
        self.default_timeout = default_timeout
        self.sudo = sudo
        self.is_windows = platform.system().lower().startswith("win")

    # ------------------------------------------------------------------ #
    # Host discovery
    # ------------------------------------------------------------------ #
    def ping_scan(
        self,
        target: str,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Host discovery only ("is it alive?"), no port scan. Sends ICMP echo plus
        TCP SYN to 80/443 and more. Maps to ``nmap -sn`` (the modern ``-sP``).
        Ideal first step to find live hosts in a range/CIDR before deeper scans.
        """
        return self._run(["-sn"], target, evasion, extra_args, timeout)

    def list_scan(
        self,
        target: str,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """List/enumerate targets without sending any packets (``nmap -sL``)."""
        return self._run(["-sL"], target, None, extra_args, timeout)

    def no_ping_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Skip host discovery and treat the target as up (``nmap -Pn``). Use when
        the host blocks ICMP so nmap would otherwise mark it down and skip it.
        """
        return self._run(["-Pn"], target, evasion, extra_args, timeout, ports=ports)

    # ------------------------------------------------------------------ #
    # Core TCP/UDP scan types
    # ------------------------------------------------------------------ #
    def syn_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """
        TCP SYN ("half-open") scan (``nmap -sS``). The fast default scan; never
        completes the handshake. Requires raw-socket privileges.
        """
        return self._run(
            ["-sS"], target, evasion, extra_args, timeout, ports=ports, privileged=privileged
        )

    def connect_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        TCP connect scan (``nmap -sT``). Completes the full three-way handshake;
        works without privileges. Louder and slower than SYN but always available.
        """
        return self._run(["-sT"], target, evasion, extra_args, timeout, ports=ports)

    def udp_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """
        UDP scan (``nmap -sU``). Finds UDP services (DNS, SNMP, DHCP...). Slow;
        consider limiting ``ports``. Requires privileges.
        """
        return self._run(
            ["-sU"], target, evasion, extra_args, timeout, ports=ports, privileged=privileged
        )

    def null_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """
        NULL scan (``nmap -sN``) - sends no TCP flags. Can slip past some
        stateless firewalls; only reliable against Unix-like stacks. Requires
        privileges.
        """
        return self._run(
            ["-sN"], target, evasion, extra_args, timeout, ports=ports, privileged=privileged
        )

    def fin_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """FIN scan (``nmap -sF``). Sends a lone FIN flag; stealthy firewall bypass."""
        return self._run(
            ["-sF"], target, evasion, extra_args, timeout, ports=ports, privileged=privileged
        )

    def xmas_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """XMAS scan (``nmap -sX``) - sets FIN, PSH, URG. Stealthy firewall bypass."""
        return self._run(
            ["-sX"], target, evasion, extra_args, timeout, ports=ports, privileged=privileged
        )

    def ack_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """
        TCP ACK scan (``nmap -sA``). Not for finding open ports - used to map
        firewall rules and tell stateful from stateless filtering.
        """
        return self._run(
            ["-sA"], target, evasion, extra_args, timeout, ports=ports, privileged=privileged
        )

    def idle_scan(
        self,
        target: str,
        zombie: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Idle / zombie scan (``nmap -sI <zombie> <target>``). Bounces the scan off
        an idle third host with predictable IP IDs so the target never sees the
        attacker's address. ``-Pn`` is added automatically as recommended.
        """
        if not zombie:
            raise NmapError("idle_scan requires a 'zombie' host.")
        return self._run(
            ["-sI", zombie, "-Pn"],
            target,
            evasion,
            extra_args,
            timeout,
            ports=ports,
            privileged=True,
        )

    def ftp_bounce_scan(
        self,
        target: str,
        ftp_relay: str,
        ports: Optional[str] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        FTP bounce scan (``nmap -b <ftp_relay> <target>``). Abuses the PORT
        command on legacy FTP servers to scan a target anonymously via the relay.
        """
        if not ftp_relay:
            raise NmapError("ftp_bounce_scan requires an 'ftp_relay' server.")
        return self._run(["-b", ftp_relay], target, None, extra_args, timeout, ports=ports)

    # ------------------------------------------------------------------ #
    # Service / OS / script detection
    # ------------------------------------------------------------------ #
    def version_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        intensity: Optional[int] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Service/version detection (``nmap -sV``). Fingerprints the exact software
        and version behind each open port so later phases can match CVEs.
        ``intensity`` (0-9) tunes probe aggressiveness via ``--version-intensity``.
        """
        base = ["-sV"]
        if intensity is not None:
            if not 0 <= int(intensity) <= 9:
                raise NmapError("version intensity must be between 0 and 9.")
            base += ["--version-intensity", str(int(intensity))]
        return self._run(base, target, evasion, extra_args, timeout, ports=ports)

    def os_scan(
        self,
        target: str,
        aggressive_guess: bool = False,
        limit: bool = False,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """
        OS fingerprinting (``nmap -O``). ``aggressive_guess`` adds
        ``--osscan-guess`` (guess harder), ``limit`` adds ``--osscan-limit``
        (only fingerprint promising hosts to save time). Requires privileges.
        """
        base = ["-O"]
        if aggressive_guess:
            base.append("--osscan-guess")
        if limit:
            base.append("--osscan-limit")
        return self._run(base, target, evasion, extra_args, timeout, privileged=privileged)

    def aggressive_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """
        Aggressive scan (``nmap -A``): OS detection, version detection, default
        scripts and traceroute in one pass. Very loud/easily detected. A common
        pairing is ``-A -T4``, so a default aggressive timing is applied unless
        the caller supplies their own via ``evasion``.
        """
        if evasion is None:
            evasion = EvasionOptions(timing="aggressive")
        return self._run(
            ["-A"], target, evasion, extra_args, timeout, ports=ports, privileged=privileged
        )

    def script_scan(
        self,
        target: str,
        scripts: Union[str, Iterable[str]] = "default",
        ports: Optional[str] = None,
        script_args: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Run Nmap Scripting Engine scripts (``nmap --script <spec>``). ``scripts``
        may be a category ("default", "vuln", "safe"), a script name, or a list.
        ``script_args`` maps to ``--script-args``.
        """
        spec = scripts if isinstance(scripts, str) else ",".join(scripts)
        base = ["--script", spec]
        if script_args:
            base += ["--script-args", script_args]
        return self._run(base, target, evasion, extra_args, timeout, ports=ports)

    # ------------------------------------------------------------------ #
    # Convenience / composite scans
    # ------------------------------------------------------------------ #
    def quick_scan(
        self,
        target: str,
        top_ports: int = 100,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """Fast scan of the N most common ports (``nmap --top-ports N -T4``)."""
        if evasion is None:
            evasion = EvasionOptions(timing="aggressive")
        return self._run(
            ["--top-ports", str(int(top_ports))], target, evasion, extra_args, timeout
        )

    def full_port_scan(
        self,
        target: str,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """Scan all 65535 TCP ports (``nmap -p- -sS``). Slow but thorough."""
        return self._run(
            ["-sS"], target, evasion, extra_args, timeout, ports="-", privileged=privileged
        )

    def comprehensive_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        evasion: Optional[EvasionOptions] = None,
        extra_args: Optional[Union[str, list[str]]] = None,
        timeout: Optional[int] = None,
        privileged: bool = True,
    ) -> dict[str, Any]:
        """
        One-shot recon: SYN scan + version + OS + default scripts
        (``nmap -sS -sV -O -sC``). Good default when you want maximum signal in a
        single call and stealth is not a concern.
        """
        return self._run(
            ["-sS", "-sV", "-O", "-sC"],
            target,
            evasion,
            extra_args,
            timeout,
            ports=ports,
            privileged=privileged,
        )

    # ------------------------------------------------------------------ #
    # Fully custom escape hatch (LLM-driven)
    # ------------------------------------------------------------------ #
    def custom_scan(
        self,
        target: str,
        flags: Union[str, list[str]],
        timeout: Optional[int] = None,
        privileged: bool = False,
    ) -> dict[str, Any]:
        """
        Run nmap with an arbitrary, caller-supplied set of flags.

        This is the escape hatch for the LLM: when the defined helpers do not fit
        (novel firewall/IDS bypass, an unusual combination of flags, a new NSE
        script, etc.) the agent can compose the exact nmap arguments it wants.

        Parameters
        ----------
        target:
            Target spec (host, IP, CIDR, range, or space-separated list).
        flags:
            Nmap flags either as a single string (e.g. ``"-sS -p 80,443 -T2 -f"``)
            which is tokenised with shlex, or as a pre-split list of tokens.
        privileged:
            Prefix ``sudo`` on POSIX if raw sockets are needed.

        Notes
        -----
        - Output formatting flags (``-oX/-oN/-oG/-oA``) are stripped and replaced
          by the wrapper's own output handling, so the result always contains the
          full human-readable report (``raw_output``), the full XML (``raw_xml``),
          and the structured parse.
        - The command still runs without a shell, so shell metacharacters in
          ``flags`` are not interpreted; each token is passed to nmap verbatim.
        """
        tokens = shlex.split(flags) if isinstance(flags, str) else [str(f) for f in flags]
        tokens = _strip_output_flags(tokens)
        return self._run(tokens, target, None, None, timeout, privileged=privileged)

    def raw_command(
        self,
        args: Union[str, list[str]],
        timeout: Optional[int] = None,
        privileged: bool = False,
    ) -> dict[str, Any]:
        """
        Lowest-level access: run nmap with a completely raw argument vector and no
        target/output handling by the wrapper (XML parsing still attempted). Use
        only when ``custom_scan`` is too constrained.
        """
        tokens = shlex.split(args) if isinstance(args, str) else [str(a) for a in args]
        cmd = self._base_command(privileged) + _strip_output_flags(tokens)
        return self._execute(cmd, timeout)

    # ------------------------------------------------------------------ #
    # Introspection helpers
    # ------------------------------------------------------------------ #
    def version(self) -> dict[str, Any]:
        """Return the installed nmap version banner (``nmap --version``)."""
        try:
            proc = subprocess.run(
                [self.nmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {"success": proc.returncode == 0, "output": proc.stdout.strip()}
        except (subprocess.SubprocessError, OSError) as exc:
            return {"success": False, "output": "", "error": str(exc)}

    # ------------------------------------------------------------------ #
    # Internal machinery
    # ------------------------------------------------------------------ #
    def _base_command(self, privileged: bool) -> list[str]:
        # `privileged` marks scans that need raw sockets; `sudo` is the operator's
        # opt-in switch. When sudo is enabled we prefix it on POSIX regardless, so
        # unprivileged scans still work under a sudo-configured scanner.
        cmd: list[str] = []
        if self.sudo and not self.is_windows:
            cmd.append("sudo")
        cmd.append(self.nmap_path)
        return cmd

    def _run(
        self,
        scan_flags: list[str],
        target: str,
        evasion: Optional[EvasionOptions],
        extra_args: Optional[Union[str, list[str]]],
        timeout: Optional[int],
        ports: Optional[str] = None,
        privileged: bool = False,
    ) -> dict[str, Any]:
        """Assemble a full nmap command from parts and execute it."""
        _validate_target(target)

        cmd = self._base_command(privileged)
        cmd += scan_flags

        if ports is not None:
            cmd += ["-p", str(ports)]

        if evasion is not None:
            cmd += evasion.to_args()

        if extra_args:
            extra_tokens = (
                shlex.split(extra_args)
                if isinstance(extra_args, str)
                else [str(a) for a in extra_args]
            )
            cmd += _strip_output_flags(extra_tokens)

        # `--` guarantees the target is never parsed as an option. Output flags
        # are injected by _execute so both human-readable and XML views are
        # always captured.
        cmd.append("--")
        cmd += shlex.split(target) if " " in target.strip() else [target]

        return self._execute(cmd, timeout)

    def _execute(self, cmd: list[str], timeout: Optional[int]) -> dict[str, Any]:
        """
        Run an assembled nmap command, capturing every view of the output.

        Output handling is centralised here so the summary agent always receives
        the complete picture:
          * ``-oN -``  sends the human-readable normal report to stdout.
          * ``-oX <tmp>`` writes full XML to a temp file for structured parsing
            and evidence, without competing with stdout.
        Neither view is a subset of the other, so nothing nmap emits is lost.
        """
        # Temp file for XML so stdout can carry the human-readable report.
        xml_fd, xml_path = tempfile.mkstemp(prefix="nmap_", suffix=".xml")
        os.close(xml_fd)
        output_flags = ["-oN", "-", "-oX", xml_path]

        # Insert output flags before the `--` target separator (nmap requires
        # options to precede the terminated target list).
        if "--" in cmd:
            idx = cmd.index("--")
            full_cmd = cmd[:idx] + output_flags + cmd[idx:]
        else:
            full_cmd = cmd + output_flags

        printable = " ".join(shlex.quote(c) for c in full_cmd)
        started = time.monotonic()
        try:
            proc = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.default_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            # Even on timeout, surface whatever partial output exists.
            partial_xml = _safe_read(xml_path)
            _safe_remove(xml_path)
            hosts, summary, _ = _parse_nmap_xml(partial_xml)
            summary["partial"] = True
            return ScanResult(
                command=printable,
                success=False,
                returncode=None,
                duration_seconds=time.monotonic() - started,
                hosts=hosts,
                summary=summary,
                raw_output=_as_text(exc.stdout),
                raw_xml=partial_xml,
                raw_stderr=_as_text(exc.stderr),
                error=f"nmap timed out after {timeout or self.default_timeout}s (partial output preserved)",
            ).to_dict()
        except (OSError, subprocess.SubprocessError) as exc:
            _safe_remove(xml_path)
            return ScanResult(
                command=printable,
                success=False,
                returncode=None,
                duration_seconds=time.monotonic() - started,
                error=f"failed to execute nmap: {exc}",
            ).to_dict()

        duration = time.monotonic() - started
        xml_text = _safe_read(xml_path)
        _safe_remove(xml_path)

        hosts, summary, parse_error = _parse_nmap_xml(xml_text)

        # An nmap run can exit 0 yet still have aborted mid-scan; treat a run
        # that reports an error state as unsuccessful so the planner reacts.
        run_errored = bool(summary.get("run_errormsg")) or summary.get("run_exit") == "error"
        success = proc.returncode == 0 and parse_error is None and not run_errored

        error = None
        if proc.returncode != 0:
            error = proc.stderr.strip() or f"nmap exited with code {proc.returncode}"
        elif parse_error is not None:
            error = f"nmap ran but XML parsing failed: {parse_error}"
        elif run_errored:
            error = summary.get("run_errormsg") or "nmap reported an error exit state"

        return ScanResult(
            command=printable,
            success=success,
            returncode=proc.returncode,
            duration_seconds=duration,
            hosts=hosts,
            summary=summary,
            raw_output=proc.stdout,
            raw_xml=xml_text,
            raw_stderr=proc.stderr,
            error=error,
        ).to_dict()


# ---------------------------------------------------------------------- #
# Module-level helpers
# ---------------------------------------------------------------------- #
def _looks_like_path(value: str) -> bool:
    return "/" in value or "\\" in value


def _safe_read(path: str) -> str:
    """Read a file's text, returning '' if it is missing/unreadable."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _safe_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _strip_output_flags(tokens: list[str]) -> list[str]:
    """
    Remove any user-supplied output flags so the wrapper's own ``-oX -`` is the
    single source of parseable output. Drops ``-oX/-oN/-oG/-oS/-oA`` and their
    following filename argument.
    """
    cleaned: list[str] = []
    skip_next = False
    output_flags = {"-oX", "-oN", "-oG", "-oS", "-oA"}
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in output_flags:
            skip_next = True
            continue
        # handle -oX- / -oXfile styles with no space
        if any(tok.startswith(f) and len(tok) > len(f) for f in output_flags):
            continue
        cleaned.append(tok)
    return cleaned


def _validate_target(target: str) -> None:
    if not target or not target.strip():
        raise NmapError("A non-empty target is required.")
    stripped = target.strip()
    # Reject leading '-' so a target can never be smuggled in as a flag even
    # before the '--' separator is applied.
    for token in stripped.split():
        if token.startswith("-"):
            raise NmapError(f"Invalid target token '{token}' (looks like a flag).")


def _parse_nmap_xml(xml_text: str) -> tuple[list[dict[str, Any]], dict[str, Any], Optional[str]]:
    """
    Parse nmap XML (from ``-oX -``) into a list of host dicts and a run summary.

    Returns ``(hosts, summary, error)``. On parse failure ``hosts``/``summary``
    are empty and ``error`` holds the reason.
    """
    if not xml_text or not xml_text.strip():
        return [], {}, "empty nmap output"

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return [], {}, str(exc)

    hosts: list[dict[str, Any]] = []
    for host_el in root.findall("host"):
        host: dict[str, Any] = {
            "state": _get(host_el.find("status"), "state"),
            "reason": _get(host_el.find("status"), "reason"),
            "addresses": [],
            "hostnames": [],
            "ports": [],
            "os": [],
        }

        for addr in host_el.findall("address"):
            host["addresses"].append(
                {
                    "addr": addr.get("addr"),
                    "type": addr.get("addrtype"),
                    "vendor": addr.get("vendor"),
                }
            )

        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                host["hostnames"].append({"name": hn.get("name"), "type": hn.get("type")})

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                port_info: dict[str, Any] = {
                    "port": _to_int(port_el.get("portid")),
                    "protocol": port_el.get("protocol"),
                    "state": _get(state_el, "state"),
                    "reason": _get(state_el, "reason"),
                    "service": _get(service_el, "name"),
                    "product": _get(service_el, "product"),
                    "version": _get(service_el, "version"),
                    "extrainfo": _get(service_el, "extrainfo"),
                    "tunnel": _get(service_el, "tunnel"),
                    "method": _get(service_el, "method"),
                    "conf": _get(service_el, "conf"),
                    "cpe": [cpe.text for cpe in service_el.findall("cpe")] if service_el is not None else [],
                    "scripts": [_parse_script(s) for s in port_el.findall("script")],
                }
                host["ports"].append(port_info)

            # Aggregated ports nmap did not list individually (e.g. "998 closed").
            for extra_el in ports_el.findall("extraports"):
                reasons = [
                    {"reason": r.get("reason"), "count": _to_int(r.get("count"))}
                    for r in extra_el.findall("extrareasons")
                ]
                host.setdefault("extraports", []).append(
                    {
                        "state": extra_el.get("state"),
                        "count": _to_int(extra_el.get("count")),
                        "reasons": reasons,
                    }
                )

        os_el = host_el.find("os")
        if os_el is not None:
            for match in os_el.findall("osmatch"):
                host["os"].append(
                    {
                        "name": match.get("name"),
                        "accuracy": _to_int(match.get("accuracy")),
                        "classes": [
                            {
                                "type": c.get("type"),
                                "vendor": c.get("vendor"),
                                "family": c.get("osfamily"),
                                "gen": c.get("osgen"),
                                "accuracy": _to_int(c.get("accuracy")),
                            }
                            for c in match.findall("osclass")
                        ],
                    }
                )

        # host-level scripts (hostscript)
        hostscript_el = host_el.find("hostscript")
        if hostscript_el is not None:
            host["host_scripts"] = [_parse_script(s) for s in hostscript_el.findall("script")]

        # uptime / network distance
        uptime_el = host_el.find("uptime")
        if uptime_el is not None:
            host["uptime"] = {
                "seconds": _to_int(uptime_el.get("seconds")),
                "lastboot": uptime_el.get("lastboot"),
            }
        distance_el = host_el.find("distance")
        if distance_el is not None:
            host["distance"] = _to_int(distance_el.get("value"))

        # traceroute
        trace_el = host_el.find("trace")
        if trace_el is not None:
            host["traceroute"] = {
                "port": _to_int(trace_el.get("port")),
                "protocol": trace_el.get("proto"),
                "hops": [
                    {
                        "ttl": _to_int(h.get("ttl")),
                        "ipaddr": h.get("ipaddr"),
                        "rtt": h.get("rtt"),
                        "host": h.get("host"),
                    }
                    for h in trace_el.findall("hop")
                ],
            }

        hosts.append(host)

    summary: dict[str, Any] = {
        "args": root.get("args"),
        "version": root.get("version"),
        "start": root.get("startstr") or root.get("start"),
    }

    # Scan-level (pre/post) NSE scripts live directly under <nmaprun>.
    prescript = root.find("prescript")
    if prescript is not None:
        summary["pre_scripts"] = [_parse_script(s) for s in prescript.findall("script")]
    postscript = root.find("postscript")
    if postscript is not None:
        summary["post_scripts"] = [_parse_script(s) for s in postscript.findall("script")]

    runstats = root.find("runstats")
    if runstats is not None:
        hosts_stat = runstats.find("hosts")
        finished = runstats.find("finished")
        if hosts_stat is not None:
            summary["hosts_up"] = _to_int(hosts_stat.get("up"))
            summary["hosts_down"] = _to_int(hosts_stat.get("down"))
            summary["hosts_total"] = _to_int(hosts_stat.get("total"))
        if finished is not None:
            summary["elapsed"] = finished.get("elapsed")
            summary["summary"] = finished.get("summary")
            # exit == "error" (or an errormsg) means the run aborted early.
            summary["run_exit"] = finished.get("exit")
            if finished.get("errormsg"):
                summary["run_errormsg"] = finished.get("errormsg")

    # Port tallies across all hosts, including the aggregated extraports so the
    # summary reflects filtered/closed volume, not just the enumerated ports.
    port_states: dict[str, int] = {}
    for h in hosts:
        for p in h.get("ports", []):
            state = p.get("state")
            if state:
                port_states[state] = port_states.get(state, 0) + 1
        for extra in h.get("extraports", []):
            state = extra.get("state")
            count = extra.get("count") or 0
            if state:
                port_states[state] = port_states.get(state, 0) + count
    summary["open_ports"] = port_states.get("open", 0)
    summary["port_state_counts"] = port_states
    return hosts, summary, None


def _parse_script(script_el: ET.Element) -> dict[str, Any]:
    """
    Parse an NSE <script> element into both its flat human output and any
    structured <table>/<elem> data it carries (e.g. vuln script tables), so the
    summary agent gets the machine-readable form as well as the text.
    """
    entry: dict[str, Any] = {
        "id": script_el.get("id"),
        "output": script_el.get("output"),
    }
    data = _parse_script_node(script_el)
    if data:
        entry["data"] = data
    return entry


def _parse_script_node(node: ET.Element) -> Any:
    """Recursively turn <table>/<elem> children into dicts/lists."""
    mapping: dict[str, Any] = {}
    items: list[Any] = []
    for child in node:
        if child.tag == "elem":
            value = child.text
            key = child.get("key")
            if key is not None:
                mapping[key] = value
            else:
                items.append(value)
        elif child.tag == "table":
            value = _parse_script_node(child)
            key = child.get("key")
            if key is not None:
                mapping[key] = value
            else:
                items.append(value)
    if mapping and items:
        mapping["_items"] = items
        return mapping
    if mapping:
        return mapping
    return items


def _get(element: Optional[ET.Element], attr: str) -> Optional[str]:
    return element.get(attr) if element is not None else None


def _to_int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


__all__ = ["NmapScanner", "EvasionOptions", "ScanResult", "NmapError", "TIMING_TEMPLATES"]


if __name__ == "__main__":
    import json
    import sys

    scanner = NmapScanner()
    ver = scanner.version()
    print(json.dumps(ver, indent=2))
    if len(sys.argv) > 1:
        out = scanner.quick_scan(sys.argv[1])
        print(json.dumps(out, indent=2))
