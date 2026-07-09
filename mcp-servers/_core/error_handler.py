"""
IntelligentErrorHandler + GracefulDegradation — lifted from HexStrike hexstrike_server.py (~1606–2427).

Strips Flask/ANSI telemetry only. Use via ``error_handler`` / ``degradation_manager`` singletons
or ``process_tool_failure()`` for Summary Agent → graph ingestion.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


class ErrorType(str, Enum):
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_UNREACHABLE = "network_unreachable"
    RATE_LIMITED = "rate_limited"
    TOOL_NOT_FOUND = "tool_not_found"
    INVALID_PARAMETERS = "invalid_parameters"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    PARSING_ERROR = "parsing_error"
    UNKNOWN = "unknown"


class RecoveryAction(str, Enum):
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    RETRY_WITH_REDUCED_SCOPE = "retry_with_reduced_scope"
    SWITCH_TO_ALTERNATIVE_TOOL = "switch_to_alternative_tool"
    ADJUST_PARAMETERS = "adjust_parameters"
    ESCALATE_TO_HUMAN = "escalate_to_human"
    GRACEFUL_DEGRADATION = "graceful_degradation"
    ABORT_OPERATION = "abort_operation"


@dataclass
class ErrorContext:
    tool_name: str
    target: str
    parameters: dict[str, Any]
    error_type: ErrorType
    error_message: str
    attempt_count: int
    timestamp: datetime
    stack_trace: str
    system_resources: dict[str, Any]
    previous_errors: list[ErrorContext] = field(default_factory=list)


@dataclass
class RecoveryStrategy:
    action: RecoveryAction
    parameters: dict[str, Any]
    max_attempts: int
    backoff_multiplier: float
    success_probability: float
    estimated_time: int


class IntelligentErrorHandler:
    """Advanced error handling with automatic recovery strategies."""

    def __init__(self) -> None:
        self.error_patterns = self._initialize_error_patterns()
        self.recovery_strategies = self._initialize_recovery_strategies()
        self.tool_alternatives = self._initialize_tool_alternatives()
        self.parameter_adjustments = self._initialize_parameter_adjustments()
        self.error_history: list[ErrorContext] = []
        self.max_history_size = 1000

    def _initialize_error_patterns(self) -> dict[str, ErrorType]:
        return {
            r"timeout|timed out|connection timeout|read timeout": ErrorType.TIMEOUT,
            r"operation timed out|command timeout": ErrorType.TIMEOUT,
            r"permission denied|access denied|forbidden|not authorized": ErrorType.PERMISSION_DENIED,
            r"sudo required|root required|insufficient privileges": ErrorType.PERMISSION_DENIED,
            r"network unreachable|host unreachable|no route to host": ErrorType.NETWORK_UNREACHABLE,
            r"connection refused|connection reset|network error": ErrorType.NETWORK_UNREACHABLE,
            r"rate limit|too many requests|throttled|429": ErrorType.RATE_LIMITED,
            r"request limit exceeded|quota exceeded": ErrorType.RATE_LIMITED,
            r"command not found|no such file or directory|not found": ErrorType.TOOL_NOT_FOUND,
            r"executable not found|binary not found": ErrorType.TOOL_NOT_FOUND,
            r"invalid argument|invalid option|unknown option": ErrorType.INVALID_PARAMETERS,
            r"bad parameter|invalid parameter|syntax error": ErrorType.INVALID_PARAMETERS,
            r"out of memory|memory error|disk full|no space left": ErrorType.RESOURCE_EXHAUSTED,
            r"resource temporarily unavailable|too many open files": ErrorType.RESOURCE_EXHAUSTED,
            r"authentication failed|login failed|invalid credentials": ErrorType.AUTHENTICATION_FAILED,
            r"unauthorized|invalid token|expired token": ErrorType.AUTHENTICATION_FAILED,
            r"target unreachable|target not responding|target down": ErrorType.TARGET_UNREACHABLE,
            r"host not found|dns resolution failed": ErrorType.TARGET_UNREACHABLE,
            r"parse error|parsing failed|invalid format|malformed": ErrorType.PARSING_ERROR,
            r"json decode error|xml parse error|invalid json": ErrorType.PARSING_ERROR,
        }


    def _initialize_recovery_strategies(self) -> dict[ErrorType, list[RecoveryStrategy]]:
        return {
            ErrorType.TIMEOUT: [
                RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 5, "max_delay": 60}, 3, 2.0, 0.7, 30),
                RecoveryStrategy(RecoveryAction.RETRY_WITH_REDUCED_SCOPE, {"reduce_threads": True, "reduce_timeout": True}, 2, 1.0, 0.8, 45),
                RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"prefer_faster_tools": True}, 1, 1.0, 0.6, 60),
            ],
            ErrorType.PERMISSION_DENIED: [
                RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Privilege escalation required", "urgency": "medium"}, 1, 1.0, 0.9, 300),
                RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"require_no_privileges": True}, 1, 1.0, 0.5, 30),
            ],
            ErrorType.NETWORK_UNREACHABLE: [
                RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 10, "max_delay": 120}, 3, 2.0, 0.6, 60),
                RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"prefer_offline_tools": True}, 1, 1.0, 0.4, 30),
            ],
            ErrorType.RATE_LIMITED: [
                RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 30, "max_delay": 300}, 5, 1.5, 0.9, 180),
                RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"reduce_rate": True, "increase_delays": True}, 2, 1.0, 0.8, 120),
            ],
            ErrorType.TOOL_NOT_FOUND: [
                RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"find_equivalent": True}, 1, 1.0, 0.7, 15),
                RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Tool installation required", "urgency": "low"}, 1, 1.0, 0.9, 600),
            ],
            ErrorType.INVALID_PARAMETERS: [
                RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"use_defaults": True, "remove_invalid": True}, 3, 1.0, 0.8, 10),
                RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"simpler_interface": True}, 1, 1.0, 0.6, 30),
            ],
            ErrorType.RESOURCE_EXHAUSTED: [
                RecoveryStrategy(RecoveryAction.RETRY_WITH_REDUCED_SCOPE, {"reduce_memory": True, "reduce_threads": True}, 2, 1.0, 0.7, 60),
                RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 60, "max_delay": 300}, 2, 2.0, 0.5, 180),
            ],
            ErrorType.AUTHENTICATION_FAILED: [
                RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Authentication credentials required", "urgency": "high"}, 1, 1.0, 0.9, 300),
                RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"no_auth_required": True}, 1, 1.0, 0.4, 30),
            ],
            ErrorType.TARGET_UNREACHABLE: [
                RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 15, "max_delay": 180}, 3, 2.0, 0.6, 90),
                RecoveryStrategy(RecoveryAction.GRACEFUL_DEGRADATION, {"skip_target": True, "continue_with_others": True}, 1, 1.0, 1.0, 5),
            ],
            ErrorType.PARSING_ERROR: [
                RecoveryStrategy(RecoveryAction.ADJUST_PARAMETERS, {"change_output_format": True, "add_parsing_flags": True}, 2, 1.0, 0.7, 20),
                RecoveryStrategy(RecoveryAction.SWITCH_TO_ALTERNATIVE_TOOL, {"better_output_format": True}, 1, 1.0, 0.6, 30),
            ],
            ErrorType.UNKNOWN: [
                RecoveryStrategy(RecoveryAction.RETRY_WITH_BACKOFF, {"initial_delay": 5, "max_delay": 30}, 2, 2.0, 0.3, 45),
                RecoveryStrategy(RecoveryAction.ESCALATE_TO_HUMAN, {"message": "Unknown error encountered", "urgency": "medium"}, 1, 1.0, 0.9, 300),
            ],
        }

    def _initialize_tool_alternatives(self) -> dict[str, list[str]]:
        return {
            "nmap": ["rustscan", "masscan", "zmap"],
            "rustscan": ["nmap", "masscan"],
            "masscan": ["nmap", "rustscan", "zmap"],
            "gobuster": ["feroxbuster", "dirsearch", "ffuf", "dirb"],
            "feroxbuster": ["gobuster", "dirsearch", "ffuf"],
            "dirsearch": ["gobuster", "feroxbuster", "ffuf"],
            "ffuf": ["gobuster", "feroxbuster", "dirsearch"],
            "nuclei": ["jaeles", "nikto", "w3af"],
            "jaeles": ["nuclei", "nikto"],
            "nikto": ["nuclei", "jaeles", "w3af"],
            "katana": ["gau", "waybackurls", "hakrawler"],
            "gau": ["katana", "waybackurls", "hakrawler"],
            "waybackurls": ["gau", "katana", "hakrawler"],
            "arjun": ["paramspider", "x8", "ffuf"],
            "paramspider": ["arjun", "x8"],
            "x8": ["arjun", "paramspider"],
            "sqlmap": ["sqlninja", "jsql-injection"],
            "dalfox": ["xsser", "xsstrike"],
            "subfinder": ["amass", "assetfinder", "findomain"],
            "amass": ["subfinder", "assetfinder", "findomain"],
            "assetfinder": ["subfinder", "amass", "findomain"],
            "prowler": ["scout-suite", "cloudmapper"],
            "scout-suite": ["prowler", "cloudmapper"],
            "trivy": ["clair", "docker-bench-security"],
            "clair": ["trivy", "docker-bench-security"],
            "ghidra": ["radare2", "ida", "binary-ninja"],
            "radare2": ["ghidra", "objdump", "gdb"],
            "gdb": ["radare2", "lldb"],
            "pwntools": ["ropper", "ropgadget"],
            "ropper": ["ropgadget", "pwntools"],
            "ropgadget": ["ropper", "pwntools"],
        }

    def _initialize_parameter_adjustments(self) -> dict[str, dict[ErrorType, dict[str, Any]]]:
        return {
            "nmap": {
                ErrorType.TIMEOUT: {"timing": "-T2", "reduce_ports": True},
                ErrorType.RATE_LIMITED: {"timing": "-T1", "delay": "1000ms"},
                ErrorType.RESOURCE_EXHAUSTED: {"max_parallelism": "10"},
            },
            "gobuster": {
                ErrorType.TIMEOUT: {"threads": "10", "timeout": "30s"},
                ErrorType.RATE_LIMITED: {"threads": "5", "delay": "1s"},
                ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"},
            },
            "nuclei": {
                ErrorType.TIMEOUT: {"concurrency": "10", "timeout": "30"},
                ErrorType.RATE_LIMITED: {"rate-limit": "10", "concurrency": "5"},
                ErrorType.RESOURCE_EXHAUSTED: {"concurrency": "5"},
            },
            "feroxbuster": {
                ErrorType.TIMEOUT: {"threads": "10", "timeout": "30"},
                ErrorType.RATE_LIMITED: {"threads": "5", "rate-limit": "10"},
                ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"},
            },
            "ffuf": {
                ErrorType.TIMEOUT: {"threads": "10", "timeout": "30"},
                ErrorType.RATE_LIMITED: {"threads": "5", "rate": "10"},
                ErrorType.RESOURCE_EXHAUSTED: {"threads": "5"},
            },
        }

    def classify_error(self, error_message: str, exception: BaseException | None = None) -> ErrorType:
        error_text = error_message.lower()
        if exception:
            if isinstance(exception, TimeoutError):
                return ErrorType.TIMEOUT
            if isinstance(exception, PermissionError):
                return ErrorType.PERMISSION_DENIED
            if isinstance(exception, ConnectionError):
                return ErrorType.NETWORK_UNREACHABLE
            if isinstance(exception, FileNotFoundError):
                return ErrorType.TOOL_NOT_FOUND
        for pattern, error_type in self.error_patterns.items():
            if re.search(pattern, error_text, re.IGNORECASE):
                return error_type
        return ErrorType.UNKNOWN

    def handle_tool_failure(self, tool: str, error: BaseException, context: dict[str, Any]) -> RecoveryStrategy:
        error_message = str(error)
        error_type = self.classify_error(error_message, error)
        error_context = ErrorContext(
            tool_name=tool,
            target=context.get("target", "unknown"),
            parameters=context.get("parameters", {}),
            error_type=error_type,
            error_message=error_message,
            attempt_count=context.get("attempt_count", 1),
            timestamp=datetime.now(),
            stack_trace=traceback.format_exc(),
            system_resources=self._get_system_resources(),
        )
        self._add_to_history(error_context)
        strategies = self.recovery_strategies.get(error_type, self.recovery_strategies[ErrorType.UNKNOWN])
        best_strategy = self._select_best_strategy(strategies, error_context)
        logger.warning(
            "Recovery for %s: %s — applying %s",
            tool,
            error_type.value,
            best_strategy.action.value,
        )
        return best_strategy

    def _select_best_strategy(self, strategies: list[RecoveryStrategy], context: ErrorContext) -> RecoveryStrategy:
        viable = [s for s in strategies if context.attempt_count <= s.max_attempts]
        if not viable:
            return RecoveryStrategy(
                RecoveryAction.ESCALATE_TO_HUMAN,
                {"message": f"All recovery strategies exhausted for {context.tool_name}", "urgency": "high"},
                1,
                1.0,
                0.9,
                300,
            )
        scored: list[tuple[float, RecoveryStrategy]] = []
        for strategy in viable:
            adjusted_probability = strategy.success_probability * (0.9 ** (context.attempt_count - 1))
            score = adjusted_probability - (strategy.estimated_time / 1000.0)
            scored.append((score, strategy))
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[0][1]

    def auto_adjust_parameters(
        self, tool: str, error_type: ErrorType, original_params: dict[str, Any]
    ) -> dict[str, Any]:
        base_tool = normalize_tool_key(tool)
        adjustments = self.parameter_adjustments.get(base_tool, {}).get(error_type, {})
        if not adjustments:
            if error_type == ErrorType.TIMEOUT:
                adjustments = {"timeout": "60", "threads": "5"}
            elif error_type == ErrorType.RATE_LIMITED:
                adjustments = {"delay": "2s", "threads": "3"}
            elif error_type == ErrorType.RESOURCE_EXHAUSTED:
                adjustments = {"threads": "3", "memory_limit": "1G"}
        adjusted_params = original_params.copy()
        adjusted_params.update(adjustments)
        logger.info("Parameter adjustment for %s: %s", tool, adjustments)
        return adjusted_params

    def get_alternative_tool(self, failed_tool: str, context: dict[str, Any]) -> Optional[str]:
        base_tool = normalize_tool_key(failed_tool)
        alternatives = self.tool_alternatives.get(base_tool, [])
        if not alternatives:
            return None
        filtered: list[str] = []
        for alt in alternatives:
            if context.get("require_no_privileges") and alt in ["nmap", "masscan"]:
                continue
            if context.get("prefer_faster_tools") and alt in ["amass", "w3af"]:
                continue
            filtered.append(alt)
        if not filtered:
            filtered = alternatives
        return filtered[0] if filtered else None

    def escalate_to_human(self, context: ErrorContext, urgency: str = "medium") -> dict[str, Any]:
        escalation_data = {
            "timestamp": context.timestamp.isoformat(),
            "tool": context.tool_name,
            "target": context.target,
            "error_type": context.error_type.value,
            "error_message": context.error_message,
            "attempt_count": context.attempt_count,
            "urgency": urgency,
            "suggested_actions": self._get_human_suggestions(context),
            "context": {
                "parameters": context.parameters,
                "system_resources": context.system_resources,
                "recent_errors": [e.error_message for e in context.previous_errors[-5:]],
            },
        }
        logger.error("Human escalation required for %s: %s", context.tool_name, context.error_message)
        logger.debug("Escalation payload: %s", json.dumps(escalation_data, indent=2))
        return escalation_data

    def _get_human_suggestions(self, context: ErrorContext) -> list[str]:
        if context.error_type == ErrorType.PERMISSION_DENIED:
            return [
                "Run the command with sudo privileges",
                "Check file/directory permissions",
                "Verify user is in required groups",
            ]
        if context.error_type == ErrorType.TOOL_NOT_FOUND:
            return [
                f"Install {context.tool_name} using package manager",
                "Check if tool is in PATH",
                "Verify tool installation",
            ]
        if context.error_type == ErrorType.NETWORK_UNREACHABLE:
            return ["Check network connectivity", "Verify target is accessible", "Check firewall rules"]
        if context.error_type == ErrorType.RATE_LIMITED:
            return ["Wait before retrying", "Use slower scan rates", "Check API rate limits"]
        return ["Review error details and logs"]

    def _get_system_resources(self) -> dict[str, Any]:
        try:
            import psutil

            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage("/").percent,
                "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None,
                "active_processes": len(psutil.pids()),
            }
        except Exception:
            return {"error": "Unable to get system resources"}

    def _add_to_history(self, error_context: ErrorContext) -> None:
        self.error_history.append(error_context)
        if len(self.error_history) > self.max_history_size:
            self.error_history = self.error_history[-self.max_history_size :]

    def get_error_statistics(self) -> dict[str, Any]:
        if not self.error_history:
            return {"total_errors": 0}
        error_counts: dict[str, int] = {}
        tool_errors: dict[str, int] = {}
        recent_errors: list[dict[str, str]] = []
        for error in self.error_history:
            error_type = error.error_type.value
            tool = error.tool_name
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
            tool_errors[tool] = tool_errors.get(tool, 0) + 1
            if (datetime.now() - error.timestamp).total_seconds() < 3600:
                recent_errors.append(
                    {"tool": tool, "error_type": error_type, "timestamp": error.timestamp.isoformat()}
                )
        return {
            "total_errors": len(self.error_history),
            "error_counts_by_type": error_counts,
            "error_counts_by_tool": tool_errors,
            "recent_errors_count": len(recent_errors),
            "recent_errors": recent_errors[-10:],
        }


class GracefulDegradation:
    """Ensure system continues operating even with partial tool failures."""

    def __init__(self) -> None:
        self.fallback_chains = self._initialize_fallback_chains()
        self.critical_operations = self._initialize_critical_operations()

    def _initialize_fallback_chains(self) -> dict[str, list[list[str]]]:
        return {
            "network_discovery": [["nmap", "rustscan", "masscan"], ["rustscan", "nmap"], ["ping", "telnet"]],
            "web_discovery": [["gobuster", "feroxbuster", "dirsearch"], ["feroxbuster", "ffuf"], ["curl", "wget"]],
            "vulnerability_scanning": [["nuclei", "jaeles", "nikto"], ["nikto", "w3af"], ["curl"]],
            "subdomain_enumeration": [["subfinder", "amass", "assetfinder"], ["amass", "findomain"], ["dig", "nslookup"]],
            "parameter_discovery": [["arjun", "paramspider", "x8"], ["ffuf", "wfuzz"], ["manual_testing"]],
        }

    def _initialize_critical_operations(self) -> set[str]:
        return {
            "network_discovery",
            "web_discovery",
            "vulnerability_scanning",
            "subdomain_enumeration",
        }

    def create_fallback_chain(self, operation: str, failed_tools: list[str] | None = None) -> list[str]:
        failed_tools = failed_tools or []
        chains = self.fallback_chains.get(operation, [])
        for chain in chains:
            viable = [tool for tool in chain if tool not in failed_tools]
            if viable:
                logger.info("Fallback chain for %s: %s", operation, viable)
                return viable
        basic_fallbacks = {
            "network_discovery": ["ping"],
            "web_discovery": ["curl"],
            "vulnerability_scanning": ["curl"],
            "subdomain_enumeration": ["dig"],
        }
        fallback = basic_fallbacks.get(operation, ["manual_testing"])
        logger.warning("Using basic fallback for %s: %s", operation, fallback)
        return fallback

    def handle_partial_failure(
        self, operation: str, partial_results: dict[str, Any], failed_components: list[str]
    ) -> dict[str, Any]:
        enhanced = partial_results.copy()
        enhanced["degradation_info"] = {
            "operation": operation,
            "failed_components": failed_components,
            "partial_success": True,
            "fallback_applied": True,
            "timestamp": datetime.now().isoformat(),
        }
        if operation == "network_discovery" and "open_ports" not in partial_results:
            enhanced["open_ports"] = self._basic_port_check(partial_results.get("target"))
        elif operation == "web_discovery" and "directories" not in partial_results:
            enhanced["directories"] = self._basic_directory_check(partial_results.get("target"))
        elif operation == "vulnerability_scanning" and "vulnerabilities" not in partial_results:
            enhanced["vulnerabilities"] = self._basic_security_check(partial_results.get("target"))
        enhanced["manual_recommendations"] = self._get_manual_recommendations(operation, failed_components)
        logger.info("Graceful degradation applied for %s", operation)
        return enhanced

    def _basic_port_check(self, target: str) -> list[int]:
        if not target:
            return []
        host = target.replace("https://", "").replace("http://", "").split("/")[0]
        open_ports: list[int] = []
        for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((host, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except OSError:
                continue
        return open_ports

    def _basic_directory_check(self, target: str) -> list[str]:
        if not target:
            return []
        found: list[str] = []
        for directory in ["/admin", "/login", "/api", "/wp-admin", "/phpmyadmin", "/robots.txt"]:
            try:
                url = f"{target.rstrip('/')}{directory}"
                req = Request(url, method="HEAD")
                with urlopen(req, timeout=5) as resp:
                    if resp.status in (200, 301, 302, 403):
                        found.append(directory)
            except (URLError, OSError, ValueError):
                continue
        return found

    def _basic_security_check(self, target: str) -> list[dict[str, Any]]:
        if not target:
            return []
        vulnerabilities: list[dict[str, Any]] = []
        try:
            with urlopen(target, timeout=10) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
            for header, description in {
                "x-frame-options": "Clickjacking protection missing",
                "x-content-type-options": "MIME type sniffing protection missing",
                "x-xss-protection": "XSS protection missing",
                "strict-transport-security": "HTTPS enforcement missing",
                "content-security-policy": "Content Security Policy missing",
            }.items():
                if header not in headers:
                    vulnerabilities.append(
                        {
                            "type": "missing_security_header",
                            "severity": "medium",
                            "description": description,
                            "header": header,
                        }
                    )
        except Exception as exc:
            vulnerabilities.append(
                {
                    "type": "connection_error",
                    "severity": "info",
                    "description": f"Could not perform basic security check: {exc}",
                }
            )
        return vulnerabilities

    def _get_manual_recommendations(self, operation: str, failed_components: list[str]) -> list[str]:
        base_recommendations = {
            "network_discovery": [
                "Manually test common ports using telnet or nc",
                "Check for service banners manually",
            ],
            "web_discovery": [
                "Manually browse common directories",
                "Check robots.txt and sitemap.xml",
            ],
            "vulnerability_scanning": [
                "Manually test for common vulnerabilities",
                "Check security headers using browser tools",
            ],
            "subdomain_enumeration": [
                "Use online subdomain discovery tools",
                "Check certificate transparency logs",
            ],
        }
        recommendations = list(base_recommendations.get(operation, []))
        for component in failed_components:
            if component == "nmap":
                recommendations.append("Consider using online port scanners")
            elif component == "gobuster":
                recommendations.append("Try manual directory browsing")
            elif component == "nuclei":
                recommendations.append("Perform manual vulnerability testing")
        return recommendations

    def is_critical_operation(self, operation: str) -> bool:
        return operation in self.critical_operations


error_handler = IntelligentErrorHandler()
degradation_manager = GracefulDegradation()


def normalize_tool_key(tool_name: str) -> str:
    """Map MCP tool names (e.g. nmap_syn_scan) to adjustment/alternative keys (nmap)."""
    base = tool_name.replace("_scan", "").replace("_attack", "").replace("_crack", "")
    base = base.replace("_fast_scan", "").replace("_high_speed", "").replace("_probe", "")
    for suffix in ("_enumeration", "_discovery", "_analyze", "_run", "_exploit"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base.replace("_", "-").split("-")[0] if base else tool_name


def determine_operation_type(tool_name: str) -> str:
    mapping = {
        "nmap": "network_discovery",
        "rustscan": "network_discovery",
        "masscan": "network_discovery",
        "gobuster": "web_discovery",
        "feroxbuster": "web_discovery",
        "dirsearch": "web_discovery",
        "ffuf": "web_discovery",
        "nuclei": "vulnerability_scanning",
        "jaeles": "vulnerability_scanning",
        "nikto": "vulnerability_scanning",
        "subfinder": "subdomain_enumeration",
        "amass": "subdomain_enumeration",
        "assetfinder": "subdomain_enumeration",
        "arjun": "parameter_discovery",
        "paramspider": "parameter_discovery",
        "x8": "parameter_discovery",
    }
    return mapping.get(normalize_tool_key(tool_name), "unknown_operation")


def rebuild_command_with_params(tool_name: str, original_command: str, new_params: dict[str, Any]) -> str:
    """Append tool-specific flags after parameter adjustment (HexStrike recipe)."""
    base = normalize_tool_key(tool_name)
    additional_args: list[str] = []
    for key, value in new_params.items():
        if key == "timeout" and base in ["nmap", "gobuster", "nuclei"]:
            additional_args.append(f"--timeout {value}")
        elif key == "threads" and base in ["gobuster", "feroxbuster", "ffuf"]:
            additional_args.append(f"-t {value}")
        elif key == "delay" and base in ["gobuster", "feroxbuster"]:
            additional_args.append(f"--delay {value}")
        elif key == "timing" and base == "nmap":
            additional_args.append(f"{value}")
        elif key == "concurrency" and base == "nuclei":
            additional_args.append(f"-c {value}")
        elif key == "rate-limit" and base == "nuclei":
            additional_args.append(f"-rl {value}")
    if additional_args:
        return f"{original_command} {' '.join(additional_args)}"
    return original_command


def process_tool_failure(
    tool_name: str,
    error_message: str,
    *,
    parameters: dict[str, Any] | None = None,
    target: str = "unknown",
    attempt_count: int = 1,
    timed_out: bool = False,
    handler: IntelligentErrorHandler | None = None,
) -> dict[str, Any]:
    """
    Summary Agent contract: classify a tool failure and return the recovery decision
    before writing to the engagement graph.

    Returns retry/switch/adjust/escalate guidance the orchestrator acts on.
    """
    handler = handler or error_handler
    parameters = parameters or {}
    if timed_out:
        error_message = error_message or "Command timed out"
    exception = TimeoutError(error_message) if timed_out else Exception(error_message)
    context = {
        "target": target or parameters.get("target", parameters.get("url", "unknown")),
        "parameters": parameters,
        "attempt_count": attempt_count,
    }
    strategy = handler.handle_tool_failure(tool_name, exception, context)
    error_type = handler.classify_error(error_message, exception)
    alternative = handler.get_alternative_tool(tool_name, strategy.parameters)
    adjusted = handler.auto_adjust_parameters(tool_name, error_type, parameters)
    backoff_seconds = 0.0
    if strategy.action == RecoveryAction.RETRY_WITH_BACKOFF:
        delay = strategy.parameters.get("initial_delay", 5)
        max_delay = strategy.parameters.get("max_delay", 60)
        backoff_seconds = min(
            delay * (strategy.backoff_multiplier ** (attempt_count - 1)),
            max_delay,
        )
    escalation = None
    if strategy.action == RecoveryAction.ESCALATE_TO_HUMAN:
        escalation = handler.escalate_to_human(
            ErrorContext(
                tool_name=tool_name,
                target=str(context["target"]),
                parameters=parameters,
                error_type=error_type,
                error_message=error_message,
                attempt_count=attempt_count,
                timestamp=datetime.now(),
                stack_trace="",
                system_resources=handler._get_system_resources(),
            ),
            strategy.parameters.get("urgency", "medium"),
        )
    return {
        "error_type": error_type.value,
        "recovery_action": strategy.action.value,
        "should_retry": strategy.action
        in (
            RecoveryAction.RETRY_WITH_BACKOFF,
            RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
            RecoveryAction.ADJUST_PARAMETERS,
        ),
        "backoff_seconds": backoff_seconds,
        "adjusted_parameters": adjusted,
        "alternative_tool": alternative,
        "human_escalation": escalation,
        "strategy": {
            "max_attempts": strategy.max_attempts,
            "success_probability": strategy.success_probability,
            "estimated_time": strategy.estimated_time,
            "parameters": strategy.parameters,
        },
        "fallback_chain": degradation_manager.create_fallback_chain(
            determine_operation_type(tool_name),
            [normalize_tool_key(tool_name)],
        ),
    }
