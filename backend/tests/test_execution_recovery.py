"""Component 1 (shadow mode): classifier + strategy table + observation store."""

from __future__ import annotations

from pentest_platform.services.execution_recovery import (
    ErrorType,
    RecoveryAction,
    classify_error,
    next_strategy,
    strategies_for,
)


def test_successful_run_never_classified_even_with_error_looking_text():
    # nmap prints "connection refused" for a closed port on a SUCCESSFUL run —
    # must never be misclassified as a failure. exit_code=0 short-circuits
    # before any regex ever runs against stdout/stderr.
    result = classify_error(
        exit_code=0,
        stdout="PORT 80/tcp closed\nconnection refused\n",
        stderr="",
        empty_success=False,
    )
    assert result is None


def test_timeout_classified_only_on_nonzero_exit():
    assert classify_error(exit_code=1, stdout="", stderr="Operation timed out") == ErrorType.TIMEOUT
    assert classify_error(exit_code=124, stdout="", stderr="command timeout after 90s") == ErrorType.TIMEOUT


def test_rate_limited_classification():
    assert classify_error(exit_code=1, stdout="", stderr="HTTP 429 Too Many Requests") == ErrorType.RATE_LIMITED


def test_tool_not_found_classification():
    assert (
        classify_error(exit_code=127, stdout="", stderr="bash: nuclei: command not found")
        == ErrorType.TOOL_NOT_FOUND
    )


def test_empty_result_is_not_a_failure_classification():
    # zero exit, no stdout, flagged by the caller as empty_success — distinct
    # from an actual error, and must not require a nonzero exit code.
    assert classify_error(exit_code=0, stdout="", stderr="", empty_success=True) == ErrorType.EMPTY_RESULT


def test_unrecognized_failure_returns_none_not_a_guess():
    # v1's table is deliberately small — an unmatched failure shape should not
    # be force-fit into one of the four known types.
    assert classify_error(exit_code=1, stdout="", stderr="some unrelated internal error") is None


def test_strategy_order_is_fixed_not_reordered():
    strategies = strategies_for(ErrorType.TIMEOUT)
    assert [s.action for s in strategies] == [
        RecoveryAction.RETRY_WITH_BACKOFF,
        RecoveryAction.RETRY_WITH_REDUCED_SCOPE,
        RecoveryAction.SWITCH_TOOL,
    ]


def test_empty_result_capped_at_one_attempt_and_requires_param_change():
    strategies = strategies_for(ErrorType.EMPTY_RESULT)
    assert len(strategies) == 1
    assert strategies[0].max_attempts == 1
    assert strategies[0].requires_param_change is True


def test_next_strategy_walks_the_fixed_order():
    assert next_strategy(ErrorType.TIMEOUT, attempt=1).action == RecoveryAction.RETRY_WITH_BACKOFF
    assert next_strategy(ErrorType.TIMEOUT, attempt=2).action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE
    assert next_strategy(ErrorType.TIMEOUT, attempt=3).action == RecoveryAction.SWITCH_TOOL
    assert next_strategy(ErrorType.TIMEOUT, attempt=4) is None


def test_negative_filter_skips_a_strategy_that_already_failed_twice():
    # Not positive history-reordering — just don't recommend the SAME first
    # strategy a third time if it already failed twice this engagement.
    result = next_strategy(ErrorType.TIMEOUT, attempt=1, already_failed_twice=True)
    assert result.action == RecoveryAction.RETRY_WITH_REDUCED_SCOPE


def test_negative_filter_on_single_strategy_type_yields_none():
    # RATE_LIMITED only has one strategy — if it already failed twice, there's
    # nothing left to recommend, and that must be an honest None, not a repeat.
    result = next_strategy(ErrorType.RATE_LIMITED, attempt=1, already_failed_twice=True)
    assert result is None
