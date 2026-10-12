from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from hybolt.logger.logger import execution_logger
from hybolt.utils import decorators
from hybolt.utils.debug import set_debugging
from hybolt.utils.decorators import (
    _graph_file_name,
    start_record_timeit,
    stop_record_timeit,
)


def test_stop_record_timeit_creates_graph_in_execution_log_directory(tmp_path):
    set_debugging(True)
    original_log_file = execution_logger.log_file
    execution_logger.log_file = str(tmp_path / "execution.log")

    try:

        @start_record_timeit(runs=3)
        def decorated_sum():
            return sum(range(10))

        @stop_record_timeit
        def finish_recording():
            return None

        result = decorated_sum()
        finish_recording()

        graph_path = Path(tmp_path) / _graph_file_name(decorated_sum)

        assert result == 45
        assert graph_path.exists()
        assert graph_path.stat().st_size > 0
    finally:
        execution_logger.log_file = original_log_file


def test_stop_record_timeit_plots_accumulated_average_times(monkeypatch):
    set_debugging(True)
    captured_average_times = []
    perf_counter_values = iter([0.0, 1.0, 2.0, 3.0, 10.0, 12.0, 20.0, 22.0])

    def fake_perf_counter():
        return next(perf_counter_values)

    def fake_save_timeit_graph(func, average_times):
        captured_average_times.append((func.__name__, list(average_times)))

    monkeypatch.setattr(decorators.time, "perf_counter", fake_perf_counter)
    monkeypatch.setattr(decorators, "_save_timeit_graph", fake_save_timeit_graph)

    @start_record_timeit(runs=2)
    def decorated_sum():
        return sum(range(5))

    @stop_record_timeit
    def finish_recording():
        return None

    assert decorated_sum() == 10
    assert decorated_sum() == 10
    finish_recording()
    assert captured_average_times == [
        (
            "decorated_sum",
            [1.0, 2.0],
        )
    ]


def test_start_record_timeit_skips_instrumentation_when_debugging_is_disabled(
    monkeypatch,
):
    graph_calls = []
    monkeypatch.setattr(
        decorators, "_save_timeit_graph", lambda *args: graph_calls.append(args)
    )

    @start_record_timeit()
    def decorated_sum():
        return sum(range(5))

    @stop_record_timeit
    def finish_recording():
        return None

    assert decorated_sum() == 10
    finish_recording()
    assert graph_calls == []


def test_stop_record_timeit_plots_parallel_calls_with_consistent_graph_data(
    monkeypatch,
):
    set_debugging(True)
    recorded_lengths = []

    def record_graph(_, average_times):
        recorded_lengths.append(len(average_times))

    monkeypatch.setattr(decorators, "_save_timeit_graph", record_graph)

    @start_record_timeit()
    def decorated_identity(value):
        return value

    @stop_record_timeit
    def finish_recording():
        return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert list(executor.map(decorated_identity, range(8))) == list(range(8))

    finish_recording()

    assert recorded_lengths == [8]
