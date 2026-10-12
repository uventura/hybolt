from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from hybolt.logger.logger import execution_logger
from hybolt.utils import decorators
from hybolt.utils.debug import set_debugging
from hybolt.utils.decorators import _graph_file_name, timeit


def test_timeit_creates_graph_in_execution_log_directory(tmp_path):
    set_debugging(True)
    original_log_file = execution_logger.log_file
    execution_logger.log_file = str(tmp_path / "execution.log")

    try:

        @timeit(runs=3)
        def decorated_sum():
            return sum(range(10))

        result = decorated_sum()

        graph_path = Path(tmp_path) / _graph_file_name(decorated_sum)

        assert result == 45
        assert graph_path.exists()
        assert graph_path.stat().st_size > 0
    finally:
        execution_logger.log_file = original_log_file


def test_timeit_accumulates_average_per_function_call(monkeypatch):
    set_debugging(True)
    captured_average_times = []
    perf_counter_values = iter([0.0, 1.0, 2.0, 3.0, 10.0, 12.0, 20.0, 22.0])

    def fake_perf_counter():
        return next(perf_counter_values)

    def fake_save_timeit_graph(func, average_times):
        captured_average_times.append((func.__name__, list(average_times)))

    monkeypatch.setattr(decorators.time, "perf_counter", fake_perf_counter)
    monkeypatch.setattr(decorators, "_save_timeit_graph", fake_save_timeit_graph)

    @timeit(runs=2)
    def decorated_sum():
        return sum(range(5))

    assert decorated_sum() == 10
    assert decorated_sum() == 10
    assert captured_average_times == [
        (
            "decorated_sum",
            [
                1.0,
            ],
        ),
        ("decorated_sum", [1.0, 2.0]),
    ]


def test_timeit_skips_instrumentation_when_debugging_is_disabled(monkeypatch):
    graph_calls = []
    monkeypatch.setattr(
        decorators, "_save_timeit_graph", lambda *args: graph_calls.append(args)
    )

    @timeit()
    def decorated_sum():
        return sum(range(5))

    assert decorated_sum() == 10
    assert graph_calls == []


def test_timeit_records_parallel_calls_with_consistent_graph_data(monkeypatch):
    set_debugging(True)
    recorded_lengths = []

    def record_graph(_, average_times):
        recorded_lengths.append(len(average_times))

    monkeypatch.setattr(decorators, "_save_timeit_graph", record_graph)

    @timeit()
    def decorated_identity(value):
        return value

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert list(executor.map(decorated_identity, range(8))) == list(range(8))

    assert sorted(recorded_lengths) == list(range(1, 9))
