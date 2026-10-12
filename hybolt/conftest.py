import pytest

from hybolt.utils.debug import set_debugging


@pytest.fixture(autouse=True)
def disable_debug_in_tests():
    set_debugging(False)
    yield
    set_debugging(False)
