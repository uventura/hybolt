from hybolt.logger.basic_logger import BasicLogger

import logging
import os

_EXECUTION_LOG_NAME = "hybolt_execution"
_EXECUTION_LOG_FILE = "logs/execution.log"
_EXECUTION_LOG_LEVEL = [logging.INFO, logging.DEBUG]


class ExecutionLogger(BasicLogger):
    def __init__(self):
        super().__init__(
            name=_EXECUTION_LOG_NAME,
            log_file=_EXECUTION_LOG_FILE,
            level=_EXECUTION_LOG_LEVEL,
        )

    def set_log_directory(self, log_directory: str) -> None:
        self.set_log_file(os.path.join(log_directory, os.path.basename(_EXECUTION_LOG_FILE)))
