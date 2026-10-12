from hyboat.logger.basic_logger import BasicLogger

import logging

_EXECUTION_LOG_NAME = "hyboat_execution"
_EXECUTION_LOG_FILE = "logs/execution.log"
_EXECUTION_LOG_LEVEL = [logging.INFO, logging.DEBUG]


class ExecutionLogger(BasicLogger):
    def __init__(self):
        super().__init__(
            name=_EXECUTION_LOG_NAME,
            log_file=_EXECUTION_LOG_FILE,
            level=_EXECUTION_LOG_LEVEL,
        )
