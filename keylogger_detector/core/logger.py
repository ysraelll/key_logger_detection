import logging
import sys

def setup_logger(name: str = "keylogger_detector", level: int = logging.INFO):
    """
    Configures the logger for the application.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        # Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)

        # Formatter: TIMESTAMP - LEVEL - MESSAGE
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
        console_handler.setFormatter(formatter)

        logger.addHandler(console_handler)

    return logger

logger = setup_logger()
