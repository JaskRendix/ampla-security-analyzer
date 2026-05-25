import logging


def get_logger(name: str | None = None) -> logging.Logger:
    logger = logging.getLogger(name or "ampla_security")

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if logger.level == logging.NOTSET:
        logger.setLevel(logging.INFO)

    return logger


def configure_logging(level: int = logging.INFO) -> logging.Logger:
    logger = get_logger()
    logger.setLevel(level)
    return logger
