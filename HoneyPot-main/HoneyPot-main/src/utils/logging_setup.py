"""Centralized logging configuration for the honeypot application."""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(log_file: str, level: str = "INFO") -> logging.Logger:
    """Configure and return the root application logger.

    Logs go both to stdout (for `docker logs` / systemd journal) and to a
    rotating file so long-running deployments don't fill the disk.
    """
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)

    logger = logging.getLogger("honeypot")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    if logger.handlers:
        return logger  # already configured (e.g. re-imported)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    file_handler = RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger
