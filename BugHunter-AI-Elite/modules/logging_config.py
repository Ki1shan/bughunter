import logging
import json
from datetime import datetime


def setup_logger(name="BugHunter", level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)
    
    return logger


logger = setup_logger()