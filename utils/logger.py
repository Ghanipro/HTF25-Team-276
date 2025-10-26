import logging
import logging.handlers
import os
from typing import Optional

class WAFLogger:
    """Custom logger for WAF"""
    
    def __init__(self, log_file: str = "waf.log", level: str = "INFO"):
        self.logger = logging.getLogger("WAF")
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with rotation
        if log_file:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=104857600, backupCount=5  # 100MB per file, 5 backups
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def info(self, message: str, *args):
        self.logger.info(message, *args)
    
    def warning(self, message: str, *args):
        self.logger.warning(message, *args)
    
    def error(self, message: str, *args):
        self.logger.error(message, *args)
    
    def debug(self, message: str, *args):
        self.logger.debug(message, *args)