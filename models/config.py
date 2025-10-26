from dataclasses import dataclass
from typing import Dict, Any, List
import yaml
import os

@dataclass
class WAFConfig:
    """WAF Configuration"""
    mode: str
    block_threshold: float
    max_request_size: int
    rule_engine_enabled: bool
    anomaly_engine_enabled: bool
    rate_limiting_enabled: bool
    behavioral_analysis_enabled: bool
    
    @classmethod
    def from_yaml(cls, config_path: str = "config/waf_config.yaml"):
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        waf_config = config_data['waf']
        
        return cls(
            mode=waf_config['mode'],
            block_threshold=waf_config['block_threshold'],
            max_request_size=waf_config['max_request_size'],
            rule_engine_enabled=waf_config['rule_engine']['enabled'],
            anomaly_engine_enabled=waf_config['anomaly_engine']['enabled'],
            rate_limiting_enabled=waf_config['rate_limiting']['enabled'],
            behavioral_analysis_enabled=waf_config['behavioral_analysis']['enabled']
        )
    
    def update(self, updates: Dict[str, Any]):
        """Update configuration with new values"""
        for key, value in updates.items():
            if hasattr(self, key):
                setattr(self, key, value)