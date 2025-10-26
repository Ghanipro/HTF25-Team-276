import yaml
import re
from typing import Dict, Any

def load_rules_from_yaml(rules_file: str) -> Dict[str, Any]:
    """Load security rules from YAML file"""
    try:
        with open(rules_file, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Rules file not found: {rules_file}")
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in rules file: {e}")

def sanitize_input(input_string: str) -> str:
    """Basic input sanitization"""
    if not input_string:
        return ""
    
    # Remove null bytes
    sanitized = input_string.replace('\0', '')
    
    # Limit length
    if len(sanitized) > 10000:
        sanitized = sanitized[:10000]
    
    return sanitized

def is_valid_ip(ip_address: str) -> bool:
    """Validate IP address format"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip_address):
        return False
    
    parts = ip_address.split('.')
    for part in parts:
        if not 0 <= int(part) <= 255:
            return False
    
    return True