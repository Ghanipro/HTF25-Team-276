import re
from typing import Dict, Any, List, Tuple
from ..models.request import WAFRequest

class RuleEngine:
    """Rule-based detection engine"""
    
    def __init__(self, rules_config: Dict[str, Any]):
        self.rules = self._compile_rules(rules_config)
        self.rule_count = len(self.rules)
    
    def _compile_rules(self, rules_config: Dict[str, Any]) -> List[Tuple]:
        """Compile rules from configuration"""
        compiled_rules = []
        
        for rule_type, rule_data in rules_config['rules'].items():
            if not rule_data.get('enabled', True):
                continue
                
            for pattern in rule_data['patterns']:
                compiled_rules.append((
                    re.compile(pattern, re.IGNORECASE),
                    rule_type,
                    rule_data.get('severity', 0.7)
                ))
        
        return compiled_rules
    
    def analyze(self, waf_request: WAFRequest) -> Dict[str, Any]:
        """Analyze request against security rules"""
        threats_detected = []
        max_threat_level = 0.0
        
        for pattern, rule_type, severity in self.rules:
            if self._check_pattern(waf_request, pattern):
                threat_description = f"{rule_type}: {pattern.pattern[:50]}..."
                threats_detected.append(threat_description)
                max_threat_level = max(max_threat_level, severity)
        
        return {
            'threats_detected': threats_detected,
            'threat_level': max_threat_level,
            'rules_checked': self.rule_count
        }
    
    def _check_pattern(self, waf_request: WAFRequest, pattern) -> bool:
        """Check if pattern matches any request component"""
        components = [
            waf_request.url,
            waf_request.path,
            str(waf_request.query_params),
            str(waf_request.headers),
            waf_request.body,
            waf_request.user_agent
        ]
        
        for component in components:
            if pattern.search(component):
                return True
        return False
    
    def add_rule(self, pattern: str, rule_type: str, severity: float = 0.7):
        """Add custom rule at runtime"""
        compiled_pattern = re.compile(pattern, re.IGNORECASE)
        self.rules.append((compiled_pattern, rule_type, severity))
        self.rule_count += 1