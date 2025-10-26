from typing import Dict, Any, List, Optional
from datetime import datetime
import threading

from ..models.request import WAFRequest, WAFResponse
from ..models.config import WAFConfig
from ..engines.rule_engine import RuleEngine
from ..engines.anomaly_engine import AnomalyEngine
from ..engines.rate_limiter import RateLimiter
from ..engines.behavioral_analyzer import BehavioralAnalyzer
from ..utils.logger import WAFLogger
from ..utils.helpers import load_rules_from_yaml

class WebApplicationFirewall:
    """
    Main WAF class that orchestrates all security engines
    """
    
    def __init__(self, config: WAFConfig):
        self.config = config
        self.logger = WAFLogger()
        self._initialize_engines()
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'rule_blocks': 0,
            'anomaly_blocks': 0,
            'rate_limit_blocks': 0,
            'threats_detected': {}
        }
        self._lock = threading.Lock()
        
        self.logger.info("WAF initialized in %s mode", config.mode)
    
    def _initialize_engines(self):
        """Initialize all security engines"""
        # Load rules
        rules = load_rules_from_yaml("config/default_rules.yaml")
        
        # Initialize engines
        self.rule_engine = RuleEngine(rules) if self.config.rule_engine_enabled else None
        self.anomaly_engine = AnomalyEngine() if self.config.anomaly_engine_enabled else None
        self.rate_limiter = RateLimiter() if self.config.rate_limiting_enabled else None
        self.behavioral_analyzer = BehavioralAnalyzer() if self.config.behavioral_analysis_enabled else None
        
        if self.anomaly_engine and not self.anomaly_engine.is_trained:
            self.logger.warning("Anomaly engine is not trained. Consider training with normal traffic.")
    
    def process_request(self, waf_request: WAFRequest) -> WAFResponse:
        """
        Process HTTP request through all security engines
        """
        with self._lock:
            self.stats['total_requests'] += 1
        
        # Early blocking for monitoring mode
        if self.config.mode == "monitoring":
            return WAFResponse(
                blocked=False,
                threat_level=0.0,
                reason="Monitoring mode - no blocking",
                request_id=waf_request.request_id,
                timestamp=datetime.now()
            )
        
        # Rate limiting (first line of defense)
        if self.rate_limiter:
            rate_limit_result = self.rate_limiter.check_rate_limit(waf_request.client_ip)
            if rate_limit_result['limited']:
                with self._lock:
                    self.stats['blocked_requests'] += 1
                    self.stats['rate_limit_blocks'] += 1
                
                self.logger.warning("Rate limit exceeded for IP: %s", waf_request.client_ip)
                return WAFResponse(
                    blocked=True,
                    threat_level=1.0,
                    reason=f"Rate limit exceeded: {rate_limit_result['reason']}",
                    request_id=waf_request.request_id,
                    timestamp=datetime.now()
                )
        
        # Rule-based detection
        rule_threat_level = 0.0
        rule_threats = []
        if self.rule_engine:
            rule_result = self.rule_engine.analyze(waf_request)
            rule_threat_level = rule_result['threat_level']
            rule_threats = rule_result['threats_detected']
            
            # Immediate block for high-confidence rule matches
            if rule_threat_level > 0.9:
                with self._lock:
                    self.stats['blocked_requests'] += 1
                    self.stats['rule_blocks'] += 1
                    self._update_threat_stats(rule_threats)
                
                return WAFResponse(
                    blocked=True,
                    threat_level=rule_threat_level,
                    reason=f"Rule-based detection: {', '.join(rule_threats)}",
                    request_id=waf_request.request_id,
                    timestamp=datetime.now(),
                    details={'rule_threats': rule_threats}
                )
        
        # Anomaly detection
        anomaly_threat_level = 0.0
        if self.anomaly_engine and self.anomaly_engine.is_trained:
            anomaly_result = self.anomaly_engine.analyze(waf_request)
            anomaly_threat_level = anomaly_result['threat_level']
        
        # Behavioral analysis
        behavioral_threat_level = 0.0
        behavioral_anomalies = []
        if self.behavioral_analyzer:
            behavioral_result = self.behavioral_analyzer.analyze(waf_request)
            behavioral_threat_level = behavioral_result['threat_level']
            behavioral_anomalies = behavioral_result['anomalies']
        
        # Combined threat assessment
        combined_threat = self._calculate_combined_threat(
            rule_threat_level, 
            anomaly_threat_level, 
            behavioral_threat_level
        )
        
        # Decision making
        blocked = combined_threat > self.config.block_threshold
        reason = self._generate_block_reason(
            rule_threats, 
            anomaly_threat_level, 
            behavioral_anomalies,
            combined_threat
        )
        
        if blocked:
            with self._lock:
                self.stats['blocked_requests'] += 1
                if anomaly_threat_level > rule_threat_level:
                    self.stats['anomaly_blocks'] += 1
                else:
                    self.stats['rule_blocks'] += 1
                self._update_threat_stats(rule_threats)
        
        return WAFResponse(
            blocked=blocked,
            threat_level=combined_threat,
            reason=reason,
            request_id=waf_request.request_id,
            timestamp=datetime.now(),
            details={
                'rule_threats': rule_threats,
                'anomaly_threat': anomaly_threat_level,
                'behavioral_anomalies': behavioral_anomalies
            }
        )
    
    def _calculate_combined_threat(self, rule_threat: float, anomaly_threat: float, behavioral_threat: float) -> float:
        """Calculate combined threat score with weighted averaging"""
        weights = {
            'rule': 0.6,      # Rules are most reliable
            'anomaly': 0.3,   # ML anomalies
            'behavioral': 0.1  # Behavioral patterns
        }
        
        combined = (
            rule_threat * weights['rule'] +
            anomaly_threat * weights['anomaly'] +
            behavioral_threat * weights['behavioral']
        )
        
        return min(1.0, combined)
    
    def _generate_block_reason(self, rule_threats: List[str], anomaly_threat: float, 
                             behavioral_anomalies: List[str], combined_threat: float) -> str:
        """Generate human-readable block reason"""
        reasons = []
        
        if rule_threats:
            reasons.append(f"Rule violations: {', '.join(rule_threats[:3])}")
        
        if anomaly_threat > 0.6:
            reasons.append("Anomalous behavior detected")
        
        if behavioral_anomalies:
            reasons.append(f"Behavioral anomalies: {', '.join(behavioral_anomalies[:2])}")
        
        if not reasons:
            return f"Combined threat score exceeded threshold: {combined_threat:.2f}"
        
        return "; ".join(reasons)
    
    def _update_threat_stats(self, threats: List[str]):
        """Update threat detection statistics"""
        for threat in threats:
            threat_type = threat.split(':')[0] if ':' in threat else 'unknown'
            self.stats['threats_detected'][threat_type] = self.stats['threats_detected'].get(threat_type, 0) + 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get WAF statistics"""
        with self._lock:
            stats = self.stats.copy()
            stats['block_rate'] = (stats['blocked_requests'] / stats['total_requests']) if stats['total_requests'] > 0 else 0
            return stats
    
    def update_config(self, new_config: WAFConfig):
        """Update WAF configuration"""
        with self._lock:
            self.config = new_config
        self.logger.info("WAF configuration updated")
    
    def train_anomaly_model(self, normal_requests: List[WAFRequest]):
        """Train anomaly detection model"""
        if self.anomaly_engine:
            self.anomaly_engine.train(normal_requests)
            self.logger.info("Anomaly detection model trained with %d samples", len(normal_requests))
    
    def add_custom_rule(self, pattern: str, rule_type: str, severity: float = 0.7):
        """Add custom rule at runtime"""
        if self.rule_engine:
            self.rule_engine.add_rule(pattern, rule_type, severity)
            self.logger.info("Custom rule added: %s", rule_type)