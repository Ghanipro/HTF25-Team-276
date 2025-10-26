from flask import request, g
from typing import Callable, Optional
from ..core.waf_core import WebApplicationFirewall
from ..models.request import WAFRequest
from ..models.config import WAFConfig

class FlaskWAF:
    """Flask integration for WAF"""
    
    def __init__(self, app=None, config_path: str = "config/waf_config.yaml"):
        self.app = app
        self.config = WAFConfig.from_yaml(config_path)
        self.waf = WebApplicationFirewall(self.config)
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Flask application with WAF"""
        self.app = app
        
        @app.before_request
        def process_request():
            """Process each request through WAF"""
            waf_request = self._create_waf_request()
            waf_response = self.waf.process_request(waf_request)
            
            # Store in Flask context for later use
            g.waf_request = waf_request
            g.waf_response = waf_response
            
            # Block request if needed
            if waf_response.blocked:
                return self._create_block_response(waf_response)
    
    def _create_waf_request(self) -> WAFRequest:
        """Create WAFRequest from Flask request"""
        from datetime import datetime
        
        return WAFRequest(
            client_ip=request.remote_addr,
            method=request.method,
            url=request.url,
            path=request.path,
            headers=dict(request.headers),
            query_params=dict(request.args),
            body=request.get_data(as_text=True),
            cookies=dict(request.cookies),
            timestamp=datetime.now(),
            user_agent=request.headers.get('User-Agent', ''),
            content_length=request.content_length or 0,
            content_type=request.content_type or ''
        )
    
    def _create_block_response(self, waf_response):
        """Create Flask response for blocked requests"""
        from flask import jsonify
        
        response_data = {
            'error': 'Request blocked by WAF',
            'reason': waf_response.reason,
            'threat_level': waf_response.threat_level,
            'request_id': waf_response.request_id
        }
        
        return jsonify(response_data), 403
    
    def get_statistics(self):
        """Get WAF statistics"""
        return self.waf.get_statistics()
    
    def add_custom_rule(self, pattern: str, rule_type: str, severity: float = 0.7):
        """Add custom security rule"""
        self.waf.add_custom_rule(pattern, rule_type, severity)