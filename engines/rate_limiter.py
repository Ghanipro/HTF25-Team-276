from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, Any

class RateLimiter:
    """Rate limiting engine"""
    
    def __init__(self, requests_per_minute: int = 100, burst_limit: int = 50):
        self.requests_per_minute = requests_per_minute
        self.burst_limit = burst_limit
        self.requests = defaultdict(deque)
    
    def check_rate_limit(self, client_ip: str) -> Dict[str, Any]:
        """Check if client has exceeded rate limits"""
        now = datetime.now()
        window_start = now - timedelta(minutes=1)
        
        # Clean old requests
        client_requests = self.requests[client_ip]
        while client_requests and client_requests[0] < window_start:
            client_requests.popleft()
        
        # Check limits
        request_count = len(client_requests)
        
        if request_count >= self.requests_per_minute:
            return {
                'limited': True,
                'reason': f"Rate limit exceeded ({request_count} requests in last minute)"
            }
        
        if request_count >= self.burst_limit:
            return {
                'limited': True,
                'reason': f"Burst limit exceeded ({request_count} requests)"
            }
        
        # Add current request
        client_requests.append(now)
        
        return {
            'limited': False,
            'current_count': request_count + 1,
            'limit': self.requests_per_minute
        }