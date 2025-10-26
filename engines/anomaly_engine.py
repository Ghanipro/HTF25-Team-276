import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
from typing import Dict, Any, List
from ..models.request import WAFRequest

class AnomalyEngine:
    """Machine Learning Anomaly Detection Engine"""
    
    def __init__(self, model_file: str = "models/anomaly_model.pkl"):
        self.model_file = model_file
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = [
            'url_length', 'param_count', 'sql_patterns', 'xss_patterns', 
            'path_patterns', 'entropy', 'special_chars', 'content_length'
        ]
        
        # Try to load pre-trained model
        self._load_model()
    
    def extract_features(self, waf_request: WAFRequest) -> np.ndarray:
        """Extract features from request for ML analysis"""
        features = []
        
        # Structural features
        features.append(len(waf_request.url))
        features.append(len(waf_request.query_params))
        features.append(waf_request.content_length)
        
        # Security pattern features
        features.append(self._count_sql_patterns(waf_request))
        features.append(self._count_xss_patterns(waf_request))
        features.append(self._count_path_patterns(waf_request))
        
        # Behavioral features
        features.append(self._calculate_entropy(str(waf_request.to_dict())))
        features.append(self._count_special_chars(waf_request))
        
        return np.array(features).reshape(1, -1)
    
    def _count_sql_patterns(self, waf_request: WAFRequest) -> int:
        patterns = [r"union", r"select", r"insert", r"delete", r"drop", r"exec"]
        return self._count_patterns(waf_request, patterns)
    
    def _count_xss_patterns(self, waf_request: WAFRequest) -> int:
        patterns = [r"<script", r"javascript:", r"onload", r"onerror", r"alert\("]
        return self._count_patterns(waf_request, patterns)
    
    def _count_path_patterns(self, waf_request: WAFRequest) -> int:
        patterns = [r"\.\./", r"\.\.\\", r"etc/passwd", r"win.ini"]
        return self._count_patterns(waf_request, patterns)
    
    def _count_patterns(self, waf_request: WAFRequest, patterns: List[str]) -> int:
        count = 0
        components = [waf_request.url, str(waf_request.query_params), waf_request.body]
        
        for pattern in patterns:
            for component in components:
                count += len(re.findall(pattern, component, re.IGNORECASE))
        return count
    
    def _calculate_entropy(self, text: str) -> float:
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy
    
    def _count_special_chars(self, waf_request: WAFRequest) -> int:
        special_chars = r"[<>\"'%;&()*+$!|]"
        text = waf_request.url + waf_request.body
        return len(re.findall(special_chars, text))
    
    def analyze(self, waf_request: WAFRequest) -> Dict[str, Any]:
        """Analyze request using anomaly detection"""
        if not self.is_trained:
            return {'threat_level': 0.0, 'anomaly_score': 0.0, 'model_trained': False}
        
        try:
            features = self.extract_features(waf_request)
            scaled_features = self.scaler.transform(features)
            
            anomaly_score = self.model.decision_function(scaled_features)[0]
            threat_level = max(0, (1 - anomaly_score) / 2)
            
            return {
                'threat_level': threat_level,
                'anomaly_score': anomaly_score,
                'model_trained': True
            }
        except Exception as e:
            return {'threat_level': 0.0, 'anomaly_score': 0.0, 'model_trained': False, 'error': str(e)}
    
    def train(self, normal_requests: List[WAFRequest]):
        """Train anomaly detection model"""
        if len(normal_requests) < 10:
            raise ValueError("Need at least 10 samples for training")
        
        features_list = []
        for req in normal_requests:
            features = self.extract_features(req)
            features_list.append(features.flatten())
        
        X = np.array(features_list)
        X_scaled = self.scaler.fit_transform(X)
        
        self.model.fit(X_scaled)
        self.is_trained = True
        
        # Save trained model
        self._save_model()
    
    def _save_model(self):
        """Save trained model to file"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained
        }
        
        with open(self.model_file, 'wb') as f:
            pickle.dump(model_data, f)
    
    def _load_model(self):
        """Load pre-trained model from file"""
        try:
            with open(self.model_file, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.is_trained = model_data['is_trained']
        except (FileNotFoundError, EOFError, KeyError):
            self.is_trained = False