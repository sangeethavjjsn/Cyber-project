from app import db
from datetime import datetime
import json

class AnalysisReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)  # 'php' or 'js'
    file_size = db.Column(db.Integer, nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    analysis_time = db.Column(db.DateTime, default=datetime.utcnow)
    security_score = db.Column(db.Float, nullable=False, default=0.0)
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    vulnerabilities_json = db.Column(db.Text)  # Store JSON data as text
    
    def get_vulnerabilities(self):
        """Get vulnerabilities as Python dict"""
        if self.vulnerabilities_json:
            return json.loads(self.vulnerabilities_json)
        return []
    
    def set_vulnerabilities(self, vulnerabilities):
        """Set vulnerabilities from Python dict"""
        self.vulnerabilities_json = json.dumps(vulnerabilities, indent=2)
