import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx
from .config import settings

class ThreatIntelligence:
    def __init__(self):
        self._load_intel_data()
        
    def _load_intel_data(self):
        """Load threat intelligence data from various sources"""
        self.known_patterns: Dict[str, List[Dict]] = {
            # Financial scams
            "get_rich_patterns": [
                r"(?:get|earn|make)\s+(?:quick|easy|fast)\s+(?:money|cash|dollars)",
                r"(?:million|[0-9,.]+k?)\s*(?:dollars|usd|€|£|\$)",
                r"(?:double|triple|[0-9]+x)\s+(?:your\s+)?(?:money|investment)",
                r"(?:bitcoin|crypto|ethereum|binance|wallet)\s+(?:investment|trading|mining)",
            ],
            # Login/credential harvesting
            "credential_patterns": [
                r"(?:login|sign\s*in|verify)\s+(?:with|using)\s+(?:your|bank|card)",
                r"(?:confirm|verify|validate)\s+(?:your|account|identity|card)",
                r"(?:debit|credit)\s*card\s*(?:details|info|number)",
                r"(?:username|password|login)\s+(?:and|&|with)\s+(?:password|pin)",
            ],
            # Urgency/pressure tactics
            "urgency_patterns": [
                r"(?:limited|exclusive|special)\s+(?:time|offer|deal)",
                r"(?:only|just|last)\s+(?:[0-9]+)\s+(?:spots|places|slots|left)",
                r"(?:expires?|ending|closing)\s+(?:soon|today|tomorrow)",
                r"(?:urgent|immediate|asap|now)\s+(?:action|response|reply)",
            ],
            # Social engineering
            "social_patterns": [
                r"(?:pretend|act\s+as|claim\s+to\s+be)\s+(?:admin|support|service)",
                r"(?:trust|believe|guarantee)\s+(?:me|us|this)",
                r"(?:no\s+risk|100%\s+safe|completely\s+secure)",
                r"(?:keep\s+this|don't\s+tell|secret)\s+(?:private|confidential)",
            ]
        }
        
        # Load external threat intelligence
        self._load_external_intel()
        
    def _load_external_intel(self):
        """Load threat intelligence from external sources"""
        # Path to cached intel data
        cache_dir = Path(__file__).parent / "data"
        cache_dir.mkdir(exist_ok=True)
        cache_file = cache_dir / "threat_intel_cache.json"
        
        try:
            if cache_file.exists() and (time.time() - cache_file.stat().st_mtime < 86400):  # 24h cache
                with open(cache_file) as f:
                    self.external_intel = json.load(f)
            else:
                self.external_intel = self._fetch_external_intel()
                with open(cache_file, 'w') as f:
                    json.dump(self.external_intel, f)
        except Exception as e:
            print(f"Error loading external intel: {e}")
            self.external_intel = {}
            
    def _fetch_external_intel(self) -> Dict:
        """Fetch threat intelligence from external sources"""
        intel = {
            "suspicious_domains": set(),
            "phishing_patterns": set(),
            "scam_indicators": set()
        }
        
        # Add known phishing domains
        try:
            with httpx.Client() as client:
                # PhishTank
                if hasattr(settings, 'phishtank_api_key') and settings.phishtank_api_key:
                    r = client.get("http://data.phishtank.com/data/online-valid.json",
                                headers={"Api-Key": settings.phishtank_api_key})
                    data = r.json()
                    for entry in data:
                        intel["suspicious_domains"].add(urlparse(entry["url"]).netloc)
                        
                # OpenPhish
                r = client.get("https://openphish.com/feed.txt")
                for line in r.text.splitlines():
                    if line.strip():
                        intel["suspicious_domains"].add(urlparse(line.strip()).netloc)
        except Exception as e:
            print(f"Error fetching external intel: {e}")
            
        return {k: list(v) for k, v in intel.items()}  # Convert sets to lists for JSON serialization
        
    def analyze_text(self, text: str) -> Dict:
        """
        Analyze text using various threat intelligence sources
        Returns dict with matched patterns and risk scores
        """
        results = {
            "matches": [],
            "risk_factors": {
                "get_rich_risk": 0.0,
                "credential_risk": 0.0,
                "urgency_risk": 0.0,
                "social_risk": 0.0,
                "known_threat_risk": 0.0
            }
        }
        
        # Check each pattern category
        for category, patterns in self.known_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    results["matches"].append({
                        "pattern": pattern,
                        "matched_text": match.group(0),
                        "category": category,
                        "start": match.start(),
                        "end": match.end()
                    })
                    
                    # Update risk scores
                    if "get_rich" in category:
                        results["risk_factors"]["get_rich_risk"] += 0.3
                    elif "credential" in category:
                        results["risk_factors"]["credential_risk"] += 0.4
                    elif "urgency" in category:
                        results["risk_factors"]["urgency_risk"] += 0.2
                    elif "social" in category:
                        results["risk_factors"]["social_risk"] += 0.25
        
        # Check for known malicious domains
        urls = re.finditer(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
        for url in urls:
            domain = urlparse(url.group()).netloc
            if domain in self.external_intel.get("suspicious_domains", []):
                results["matches"].append({
                    "pattern": "known_malicious_domain",
                    "matched_text": domain,
                    "category": "known_threat",
                    "start": url.start(),
                    "end": url.end()
                })
                results["risk_factors"]["known_threat_risk"] += 0.5
                
        # Calculate final risk scores
        for key in results["risk_factors"]:
            results["risk_factors"][key] = min(1.0, results["risk_factors"][key])
            
        return results

# Initialize global instance
threat_intel = ThreatIntelligence()
