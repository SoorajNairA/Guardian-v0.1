import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx
from .logging_client import logger
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
        try:
            cache_dir.mkdir(exist_ok=True)
            cache_file = cache_dir / "threat_intel_cache.json"
            
            cache_ttl = getattr(settings, 'threat_intel_cache_ttl', 86400)  # 24h default
            
            try:
                if cache_file.exists() and (time.time() - cache_file.stat().st_mtime < cache_ttl):
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        self.external_intel = json.load(f)
                else:
                    self.external_intel = self._fetch_external_intel()
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        json.dump(self.external_intel, f, indent=2)
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error accessing threat intel cache: {str(e)}")
                self.external_intel = self._fetch_external_intel()
        except Exception as e:
            logger.error(f"Error loading external intel: {str(e)}")
            self.external_intel = {
                "suspicious_domains": [],
                "phishing_patterns": [],
                "scam_indicators": []
            }
            
    def _fetch_external_intel(self) -> Dict:
        """
        Fetch threat intelligence from external sources.
        
        Returns:
            Dictionary containing suspicious domains, patterns, and indicators
        """
        intel = {
            "suspicious_domains": set(),
            "phishing_patterns": set(),
            "scam_indicators": set(),
            "last_updated": time.time()
        }
        
        timeout = getattr(settings, 'threat_intel_timeout', 30)
        
        # Add known phishing domains
        try:
            with httpx.Client(timeout=timeout) as client:
                # PhishTank
                if getattr(settings, 'phishtank_api_key', None):
                    try:
                        r = client.get(
                            "http://data.phishtank.com/data/online-valid.json",
                            headers={"Api-Key": settings.phishtank_api_key}
                        )
                        r.raise_for_status()
                        data = r.json()
                        for entry in data:
                            try:
                                domain = urlparse(entry["url"]).netloc
                                if domain:
                                    intel["suspicious_domains"].add(domain)
                            except Exception as e:
                                logger.warning(f"Error parsing PhishTank URL: {str(e)}")
                                
                    except Exception as e:
                        logger.error(f"Error fetching from PhishTank: {str(e)}")
                        
                # OpenPhish
                try:
                    r = client.get("https://openphish.com/feed.txt")
                    r.raise_for_status()
                    for line in r.text.splitlines():
                        try:
                            if line.strip():
                                domain = urlparse(line.strip()).netloc
                                if domain:
                                    intel["suspicious_domains"].add(domain)
                        except Exception as e:
                            logger.warning(f"Error parsing OpenPhish URL: {str(e)}")
                            
                except Exception as e:
                    logger.error(f"Error fetching from OpenPhish: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error fetching external intel: {str(e)}")
            
        # Convert sets to lists for JSON serialization
        return {
            "suspicious_domains": sorted(list(intel["suspicious_domains"])),
            "phishing_patterns": sorted(list(intel["phishing_patterns"])),
            "scam_indicators": sorted(list(intel["scam_indicators"])),
            "last_updated": intel["last_updated"]
        }
        
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
