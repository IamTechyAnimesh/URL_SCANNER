import requests
import base64
from urllib.parse import urlparse
import google.generativeai as genai

# API Keys
VIRUSTOTAL_API_KEY = "your_actual_key_here"
GEMINI_API_KEY = "your_actual_key_here"
genai.configure(api_key=GEMINI_API_KEY)

class VirusTotalScanner:
    # Scan URLs using VirusTotal API
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": api_key}

    def scan_url(self, url):
        try:
            scan_result = self.get_url_report(url)
            if scan_result:
                return scan_result
            return self.submit_url_for_scanning(url)
        except Exception as e:
            return {"error": str(e), "safe": None}

    def get_url_report(self, url):
        # Get existing scan report for URL
        try:
            url_id = self._encode_url(url)
            endpoint = f"{self.base_url}/urls/{url_id}"
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)
                
                is_safe = malicious == 0 and suspicious == 0
                
                return {
                    "source": "VirusTotal",
                    "url": url,
                    "safe": is_safe,
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": harmless,
                    "total_scans": malicious + suspicious + undetected + harmless
                }
            
            return None
        except Exception as e:
            return {"error": str(e), "source": "VirusTotal"}

    def submit_url_for_scanning(self, url):
        # Submit new URL for scanning
        try:
            endpoint = f"{self.base_url}/urls"
            data = {"url": url}
            response = requests.post(endpoint, headers=self.headers, data=data, timeout=10)
            
            if response.status_code == 200:
                return {
                    "source": "VirusTotal",
                    "url": url,
                    "status": "submitted",
                    "message": "URL submitted for scanning. Check again in a few moments."
                }
            
            return {"error": "Failed to submit URL", "source": "VirusTotal"}
        except Exception as e:
            return {"error": str(e), "source": "VirusTotal"}
    
    @staticmethod
    def _encode_url(url):
        """Encode URL for VirusTotal API"""
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

class GeminiAnalyzer:
    # Analyze URLs using Google Gemini AI
    def __init__(self, api_key):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.5-flash')

    def analyze_url(self, url):
        """Analyze a URL using Gemini"""
        try:
            prompt = f"""Analyze this URL for security threats in 1-2 sentences:
            
URL: {url}

Respond ONLY as:
SAFE: Yes/No
REASON: [brief reason]"""
            
            response = self.model.generate_content(prompt)
            analysis_text = response.text.strip()
            safe = self._parse_safety(analysis_text)
            
            return {
                "source": "Gemini",
                "url": url,
                "safe": safe,
                "analysis": analysis_text
            }
        except Exception as e:
            error_msg = str(e)
            if "quota" in error_msg.lower() or "rate_limit" in error_msg.lower():
                return {
                    "source": "Gemini",
                    "url": url,
                    "skipped": True,
                    "reason": "Gemini API rate limited or unavailable",
                    "safe": None
                }
            return {
                "source": "Gemini",
                "url": url,
                "error": str(e),
                "safe": None
            }
    @staticmethod
    def _parse_safety(response_text):
        """Parse safety from response"""
        if "SAFE: Yes" in response_text or "safe: yes" in response_text.lower():
            return True
        elif "SAFE: No" in response_text or "safe: no" in response_text.lower():
            return False
        
        lower_text = response_text.lower()
        if "safe" in lower_text and any(w in lower_text for w in ["not", "danger", "threat"]):
            return False
        elif "safe" in lower_text:
            return True
        
        return None

class URLScanner:
    # Combined scanner using VirusTotal & Gemini
    def __init__(self, vt_key, gemini_key):
        self.vt_scanner = VirusTotalScanner(vt_key)
        self.gemini_analyzer = GeminiAnalyzer(gemini_key)

    def scan_url(self, url):
        # Scan URL with both services
        """Scan URL with both services"""
        if not self._is_valid_url(url):
            return {"error": "Invalid URL format", "url": url}
        print(f"\nScanning: {url}")
        print("-" * 60)
        
        results = {
            "url": url,
            "virustotal": None,
            "gemini": None,
            "final_verdict": None
        }
        print("Checking VirusTotal...")
        vt_result = self.vt_scanner.scan_url(url)
        results["virustotal"] = vt_result
        self._print_vt_result(vt_result)
        print("\nAnalyzing with Gemini...")
        gemini_result = self.gemini_analyzer.analyze_url(url)
        results["gemini"] = gemini_result
        self._print_gemini_result(gemini_result)
        results["final_verdict"] = self._determine_verdict(results)
        self._print_final_verdict(results["final_verdict"])
        self._save_to_log(results)
        
        return results
    
    def _print_vt_result(self, result):
        # Display VirusTotal scan results
        """Print VirusTotal results"""
        if "error" in result:
            print(f"   ❌ Error: {result['error']}")
        elif "status" in result:
            print(f"   ℹ️  {result['status']}: {result['message']}")
        else:
            safe = "✅ SAFE" if result["safe"] else "⚠️  THREATS DETECTED"
            print(f"   {safe}")
            if "malicious" in result:
                print(f"   - Malicious: {result['malicious']} | Suspicious: {result['suspicious']} | Total: {result['total_scans']}")
    
    def _print_chatgpt_result(self, result):
        """Print Gemini results"""
        if "skipped" in result:
            print(f"   ⏭️  Skipped: {result['reason']}")
        elif "error" in result:
            print(f"   ❌ Error: {result['error']}")
        else:
            safe = "✅ SAFE" if result["safe"] else "⚠️  NOT SAFE"
            print(f"   {safe}")
            print(f"   Analysis: {result['analysis'][:150]}")
    
    def _print_gemini_result(self, result):
        """Print Gemini results"""
        if "skipped" in result:
            print(f"   ⏭️  Skipped: {result['reason']}")
        elif "error" in result:
            print(f"   ❌ Error: {result['error']}")
        else:
            safe = "✅ SAFE" if result["safe"] else "⚠️  NOT SAFE"
            print(f"   {safe}")
            print(f"   Analysis: {result['analysis']}")
    def _print_final_verdict(self, verdict):
        """Print final verdict"""
        print("\n" + "=" * 60)
        if verdict["overall_safe"]:
            print("🟢 FINAL VERDICT: SAFE")
        else:
            print("🔴 FINAL VERDICT: NOT SAFE / SUSPICIOUS")
        print(f"Confidence: {verdict['confidence']}")
        print("=" * 60)
    def _determine_verdict(self, results):
        # Combine results from both sources
        """Determine overall safety verdict"""
        vt_result = results.get("virustotal")
        gemini_result = results.get("gemini")
        
        vt_safe = None
        gemini_safe = None
        
        if vt_result and "error" not in vt_result and "status" not in vt_result:
            vt_safe = vt_result.get("safe")
        
        if gemini_result and "error" not in gemini_result and "skipped" not in gemini_result:
            gemini_safe = gemini_result.get("safe")
        
        safe_count = sum(1 for s in [vt_safe, gemini_safe] if s is True)
        unsafe_count = sum(1 for s in [vt_safe, gemini_safe] if s is False)
        
        overall_safe = unsafe_count == 0 and safe_count > 0
        
        if vt_safe is not None and gemini_safe is not None:
            confidence = "High" if vt_safe == gemini_safe else "Medium"
        elif vt_safe is not None or gemini_safe is not None:
            confidence = "Medium (VirusTotal only)"
        else:
            confidence = "Low"
        
        return {
            "overall_safe": overall_safe,
            "confidence": confidence,
            "vt_verdict": vt_safe,
            "gemini_verdict": gemini_safe
        }
    
    def _save_to_log(self, results):
        # Save scan results to log file
        """Save results to log file"""
        try:
            with open("scan_results.log", "a") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"URL: {results['url']}\n")
                f.write(f"Verdict: {'SAFE' if results['final_verdict']['overall_safe'] else 'NOT SAFE'}\n")
                f.write(f"Confidence: {results['final_verdict']['confidence']}\n")
                f.write(f"{'='*60}\n")
        except Exception as e:
            print(f"Could not save to log: {e}")
    @staticmethod
    def _is_valid_url(url):
        """Validate URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

def print_banner():
    """Print ASCII banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║           🛡️  URL SECURITY SCANNER v1.0 🛡️               ║
    ║                                                           ║
    ║      Powered by VirusTotal & Google Gemini AI             ║
    ║                                                           ║
    ║  Scan URLs for threats, malware, and suspicious activity  ║
    ║                                                           ║
    ║               Author: IamTechyAnimesh                     ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    # Check API keys
    if VIRUSTOTAL_API_KEY == "your_virustotal_api_key_here":
        print("ERROR: Please add your VirusTotal API key to the script!")
        print("   Get it at: https://www.virustotal.com/gui/my-apikey")
        return
    
    if GEMINI_API_KEY == "your_gemini_api_key_here":
        print("ERROR: Please add your Gemini API key to the script!")
        print("   Get it at: https://makersuite.google.com/app/apikey")
        return
    scanner = URLScanner(VIRUSTOTAL_API_KEY, GEMINI_API_KEY)
    print_banner()
    
    while True:
        url = input("\nEnter a URL to scan (or 'quit'/'exit'/'q' to exit):").strip()
        
        if url.lower() in ["quit", "exit", "q"]:
            print("\n👋Goodbye!")
            break
        if not url:
            print("❌ Please enter a valid URL")
            continue
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            scanner.scan_url(url)
        except Exception as e:
            print(f"❌ Error scanning URL: {e}")

if __name__ == "__main__":
    main()

