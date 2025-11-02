import requests
from datetime import datetime, timedelta
import time

def fetch_nvd(days=365):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    cves = []
    max_results = min(2000, days * 10)
    
    try:
        if days > 30:
            chunk_size = 30
            chunks = (days // chunk_size) + 1
        else:
            chunk_size = days
            chunks = 1
        
        for i in range(min(chunks, 5)):
            end_date = datetime.now() - timedelta(days=i * chunk_size)
            start_date = end_date - timedelta(days=chunk_size)
            
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
                "resultsPerPage": min(2000, max_results)
            }
            
            print(f"Fetching NVD from {start_date.date()} to {end_date.date()}")
            
            response = requests.get(base_url, params=params, timeout=60)
            response.raise_for_status()
            data = response.json()
            
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")
                
                descriptions = cve_data.get("descriptions", [])
                description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                
                metrics = cve_data.get("metrics", {})
                severity = "UNKNOWN"
                
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
                
                configurations = cve_data.get("configurations", [])
                affected = []
                for config in configurations:
                    for node in config.get("nodes", []):
                        for match in node.get("cpeMatch", []):
                            if match.get("vulnerable", False):
                                affected.append(match.get("criteria", ""))
                
                published = cve_data.get("published", "")
                
                cves.append({
                    "id": cve_id,
                    "description": description,
                    "severity": severity,
                    "affected_products": affected,
                    "published_date": published,
                    "source": "NVD"
                })
            
            print(f"Fetched {len(cves)} CVEs so far")
            
            if i < min(chunks, 5) - 1:
                print("Waiting 6 seconds (NVD rate limit)...")
                time.sleep(6)
        
    except Exception as e:
        print(f"NVD Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status: {e.response.status_code}")
            print(f"Response text: {e.response.text[:500]}")
        return cves if cves else []
    
    return cves


def _extract_nvd_cve(item):
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "")

    descriptions = cve_data.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    metrics = cve_data.get("metrics", {})
    severity = "UNKNOWN"

    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")

    configurations = cve_data.get("configurations", [])
    affected = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", False):
                    affected.append(match.get("criteria", ""))

    published = cve_data.get("published", "")

    return {
        "id": cve_id,
        "description": description,
        "severity": severity,
        "affected_products": affected,
        "published_date": published,
        "source": "NVD"
    }


def fetch_nvd_by_id(cve_id: str):
    base_url = "https://services.nvd.nist.gov/rest/json/cve/2.0/"
    cve_id = cve_id.strip().upper()

    try:
        response = requests.get(base_url + cve_id, timeout=30)
        response.raise_for_status()
        data = response.json()

        for item in data.get("vulnerabilities", []):
            extracted = _extract_nvd_cve(item)
            if extracted.get("id") == cve_id:
                return extracted
    except Exception as e:
        print(f"NVD lookup error for {cve_id}: {e}")
        return None

    return None


def fetch_osv(days=365):
    query_url = "https://api.osv.dev/v1/query"
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    all_cves = []
    
    try:
        payload = {
            "version": "1.0.0"
        }
        
        response = requests.post(query_url, json=payload, timeout=30)
        
        if response.status_code != 200:
            print(f"OSV API returned status {response.status_code}")
            
            ecosystems = ["PyPI", "npm", "Go"]
            
            for eco in ecosystems:
                try:
                    list_url = f"https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
                    resp = requests.get(list_url, timeout=10, stream=True)
                    if resp.status_code == 200:
                        print(f"Found {eco} vulnerabilities")
                except:
                    pass
        
        nvd_recent_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        recent_params = {
            "resultsPerPage": 100
        }
        
        try:
            response = requests.get(nvd_recent_url, params=recent_params, timeout=30)
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get("vulnerabilities", [])[:50]:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    
                    descriptions = cve_data.get("descriptions", [])
                    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                    
                    metrics = cve_data.get("metrics", {})
                    severity = "UNKNOWN"
                    
                    if "cvssMetricV31" in metrics:
                        severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
                    elif "cvssMetricV2" in metrics:
                        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")
                    
                    affected = []
                    configurations = cve_data.get("configurations", [])
                    for config in configurations:
                        for node in config.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                if match.get("vulnerable", False):
                                    affected.append(match.get("criteria", ""))
                    
                    published = cve_data.get("published", "")
                    
                    all_cves.append({
                        "id": cve_id,
                        "description": description,
                        "severity": severity,
                        "affected_products": affected,
                        "published_date": published,
                        "source": "OSV"
                    })
        except Exception as e:
            print(f"OSV fallback error: {str(e)}")
        
    except Exception as e:
        print(f"OSV Error: {str(e)}")
    
    return all_cves

def normalize_cves(cves):
    normalized = []
    for cve in cves:
        if cve.get("description") and cve.get("id"):
            normalized.append(cve)
    return normalized

