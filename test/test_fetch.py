from cve_fetch import fetch_nvd, fetch_osv, normalize_cves

print("Testing NVD fetch...")
nvd_cves = fetch_nvd(days=30)
print(f"NVD returned {len(nvd_cves)} CVEs")

if nvd_cves:
    print(f"\nSample NVD CVE: {nvd_cves[0]['id']}")
    print(f"Description: {nvd_cves[0]['description'][:100]}...")
    print(f"Severity: {nvd_cves[0]['severity']}")

print("\n" + "="*50 + "\n")

print("Testing OSV fetch...")
osv_cves = fetch_osv(days=30)
print(f"OSV returned {len(osv_cves)} CVEs")

if osv_cves:
    print(f"\nSample OSV CVE: {osv_cves[0]['id']}")
    print(f"Description: {osv_cves[0]['description'][:100]}...")
    print(f"Severity: {osv_cves[0]['severity']}")

print("\nDone!")

