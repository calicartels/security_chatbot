from cve_fetch import fetch_nvd

print("Testing NVD with 90 days (should fetch 3 chunks of 30 days each)...")
print("This will take ~12 seconds due to rate limiting between chunks.\n")

nvd_cves = fetch_nvd(days=90)
print(f"\nTotal CVEs fetched: {len(nvd_cves)}")

if nvd_cves:
    print(f"\nFirst CVE: {nvd_cves[0]['id']} - {nvd_cves[0]['severity']}")
    print(f"Last CVE: {nvd_cves[-1]['id']} - {nvd_cves[-1]['severity']}")
    print("\nSuccess!")
else:
    print("\nFailed - check errors above")

