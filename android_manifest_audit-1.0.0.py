import xml.etree.ElementTree as ET
import argparse
import json
import os

def parse_manifest(manifest_path):
    """Parse AndroidManifest.xml and extract security issues."""
    
    # Load the XML file
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError:
        print("❌ Error: Invalid XML file. Check your AndroidManifest.xml.")
        return None

    # Define the package name
    package_name = root.get("package", "Unknown Package")

    issues = []
    
    print(f"\n🔍 Auditing AndroidManifest.xml: {manifest_path}")
    print("=" * 80)

    # 1️⃣ Detect Dangerous Permissions
    dangerous_permissions = {
        "android.permission.READ_SMS": "Can read SMS messages (privacy risk).",
        "android.permission.SEND_SMS": "Can send SMS (potential for abuse).",
        "android.permission.RECORD_AUDIO": "Can record audio (spyware risk).",
        "android.permission.READ_CONTACTS": "Can access user contacts (data privacy concern).",
        "android.permission.READ_PHONE_STATE": "Can access phone identifiers (IMEI/IMSI).",
        "android.permission.WRITE_SETTINGS": "Can modify system settings (high privilege risk)."
    }

    for perm in root.findall(".//uses-permission"):
        name = perm.get("{http://schemas.android.com/apk/res/android}name")
        if name in dangerous_permissions:
            issues.append({
                "issue": f"Dangerous Permission Detected: {name}",
                "severity": "High",
                "impact": dangerous_permissions[name],
                "mitigation": "Ensure this permission is necessary and restrict access using runtime permissions."
            })

    # 2️⃣ Check Exported Components (Activities, Services, Receivers, Providers)
    for component in root.findall(".//activity") + root.findall(".//service") + root.findall(".//receiver") + root.findall(".//provider"):
        name = component.get("{http://schemas.android.com/apk/res/android}name")
        exported = component.get("{http://schemas.android.com/apk/res/android}exported")

        if exported == "true":
            issues.append({
                "issue": f"Exported Component Found: {name}",
                "severity": "Critical",
                "impact": "This component can be accessed by other apps, leading to security risks like privilege escalation.",
                "mitigation": "Set android:exported='false' unless necessary, and enforce permissions if needed."
            })

    # 3️⃣ Insecure Data Storage (Backup & Cleartext Traffic)
    application = root.find("application")
    if application is not None:
        backup = application.get("{http://schemas.android.com/apk/res/android}allowBackup", "false")
        cleartext_traffic = application.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic", "false")

        if backup == "true":
            issues.append({
                "issue": "App Allows Backup (Data Exposure Risk)",
                "severity": "High",
                "impact": "User data can be extracted via ADB backup.",
                "mitigation": "Set android:allowBackup='false' to prevent unauthorized backups."
            })
        
        if cleartext_traffic == "true":
            issues.append({
                "issue": "Cleartext Traffic Allowed (MITM Risk)",
                "severity": "High",
                "impact": "Allows unencrypted HTTP traffic, making it vulnerable to Man-in-the-Middle (MITM) attacks.",
                "mitigation": "Set android:usesCleartextTraffic='false' to enforce HTTPS connections."
            })

    # 4️⃣ Debuggable Mode Detection
    debuggable = application.get("{http://schemas.android.com/apk/res/android}debuggable", "false")
    if debuggable == "true":
        issues.append({
            "issue": "App is Running in Debug Mode",
            "severity": "Critical",
            "impact": "An attacker can attach a debugger and reverse-engineer the app.",
            "mitigation": "Ensure android:debuggable='false' in production builds."
        })

    # 🔹 JSON Output for Further Analysis
    result = {
        "file": manifest_path,
        "package": package_name,
        "total_issues": len(issues),
        "issues": issues
    }

    print("\n🎯 Audit Summary")
    print("=" * 80)
    if issues:
        for idx, issue in enumerate(issues, 1):
            print(f"🚨 {idx}. {issue['issue']}")
            print(f"   🔹 Severity: {issue['severity']}")
            print(f"   ⚠️ Impact: {issue['impact']}")
            print(f"   🛠 Mitigation: {issue['mitigation']}\n")
    else:
        print("✅ No security issues detected!")

    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit an AndroidManifest.xml file for security misconfigurations.")
    parser.add_argument("manifest_file", help="Path to the AndroidManifest.xml file to audit")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--json-output", help="Save JSON results to a file")

    args = parser.parse_args()
    audit_results = parse_manifest(args.manifest_file)

    if args.json:
        print(json.dumps(audit_results, indent=4))
    
    if args.json_output:
        with open(args.json_output, "w") as json_file:
            json.dump(audit_results, json_file, indent=4)
        print(f"📂 JSON results saved to {args.json_output}")
