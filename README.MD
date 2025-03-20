## 🛡️ AndroidManifest Auditor  
A "vibe coded" **Python-based security audit tool** that scans `AndroidManifest.xml` files for misconfigurations, privacy risks, and security vulnerabilities. 🚀  

## 🛠 Why I Built This
I wanted to explore iOS security automation, so I vibe-coded this tool to audit `Info.plist` files for misconfigurations. 


## 🔥 Features  
✅ **Detects Dangerous Permissions** (SMS, Contacts, Microphone, etc.)  
✅ **Identifies Exported Components** (Activities, Services, Providers, Receivers)  
✅ **Finds Insecure Storage Settings** (ADB Backup, Cleartext Traffic)  
✅ **Detects Debug Mode Enabled in Production**  
✅ **Provides Structured Output with Severity & Mitigation**  
✅ **Exports Results in JSON Format (`--json-output results.json`)**  

---

## 📌 **Installation & Usage**  
### **1️⃣ Clone the Repository**  
```sh
git clone https://github.com/YOUR_USERNAME/android-manifest-auditor.git
cd android-manifest-auditor

```

2️⃣ Run the Auditor
```sh
python android_manifest_audit.py /path/to/AndroidManifest.xml
```

3️⃣ JSON Output (For Reports & Automation)
```sh
Print JSON in Console:
python android_manifest_audit.py /path/to/AndroidManifest.xml --json

Save JSON Output to a File:
python android_manifest_audit.py /path/to/AndroidManifest.xml --json-output results.json
```
🎯 This generates a structured JSON file for further analysis!
