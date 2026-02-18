
# Enterprise Network Backup Tool

Automated, multi-threaded Python tool for backing up FortiGate Firewalls and Ruckus ICX Switches. 

## 🚀 Features
* **Multi-vendor**: Natively supports FortiOS and Ruckus FastIron.
* **Smart Diffs**: Automatically sanitizes configs to ignore dynamic hashes, encrypted passwords, and uptime counters.
* **Dual-Authentication**: Seamlessly switches between Active Directory (AD) and Local admin credentials based on the device configuration.
* **Zero Hardcoded Secrets**: Uses macOS Keychain to securely retrieve passwords at runtime.
* **Auto-Cleanup**: Retains 30 days of backup history automatically.

## 📋 Requirements
* macOS (requires Apple's `security` keychain tool)
* Python 3.x
* Netmiko (`pip install netmiko`)

## 🔐 Credential Setup (First Time Only)
Before running the script, you must store your credentials securely in your Mac's Keychain. The script will request them invisibly at runtime.

1. **Add your Local Switch Admin password:**
   ```bash
   security add-generic-password -a "admin" -s "NetworkLocalAdmin" -w "YOUR_LOCAL_PASSWORD"
