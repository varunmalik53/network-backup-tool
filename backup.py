import os
import re
import csv
import datetime
import getpass
import sys
import difflib
import glob
import time
import subprocess
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor

# --- CONFIGURATION ---
CSV_FILE = "devices.csv"
BASE_DIR = "network_backups"
MAX_THREADS = 10 

def sanitize_config(config_text):
    config_text = re.sub(r'^#conf_file_ver=.*$', '', config_text, flags=re.M)
    config_text = re.sub(r'^#config-version=.*$', '', config_text, flags=re.M)
    config_text = re.sub(r'set .* ENC \S+', 'set password ENC <STRIPPED>', config_text)
    config_text = re.sub(r'set (?:private-key|certificate) "-----BEGIN.*?-----END.*?"', 
                         'set security-data <STRIPPED>', config_text, flags=re.DOTALL)
    config_text = re.sub(r'^.*uptime is.*$', '', config_text, flags=re.M)
    return config_text

def cleanup_old_files(days_to_keep=30):
    cutoff = time.time() - (days_to_keep * 86400)
    if not os.path.exists(BASE_DIR): return
    for root, dirs, files in os.walk(BASE_DIR):
        for name in files:
            file_path = os.path.join(root, name)
            if os.path.getmtime(file_path) < cutoff:
                os.remove(file_path)

def get_keychain_pass(username, service_name):
    """Securely fetches a password from macOS Keychain."""
    try:
        return subprocess.check_output(
            ['security', 'find-generic-password', '-a', username, '-s', service_name, '-w'],
            text=True
        ).strip()
    except subprocess.CalledProcessError:
        print(f"🛑 ERROR: Password for '{username}' ({service_name}) not found in Mac Keychain.")
        print(f"Run: security add-generic-password -a \"{username}\" -s \"{service_name}\" -w \"your_password\"")
        sys.exit(1)

def get_device_params(row, ad_user, ad_pwd, local_user, local_pwd):
    brand = row.get('brand', '').lower().strip()
    
    # Check if this specific switch uses Local Auth instead of AD
    auth_type = row.get('auth_type', 'ad').lower().strip()
    if auth_type == 'local':
        target_user = local_user
        target_pwd = local_pwd
    else:
        target_user = ad_user
        target_pwd = ad_pwd

    params = {
        'device_type': 'fortinet' if brand == 'fortigate' else 'ruckus_fastiron',
        'host': row['ip'],
        'username': target_user,
        'password': target_pwd,
        'secret': target_pwd,
        'global_delay_factor': 4,
        'ssh_config_file': '~/.ssh/config' # Uses legacy crypto config if needed
    }
    if brand == 'fortigate':
        params['fast_cli'] = False
    return params

def backup_device(row, ad_user, ad_pwd, local_user, local_pwd, timestamp):
    brand = row.get('brand', 'unknown_brand').lower().strip()
    site = row.get('site', 'unknown_site').lower().strip()
    hostname = row.get('hostname', row['ip'])
    
    save_status = "Skipped"
    diff_status = "No Changes"
    
    save_path = os.path.join(BASE_DIR, site, brand)
    os.makedirs(save_path, exist_ok=True)
    params = get_device_params(row, ad_user, ad_pwd, local_user, local_pwd)
    print(f"🔍 DEBUG: {hostname} is attempting to login as '{params['username']}'")

    try:
        with ConnectHandler(**params) as net_connect:
            # --- SAVE/SYNC STEP ---
            if brand == 'ruckus':
                net_connect.enable()
                save_output = net_connect.send_command("write memory", read_timeout=60)
                save_status = "Saved OK" if not any(x in save_output.lower() for x in ["error", "invalid", "fail"]) else "Save Error"
            elif 'fortigate' in brand:
                sync_check = net_connect.send_command("diagnose sys conf sync status")
                save_status = "In Sync" if "in-sync" in sync_check.lower() else "Auto-saved"

            # --- BACKUP STEP ---
            cmd = "show full-configuration" if 'fortigate' in brand else "show running-config"
            config_data = net_connect.send_command(cmd, read_timeout=120)
            new_config_clean = sanitize_config(config_data)
            
            # --- DIFF STEP ---
            existing_files = sorted(glob.glob(os.path.join(save_path, f"{hostname}_*.cfg")), reverse=True)
            if existing_files:
                with open(existing_files[0], 'r') as f:
                    old_config_raw = f.read()
                old_config_clean = sanitize_config(old_config_raw)
                
                if old_config_clean.strip() != new_config_clean.strip():
                    diff = list(difflib.unified_diff(
                        old_config_clean.splitlines(), 
                        new_config_clean.splitlines(), 
                        fromfile='Previous', tofile='Current', lineterm=''
                    ))
                    if diff:
                        diff_status = "⚠️ CHANGE DETECTED"
                        with open(os.path.join(save_path, f"{hostname}_{timestamp}.diff"), "w") as df:
                            df.write("\n".join(diff))

            # --- SAVE RAW FILE ---
            with open(os.path.join(save_path, f"{hostname}_{timestamp}.cfg"), "w") as f:
                f.write(config_data)

            return f"✅ {hostname} [{site}] | Save: {save_status} | Diff: {diff_status}"

    except Exception as e:
        return f"❌ FAILED: {hostname} - {e}"

def main():
    print("--- Enterprise Network Backup Tool ---")
    
    # 1. Ask for Active Directory Credentials
    ad_user = input("Enter AD Username: ")
    ad_pwd = getpass.getpass("Enter AD Password: ")
    
    # 2. Fetch Local Switch Credentials seamlessly from Keychain
    local_user = "admin" # Update this if your local switch user is different
    local_pwd = get_keychain_pass(local_user, "NetworkLocalAdmin")
    
    devices = []
    try:
        with open(CSV_FILE, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            reader.fieldnames = [name.strip().lower() for name in reader.fieldnames]
            devices = list(reader)
    except FileNotFoundError:
        print(f"Error: {CSV_FILE} not found!")
        sys.exit(1)

    if not devices: return

    # 3. SAFETY CHECK
    print(f"\nVerifying credentials on {devices[0]['hostname']}...")
    test_result = backup_device(devices[0], ad_user, ad_pwd, local_user, local_pwd, "VERIFY_ONLY")
    
    if "FAILED" in test_result:
        print(f"\n🛑 AUTHENTICATION ERROR: {test_result}")
        sys.exit(1)
    
    print("✅ Credentials verified. Starting bulk backup...\n")

    # 4. Multi-threaded Execution
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(backup_device, d, ad_user, ad_pwd, local_user, local_pwd, ts) for d in devices]
        for f in futures:
            print(f.result())

    # 5. Generate Summary Report
    summary_file = os.path.join(BASE_DIR, f"summary_{ts}.txt")
    with open(summary_file, "w") as f:
        f.write(f"Backup Summary - {ts}\n")
        f.write("-" * 30 + "\n")
        for f_result in futures:
            res = f_result.result()
            if "⚠️ CHANGE DETECTED" in res or "❌ FAILED" in res:
                f.write(res + "\n")
    
    print(f"\n📄 Summary report generated: {summary_file}")
    cleanup_old_files(30)

if __name__ == "__main__":
    main()
