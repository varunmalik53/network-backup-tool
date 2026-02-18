import os
import re
import csv
import datetime
import getpass
import sys
import difflib
import glob
import time
from netmiko import ConnectHandler
from concurrent.futures import ThreadPoolExecutor

# --- CONFIGURATION ---
CSV_FILE = "devices.csv"
BASE_DIR = "network_backups"
MAX_THREADS = 10 

def sanitize_config(config_text):
    """Strips out dynamic FortiGate lines to prevent false diffs."""
    # [cite_start]1. Remove file version/checksum and headers [cite: 1]
    config_text = re.sub(r'^#conf_file_ver=.*$', '', config_text, flags=re.M)
    config_text = re.sub(r'^#config-version=.*$', '', config_text, flags=re.M)

    # [cite_start]2. Strip ALL salted encrypted passwords [cite: 3, 5, 27]
    config_text = re.sub(r'set .* ENC \S+', 'set password ENC <STRIPPED>', config_text)
    
    # [cite_start]3. Strip Multi-line Certificate/Key blocks [cite: 6, 9]
    config_text = re.sub(r'set (?:private-key|certificate) "-----BEGIN.*?-----END.*?"', 
                         'set security-data <STRIPPED>', config_text, flags=re.DOTALL)
    
    # 4. Ruckus specific: Ignore system uptime
    config_text = re.sub(r'^.*uptime is.*$', '', config_text, flags=re.M)
    
    return config_text

def cleanup_old_files(days_to_keep=30):
    """Deletes files older than 30 days."""
    cutoff = time.time() - (days_to_keep * 86400)
    if not os.path.exists(BASE_DIR): return
    for root, dirs, files in os.walk(BASE_DIR):
        for name in files:
            file_path = os.path.join(root, name)
            if os.path.getmtime(file_path) < cutoff:
                os.remove(file_path)

def get_device_params(row, ad_username, ad_password):
    brand = row['brand'].lower().strip()
    params = {
        'device_type': 'fortinet' if brand == 'fortigate' else 'ruckus_fastiron',
        'host': row['ip'],
        'username': ad_username,
        'password': ad_password,
        'secret': ad_password,
        'conn_timeout': 30,
        'auth_timeout': 30,
        'banner_timeout': 30,
        'global_delay_factor': 2,
    }
    if brand == 'fortigate':
        params['fast_cli'] = False
    return params

def backup_device(row, ad_username, ad_password, timestamp):
    brand = row.get('brand', 'unknown_brand').lower().strip()
    site = row.get('site', 'unknown_site').lower().strip()
    hostname = row.get('hostname', row['ip'])
    
    # Initialize variables to prevent "not associated with a value" errors
    save_status = "Skipped" 
    diff_status = "No Changes"
    
    save_path = os.path.join(BASE_DIR, site, brand)
    os.makedirs(save_path, exist_ok=True)
    params = get_device_params(row, ad_username, ad_password)

    try:
        with ConnectHandler(**params) as net_connect:
            # --- SAVE STEP ---
            if brand == 'ruckus':
                net_connect.enable()
                save_output = net_connect.send_command("write memory", expect_string=r"#", read_timeout=60)
                # Successful if no error keywords appear
                save_status = "Saved OK" if not any(x in save_output.lower() for x in ["error", "invalid"]) else "Save Error"
            
            elif 'fortigate' in brand:
                sync_check = net_connect.send_command("diagnose sys conf sync status")
                save_status = "In Sync" if "in-sync" in sync_check.lower() else "Auto-saved"

            # --- BACKUP STEP ---
            cmd = "show full-configuration" if 'fortigate' in brand else "show running-config"
            config_data = net_connect.send_command(cmd)
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
    user = input("Enter AD Username: ")
    pwd = getpass.getpass("Enter AD Password: ")
    
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
    test_result = backup_device(devices[0], user, pwd, "VERIFY_ONLY")
    
    if "FAILED" in test_result:
        print(f"\n🛑 AUTHENTICATION ERROR: {test_result}")
        sys.exit(1)
    
    print("✅ Credentials verified. Starting bulk backup...\n")

    # 4. Multi-threaded Execution
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(backup_device, d, user, pwd, ts) for d in devices]
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
