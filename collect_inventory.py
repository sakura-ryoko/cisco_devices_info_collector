#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Modernized Cisco Inventory Script
Target: Python 3.12+ (Forward compatible with 3.14)
Optimized for concurrency, reliability, and detailed reporting.
"""

import sys
import time
import re
import ipaddress
import platform
import subprocess
import getpass
import logging
import csv
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Optional

# Third-party modules
from netmiko import ConnectHandler, SSHDetect
import paramiko
import textfsm
from tabulate import tabulate
import xlsxwriter

# --- CONFIGURATION ---
MAX_WORKERS = 30   # Safe concurrency limit
TIMEOUT = 15       # Connection timeout
VERBOSE = False

# Logging Setup
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# --- DATA STRUCTURES ---

@dataclass
class DeviceResult:
    """Standardized storage for device data."""
    ip: str
    device_type: str
    hostname: str = "Unknown"
    # Basic info (from show version/sysinfo)
    os_version: str | None = None
    uptime: str | None = None
    # Detailed Inventory (List of dicts for all components)
    inventory_items: list[dict] = field(default_factory=list)
    # Storage for raw text
    raw_output: dict[str, str] = field(default_factory=dict)
    error: str | None = None

# --- CORE FUNCTIONS ---

def welcome_message() -> None:
    """Sets the verbose flag based on user input."""
    global VERBOSE
    print('=' * 60)
    print('Cisco Inventory Collector (Detailed Edition)')
    print('=' * 60)
    
    choice = input('Enable verbose logging? [y/N]: ').strip().lower()
    if choice in ('y', 'yes'):
        VERBOSE = True
        logger.setLevel(logging.DEBUG)
        print('-> Verbose mode: ON')
    else:
        print('-> Verbose mode: OFF')


def validate_ip_input(user_input: str) -> list[str]:
    """Parses complex IP strings (ranges, lists) into a clean list of IPv4 strings."""
    clean_list: list[str] = []
    raw_items = [x.strip() for x in user_input.split(',') if x.strip()]

    for item in raw_items:
        try:
            if '-' in item:
                parts = item.split('-')
                start_ip = ipaddress.IPv4Address(parts[0].strip())
                end_part = parts[1].strip()
                
                if '.' in end_part:
                    end_ip = ipaddress.IPv4Address(end_part)
                else:
                    base = str(start_ip).rsplit('.', 1)[0]
                    end_ip = ipaddress.IPv4Address(f"{base}.{end_part}")

                if int(end_ip) < int(start_ip):
                    continue
                
                for ip_int in range(int(start_ip), int(end_ip) + 1):
                    ip_obj = ipaddress.IPv4Address(ip_int)
                    if ip_obj.is_private:
                        clean_list.append(str(ip_obj))
            else:
                ip = ipaddress.IPv4Address(item)
                if ip.is_private:
                    clean_list.append(str(ip))
        except ValueError:
            continue

    return sorted(list(set(clean_list)))


def is_host_alive(ip: str) -> bool:
    """Checks if an IP is pingable."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip] 
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def check_reachability_parallel(ip_list: list[str]) -> list[str]:
    """Pings all IPs in parallel."""
    alive_ips = []
    print(f"\nScanning {len(ip_list)} IPs for reachability (Max Workers: {MAX_WORKERS})...")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {executor.submit(is_host_alive, ip): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            if future.result():
                alive_ips.append(future_to_ip[future])
                    
    print(f"-> Found {len(alive_ips)} active devices.")
    return sorted(alive_ips)


def detect_device_type(device_params: dict) -> str:
    """Attempts to detect device type using Netmiko or fallback."""
    try:
        guesser = SSHDetect(**device_params)
        best_match = guesser.autodetect()
        if best_match: return best_match
    except Exception:
        pass

    # Manual Fallback
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=device_params['ip'], 
            username=device_params['username'],
            password=device_params['password'],
            look_for_keys=False, allow_agent=False, timeout=TIMEOUT
        )
        with client.invoke_shell() as shell:
            time.sleep(2) 
            while shell.recv_ready():
                output = shell.recv(4096).decode('utf-8', errors='ignore')
                if '(Cisco Controller)' in output:
                    client.close()
                    return 'cisco_wlc'
        client.close()
        return 'cisco_ios' # Safer default than SMB
    except Exception:
        return 'unknown'


def process_device(device_params: dict) -> DeviceResult:
    """Connects to device, runs commands, and returns data."""
    ip = device_params['ip']
    if VERBOSE: print(f"Processing {ip}...")

    dev_type = detect_device_type(device_params)
    if not dev_type or dev_type == 'unknown':
        return DeviceResult(ip=ip, device_type="unknown", error="Detection Failed")

    device_params['device_type'] = dev_type
    
    if dev_type == 'cisco_wlc':
        commands = ['show inventory', 'show sysinfo', 'show cdp neighbors detail']
    elif dev_type == 'cisco_s300':
        commands = ['show inventory', 'show version', 'show cdp neighbors']
    else:
        device_params['device_type'] = 'cisco_ios' 
        commands = ['show inventory', 'show version', 'show cdp neighbors']

    result = DeviceResult(ip=ip, device_type=dev_type)

    try:
        with ConnectHandler(**device_params) as ssh:
            if not ssh.check_config_mode(): ssh.enable()
            
            prompt = ssh.find_prompt()
            result.hostname = prompt.replace('#', '').replace('>', '').strip()
            
            for cmd in commands:
                result.raw_output[cmd] = ssh.send_command(cmd)
                
    except Exception as e:
        result.error = str(e)
        if VERBOSE: logger.error(f"Error processing {ip}: {e}")

    return result


def parse_data(results: list[DeviceResult]) -> None:
    """Parses raw command output using TextFSM."""
    template_dir = Path("templates")
    
    for device in results:
        if device.error: continue

        for cmd, output in device.raw_output.items():
            template_name = ""
            
            # Map commands to templates
            match (device.device_type, cmd):
                case ('cisco_ios', 'show inventory'): template_name = 'cisco_ios_show_inventory.template'
                case ('cisco_ios', 'show version'): template_name = 'cisco_ios_show_version.template'
                case ('cisco_ios', 'show cdp neighbors'): template_name = 'cisco_ios_show_cdp_neighbors.template'
                case ('cisco_s300', 'show inventory'): template_name = 'cisco_s300_ssh_show_inventory.template'
                case ('cisco_s300', 'show version'): template_name = 'cisco_s300_ssh_show_version.template'
                case ('cisco_s300', 'show cdp neighbors'): template_name = 'cisco_s300_ssh_show_cdp_neighbors.template'
                case ('cisco_wlc', 'show inventory'): template_name = 'cisco_wlc_ssh_show_inventory.template'
                case ('cisco_wlc', 'show sysinfo'): template_name = 'cisco_wlc_ssh_show_sysinfo.template'
                case ('cisco_wlc', 'show cdp neighbors detail'): template_name = 'cisco_wlc_ssh_show_cdp_neighbors_detail.template'

            if not template_name: continue
            
            template_path = template_dir / template_name
            if not template_path.exists(): continue

            try:
                with open(template_path) as f:
                    fsm = textfsm.TextFSM(f)
                    fsm_results = fsm.ParseText(output)
                    if not fsm_results: continue
                        
                    # --- NEW LOGIC: Capture ALL rows ---
                    
                    if cmd == 'show inventory':
                        # Iterate through EVERY component found
                        for row in fsm_results:
                            row_dict = dict(zip(fsm.header, row))
                            # Add to device's inventory list
                            device.inventory_items.append({
                                'NAME': row_dict.get('NAME', ''),
                                'DESCR': row_dict.get('DESCR', ''),
                                'PID': row_dict.get('PID', ''),
                                'VID': row_dict.get('VID', ''),
                                'SN': row_dict.get('SN', '')
                            })
                    
                    elif cmd == 'show version':
                        first_row = dict(zip(fsm.header, fsm_results[0]))
                        device.os_version = first_row.get('VERSION', '')
                        device.uptime = first_row.get('UPTIME', '')
                        
                    elif cmd == 'show sysinfo':
                        first_row = dict(zip(fsm.header, fsm_results[0]))
                        device.os_version = first_row.get('PRODUCT_VERSION', '')
                        device.uptime = first_row.get('SYSTEM_UP_TIME', '')
                        if 'SYSTEM_NAME' in first_row:
                            device.hostname = first_row['SYSTEM_NAME']

            except Exception as e:
                logger.error(f"Parsing error on {device.ip} ({cmd}): {e}")

def save_reports(results: list[DeviceResult]) -> None:
    """
    Saves individual raw logs and a detailed Excel inventory.
    Includes robust sanitization for illegal Excel characters.
    """
    
    # --- ROBUST CLEANING FUNCTION ---
    def clean_for_excel(text: Any) -> str:
        """
        Aggressively cleans text to prevent Excel XML corruption.
        Removes: C0/C1 controls, Surrogates, DEL, and specific formatting markers.
        """
        if text is None:
            return ""
        
        # 1. Convert to string
        text = str(text)
        
        # 2. Remove C0 Control Chars (ASCII 0-31) except Tab (\t), Newline (\n), Carriage Return (\r)
        #    Also removes Delete (\x7F)
        text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
        
        # 3. Remove C1 Control Chars (Unicode \u0080-\u009F)
        #    These are invisible "Latin-1 Supplement" controls often found in CLI output.
        text = re.sub(r'[\u0080-\u009F]', '', text)
        
        # 4. Remove Unicode Surrogates (Illegal in XML: \uD800-\uDFFF)
        text = re.sub(r'[\uD800-\uDFFF]', '', text)
        
        # 5. Excel Cell Limit: Truncate to 32,000 characters (Excel limit is 32,767)
        if len(text) > 32000:
            text = text[:32000] + "...(truncated)"
            
        return text.strip()
    # -------------------------------

    # 1. Create Log Directory
    log_dir = Path("device_logs")
    log_dir.mkdir(exist_ok=True)
    
    print(f"\nSaving raw logs to '{log_dir}/'...")

    for d in results:
        # Clean hostname for filename safety
        clean_hostname = re.sub(r'[\\/*?:"<>|]', "", d.hostname)
        filename = log_dir / f"{clean_hostname}_{d.ip}.txt"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"DEVICE: {d.ip} ({d.hostname})\n")
                if d.error: f.write(f"ERROR: {d.error}\n")
                f.write("="*40 + "\n")
                for cmd, out in d.raw_output.items():
                    f.write(f"\nCommand: {cmd}\n")
                    f.write("-" * 20 + "\n")
                    f.write(out + "\n")
                    f.write("-" * 20 + "\n")
        except Exception as e:
            logger.error(f"Could not save log for {d.ip}: {e}")

    # 2. Save Standard Device Summary
    # 'strings_to_formulas': False prevents "=" at start of text being treated as math
    wb = xlsxwriter.Workbook('device_summary.xlsx', {'strings_to_formulas': False})
    ws = wb.add_worksheet("Summary")
    
    headers = ['#', 'IP Address', 'Hostname', 'Device Type', 'Main PID', 'Main SN', 'OS Version', 'Uptime', 'Status']
    fmt_header = wb.add_format({'bold': True, 'bg_color': '#D3D3D3', 'border': 1})
    
    for col, h in enumerate(headers):
        ws.write(0, col, h, fmt_header)
        
    for i, d in enumerate(results, start=1):
        main_pid = ""
        main_sn = ""
        if d.inventory_items:
            main_pid = clean_for_excel(d.inventory_items[0].get('PID', ''))
            main_sn = clean_for_excel(d.inventory_items[0].get('SN', ''))
            
        status = "Error" if d.error else "OK"
        ws.write_row(i, 0, [
            i, 
            clean_for_excel(d.ip), 
            clean_for_excel(d.hostname), 
            clean_for_excel(d.device_type), 
            main_pid, 
            main_sn, 
            clean_for_excel(d.os_version), 
            clean_for_excel(d.uptime), 
            status
        ])
    wb.close()

    # 3. Save DETAILED Component Inventory
    print("Saving detailed component inventory to 'full_component_inventory.xlsx'...")
    
    wb_full = xlsxwriter.Workbook('full_component_inventory.xlsx', {'strings_to_formulas': False})
    ws_full = wb_full.add_worksheet("All Components")
    
    full_headers = ['IP Address', 'Hostname', 'Component Name', 'Description', 'PID', 'VID', 'Serial Number']
    
    for col, h in enumerate(full_headers):
        ws_full.write(0, col, h, fmt_header)
    
    row_idx = 1
    for d in results:
        # Iterate every component found
        for item in d.inventory_items:
            # Apply cleaning to ALL fields
            ws_full.write_row(row_idx, 0, [
                clean_for_excel(d.ip), 
                clean_for_excel(d.hostname), 
                clean_for_excel(item.get('NAME', '')),
                clean_for_excel(item.get('DESCR', '')),
                clean_for_excel(item.get('PID', '')),
                clean_for_excel(item.get('VID', '')),
                clean_for_excel(item.get('SN', ''))
            ])
            row_idx += 1
            
    wb_full.close()
    
    print(f"\n-> Summary Report: 'device_summary.xlsx'")
    print(f"-> Full Component Report: 'full_component_inventory.xlsx'")

# --- MAIN EXECUTION ---

def main():
    welcome_message()
    
    print('\nEnter IPv4 list or range (e.g., 192.168.1.1-10):')
    ip_input = input('>: ')
    
    target_ips = validate_ip_input(ip_input)
    if not target_ips:
        print("No valid Private IPs found. Exiting.")
        sys.exit(1)

    active_ips = check_reachability_parallel(target_ips)
    if not active_ips:
        print("No devices are reachable. Exiting.")
        sys.exit(1)

    print('\n--- Credentials ---')
    username = input('Username: ')
    password = getpass.getpass('Password: ')
    secret = getpass.getpass('Enable Secret: ')

    device_list = []
    for ip in active_ips:
        device_list.append({
            'device_type': 'autodetect', 
            'ip': ip,
            'username': username,
            'password': password,
            'secret': secret,
            'fast_cli': False,
            'timeout': TIMEOUT,
            'auth_timeout': TIMEOUT
        })

    print(f"\nConnecting to {len(device_list)} devices (Max Workers: {MAX_WORKERS})...")
    results = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(process_device, dev): dev['ip'] for dev in device_list}
        
        for f in as_completed(futures):
            res = f.result()
            results.append(res)
            print(f"  Finished: {res.ip} ({res.hostname})")

    print("\nParsing output...")
    parse_data(results)

    save_reports(results)
    
    print("\nDone! Have a nice day.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nScript cancelled by user.")
        sys.exit(0)
