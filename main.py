import os
import hashlib
import psutil
import time
from datetime import datetime

# Banner
def show_banner():
    banner = r'''
  __  __             _____  _______  ______  _____         _____    _____   _____    ____  
 |  \/  |    /\     / ____||__   __||  ____||  __ \       |  __ \  |  __ \ |  __ \  / __ \ 
 | \  / |   /  \   | (___     | |   | |__   | |__) |__  __| |  | | | |__) || |__) || |  | |
 | |\/| |  / /\ \   \___ \    | |   |  __|  |  _  / \ \/ /| |  | | |  ___/ |  _  / | |  | |
 | |  | | / ____ \  ____) |   | |   | |____ | | \ \  >  < | |__| | | |     | | \ \ | |__| |
 |_|  |_|/_/    \_\|_____/    |_|   |______||_|  \_\/_/\_\|_____/  |_|     |_|  \_\ \____/ 

                       Offline Keylogger Detector
                          By MASTERxD (Yug)
                    https://github.com/yugdabgar21

-------------------------------------------------------------------------------------------
    '''
    print(banner)

# Load file signature hashes
def load_signatures(path):
    signatures = []
    try:
        with open(path, 'r', encoding="utf-8") as f:
            for line in f:
                sig = line.strip().lower()
                if sig:
                    signatures.append(sig)
    except Exception as e:
        print(f"[Error] Could not load signature file: {e}")
    return signatures

# Generate file hash (SHA256)
def file_hash(filepath):
    try:
        with open(filepath, "rb") as f:
            h = hashlib.sha256()
            while chunk := f.read(4096):
                h.update(chunk)
            return h.hexdigest()
    except:
        return None

# Check file content for suspicious keywords
def file_content_suspicious(filepath):
    keywords = ['keylog', 'keyboard', 'listener', 'hook', 'pynput', 'keylogger', 'logkeys', 'getasynckeystate']
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().lower()
            return any(kw in content for kw in keywords)
    except:
        return False

# Scan files in directory
def scan_files(path):
    suspicious_files = []
    suspicious_names = ['keylog', 'hook', 'capture', 'logger']

    for root, dirs, files in os.walk(path):
        for name in files:
            full_path = os.path.join(root, name)
            file_lower = name.lower()

            print(f"Scanning: {full_path} ...")
            time.sleep(0.01)  # fake delay to show progress

            if any(name in file_lower for name in suspicious_names) or file_content_suspicious(full_path):
                suspicious_files.append(full_path)
    return suspicious_files

# Scan processes
def scan_processes():
    flagged = []
    suspicious_names = ['keylog', 'hook', 'capture', 'logger']
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if any(s in name for s in suspicious_names):
                flagged.append((proc.info['pid'], proc.info['name']))
        except:
            continue
    return flagged

# Heuristic analysis (based on keywords in running code)
def heuristic_analysis():
    warnings = []
    keywords = ['pynput', 'keyboard', 'listener', 'keylogger']
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info['cmdline']).lower()
            for kw in keywords:
                if kw in cmdline:
                    warnings.append((proc.info['pid'], proc.info['name'], kw))
        except:
            continue
    return warnings

# Report generation
def generate_report(suspicious_files, flagged_procs, heuristics):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("report.txt", "w", encoding="utf-8") as f:
        f.write(f"Scan Time: {now}\n")
        f.write("-" * 40 + "\n")

        if suspicious_files:
            f.write("[!] Suspicious Files:\n")
            for file in suspicious_files:
                f.write(f" - {file}\n")
        else:
            f.write("[✓] File Scan: Clean\n")

        f.write("\n")

        if flagged_procs:
            f.write("[!] Suspicious Processes:\n")
            for pid, name in flagged_procs:
                f.write(f" - {pid} - {name}\n")
        else:
            f.write("[✓] Process Scan: Clean\n")

        f.write("\n")

        if heuristics:
            f.write("[!] Heuristic Warnings:\n")
            for pid, name, match in heuristics:
                f.write(f" - PID {pid} | Process: {name} | Keyword: {match}\n")
        else:
            f.write("[✓] Heuristic Scan: Clean\n")

        f.write("\n")
        f.write("Scan Summary:\n")
        f.write(f"- {len(suspicious_files)} suspicious files\n")
        f.write(f"- {len(flagged_procs)} suspicious processes\n")
        f.write(f"- {len(heuristics)} heuristic warnings\n")

        f.write("\nNote: Suspicious File = A file that contains keywords commonly used in keylogger programs.")
        f.write("\nNote: Heuristic Scan = Smart detection based on suspicious coding patterns or imports.")

# Main function
def main():
    show_banner()
    path = input("Enter path to scan (folder or file): ").strip()

    if not os.path.exists(path):
        print("[X] Invalid path")
        return

    print("\n[•] Starting Scan...\n")

    files = []
    if os.path.isfile(path):
        if file_content_suspicious(path) or any(n in os.path.basename(path).lower() for n in ['keylog', 'hook', 'logger']):
            files = [path]
    else:
        files = scan_files(path)

    procs = scan_processes()
    heuristics = heuristic_analysis()
    generate_report(files, procs, heuristics)

    print("\n[✓] Scan Complete! Report saved as 'report.txt'")

if __name__ == "__main__":
    main()
