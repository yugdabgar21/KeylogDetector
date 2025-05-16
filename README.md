===========================================================================
                           Offline KeylogDetector
===========================================================================

                 Offline Keylogger Detection Tool for Windows
                     Created by MASTERxD (Yug)
                    https://github.com/yugdabgar21

===========================================================================

Features:
---------

- Filename Matching: Detects suspicious file names like keylog, spy, stealer, etc.
- Heuristic Content Scan: Reads file contents for keywords like on_press, keyboard, Listener.
- Running Process Check: Flags known keylogger-related running processes.
- Simple CLI Interface: Easy to use command line prompts, no GUI.
- Offline Operation: Works without internet.
- Generates detailed scan reports with timestamps.

===========================================================================

How to Run:
-----------

1. Clone the repository:
   git clone https://github.com/yugdabgar21/KeylogDetector.git

2. Navigate to project folder:
   cd KeylogDetector

3. Install dependencies:
   pip install -r requirements.txt

4. Run the scanner:
   python main.py

5. When prompted, enter:
   - Folder path to scan (e.g., C:\Users\YourName\Documents)
   - Path to your signatures.txt file (contains suspicious keywords)

===========================================================================

Sample Scan Output:
-------------------

Scan Time: 2025-05-16 11:54:33
----------------------------------------
[OK] File Signature Scan: Clean

[!] Suspicious Processes:
 - 1088 - winlogon.exe

[!] Heuristic Scan Warnings:
 - Suspicious term found in file: keylog.py → 'on_press'
 - Suspicious term found in file: keylog.py → 'Listener'

Scan Summary:
- 0 suspicious files
- 1 suspicious process
- 2 heuristic warnings

===========================================================================

Dependencies:
-------------

- psutil
- tqdm
- Python 3.7 or newer

Install with:
pip install psutil tqdm

===========================================================================

About:
------

Developed by MASTERxD (Yug)
Student | Ethical Hacking Enthusiast
GitHub: https://github.com/yugdabgar21

===========================================================================

License:
--------

MIT License

===========================================================================
