#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Node Upgrade Manager (Telnet + SSH + GUI)
- Manually decodes SSH leftover with "utf-8" + errors="replace"
- Debug logs go to debug_node_upgrade.log, not the console or GUI
- Debug log removed if all nodes succeed, kept otherwise
"""

import sys
import os
import re
import time
import telnetlib
import pexpect
import logging

# Fallback Imports for Python 2 vs. Python 3
try:
    import Tkinter as tk
    import ttk
    from ScrolledText import ScrolledText
    import Queue as queue
    import tkMessageBox as messagebox
except ImportError:
    import tkinter as tk
    import tkinter.ttk as ttk
    from tkinter.scrolledtext import ScrolledText
    import queue
    from tkinter import messagebox

import threading
from itertools import cycle

# Attempt PIL import for images
try:
    from PIL import Image, ImageTk
except ImportError:
    print("\033[91mPlease install Pillow: pip install pillow\033[0m")
    sys.exit(1)

###############################################################################
# 1) GLOBAL LOGGER - debug logs to file only
###############################################################################
DEBUG_LOG_FILE = "debug_node_upgrade.log"
logging.basicConfig(filename=DEBUG_LOG_FILE, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("UpgradeLogger")
logger.setLevel(logging.DEBUG)

# File handler for debug logs
file_handler = logging.FileHandler(DEBUG_LOG_FILE, mode="w")
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Console handler: CRITICAL only, so user doesn't see debug logs
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.CRITICAL)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Global success flag
ALL_SUCCESS = True

###############################################################################
# 2) LOAD CONFIG (master_config.json)
###############################################################################
script_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(script_dir, "master_config.json")

try:
    import json
    with open(config_path, "r") as f:
        CONFIG = json.load(f)
except Exception as e:
    print("\033[91mFailed to load master_config.json:\033[0m", e)
    sys.exit(1)

DEFAULT_TIMEOUT = 60
LONG_TIMEOUT = 3600  # 60 minutes

# If user doesn't provide Linux version
LINUX_VERSIONS = {
    "m5": "161.000",
    "n1": "183.000",
    "n2": "197.000",
    "n3": "555.000"
}

REMOTE_SERVER = CONFIG["remote_server"][0]  # e.g. { "ip": "10.94.164.110", ... }

# Cycle of highlight colors
NODE_COLORS = cycle([
    "#0044cc",
    "#00cc44",
    "#cc4400",
    "#8800cc",
    "#cccc00"
])

###############################################################################
# UTILITY: Parse Active/Inactive from leftover
###############################################################################
def parse_versions_from_output(raw_output):
    """
    We assume lines like:
      Active version   : R100.1-n2.534-11-fr-c82
      Inactive version : R100.1-n2.534-8-fr-c82
    Adjust as needed for your device's actual banner text.
    """
    cleaned = re.sub(r'\x1b\[[0-9;]*m', '', raw_output).strip()

    active_match   = re.search(r"Active\s+version\s*:\s*(\S+)", cleaned, re.IGNORECASE)
    inactive_match = re.search(r"Inactive\s+version\s*:\s*(\S+)", cleaned, re.IGNORECASE)

    active   = active_match.group(1) if active_match else "N/A"
    inactive = inactive_match.group(1) if inactive_match else "N/A"

    return active, inactive

###############################################################################
# 3) NodeUpgrader
###############################################################################
class NodeUpgrader(object):
    def __init__(self, node, version, linux_version, start_step, gui_log, color):
        self.node = node
        self.version = version
        self.linux_version = linux_version
        self.start_step = start_step
        self.log = gui_log  # function for logging to GUI
        self.color = color
        self.conn = None  # Telnet or pexpect spawn
        # For directory/prefix logic
        self.dir_prefix = '.'.join(version.split('.')[:-1])
        self.patch_suffix = version.split('.')[-1]

        self.active_version = "N/A"
        self.inactive_version = "N/A"

    def log_blue(self, msg):
        logger.debug("[GUI BLUE] " + msg)
        self.log(msg, "BLUE")

    def log_green(self, msg):
        logger.info("[GUI GREEN] " + msg)
        self.log(msg, "GREEN")

    def log_red(self, msg):
        global ALL_SUCCESS
        ALL_SUCCESS = False
        logger.error("[GUI RED] " + msg)
        self.log(msg, "RED")

    def connect(self):
        """
        Connect via Telnet or SSH, parse leftover banner for active/inactive
        """
        try:
            if self.node["type"].lower() == "telnet":
                self._connect_telnet()
                # parse leftover
                leftover_bytes = self.conn.read_very_eager()
                leftover_str   = leftover_bytes.decode("utf-8", errors="replace")
                a, i = parse_versions_from_output(leftover_str)
                self.active_version   = a
                self.inactive_version = i
                self.log_blue(f"Telnet authentication successful\nActive version: {a}\nInactive version: {i}")
            else:
                self._connect_ssh()
                # parse leftover from SSH
                # after expect, data is in self.conn.before (raw bytes)
                leftover_bytes = self.conn.before
                # Possibly read more data if any left
                try:
                    extra = self.conn.read_nonblocking(size=1024, timeout=1)
                    leftover_bytes += extra
                except:
                    pass
                leftover_str = leftover_bytes.decode("utf-8", errors="replace")
                a, i = parse_versions_from_output(leftover_str)
                self.active_version   = a
                self.inactive_version = i
                self.log_blue(f"SSH authentication successful\nActive version: {a}\nInactive version: {i}")

            return True
        except Exception as e:
            self.log_red(f"Connection failed: {str(e)}")
            return False

    def _connect_telnet(self):
        ip = self.node["ip"]
        user = self.node["login"]
        pw   = self.node["password"]
        logger.debug(f"[Telnet] Attempting connection to {ip} as {user}")
        self.conn = telnetlib.Telnet(ip, timeout=DEFAULT_TIMEOUT)

        # Wait for "login:"
        self.conn.read_until(b"login: ", DEFAULT_TIMEOUT)
        self.conn.write((user + "\n").encode("utf-8"))
        time.sleep(2)

        # Wait for "Password:"
        self.conn.read_until(b"Password: ", DEFAULT_TIMEOUT)
        self.conn.write((pw + "\n").encode("utf-8"))
        time.sleep(5)

    def _connect_ssh(self):
        ip = self.node["ip"]
        user = self.node["login"]
        pw   = self.node["password"]
        logger.debug(f"[SSH] Attempting connection to {ip} as {user}")

        cmd = f"ssh {user}@{ip}"
        self.conn = pexpect.spawn(cmd, timeout=DEFAULT_TIMEOUT)  # no encoding param
        i = self.conn.expect(["password:", "Are you sure", pexpect.EOF, pexpect.TIMEOUT], timeout=30)
        if i == 1:
            self.conn.sendline("yes")
            self.conn.expect("password:", timeout=30)
        elif i in [2, 3]:
            raise Exception("SSH connect failed (EOF/TIMEOUT).")

        self.conn.sendline(pw)
        j = self.conn.expect([r"[\$#>\]]\s*$", "password:", "Permission denied", pexpect.EOF, pexpect.TIMEOUT], timeout=30)
        if j == 1:
            raise Exception("SSH password rejected.")
        if j == 2:
            raise Exception("SSH permission denied.")
        if j in [3, 4]:
            raise Exception("SSH connect closed or timed out.")

    def enter_swinst(self):
        if not self.conn:
            self.log_red("SWINST entry failed: no connection object.")
            return False
        try:
            if self.node["type"].lower() == "telnet":
                self._telnet_wait_send(r"[\$#>\]]\s*$", "swinst")
                self._telnet_wait_send("Password: ", self.node["swinst_password"])
                out = self._telnet_wait_send("Your choice [1..2, Q] ?", "2")
                if "Your choice" not in out:
                    raise Exception("Telnet SWINST: didn't see Expert menu.")
                self.log_green("SWINST expert mode entered (Telnet)")
                return True
            else:
                self.conn.sendline("swinst")
                idx = self.conn.expect(["[Pp]assword:", r"[\$#>\]]\s*$"], timeout=30)
                if idx == 0:
                    self.conn.sendline(self.node["swinst_password"])
                    self.conn.expect([r"\s*Your choice\s*\[1\.\.2,\s*Q\]\s*\?"], timeout=60)
                self.conn.sendline("2")
                time.sleep(5)
                self.log_green("SWINST expert mode entered (SSH)")
                return True
        except Exception as e:
            self.log_red(f"SWINST entry failed: {str(e)}")
            return False

    def execute_step(self, step_num):
        if step_num == 1:
            return self._step1_package()
        elif step_num == 2:
            return self._step2_delivery()
        elif step_num == 3:
            return self._step3_patch()
        return False

    def _step1_package(self):
        self.log_blue("\nStarting Step 1: Package (Linux) Installation")
        try:
            steps = [
                ("Your choice [1..9, Q] ?", "1"),
                ("Your choice [1..5, Q] ?", "4"),
                ("Enter the name of the server", REMOTE_SERVER["ip"]),
                ("Enter directory of LINUX", f"{self.dir_prefix}.delivery/pcmao/boot_res/bootp/linux"),
                ("Enter the name of the Linux version", self.linux_version),
                ("Clean the second Linux version", "y")
            ]
            self._execute_menu_sequence(steps)
            leftover = self._read_output().lower()
            if "bypass" in leftover:
                self._execute_menu_sequence([("Do you want to bypass this control", "y")])

            self._wait_installation_confirmation()
            self._execute_menu_sequence([("Press return", "")])
            time.sleep(60)
            self._execute_menu_sequence([("Your choice [1..5, Q] ?", "Q")])
            time.sleep(60)

            self.log_green("Step 1 completed successfully\n")
            return True
        except Exception as e:
            self.log_red(f"Step 1 failed: {str(e)}\n")
            return False

    def _step2_delivery(self):
        self.log_blue("\nStarting Step 2: Delivery Installation")
        try:
            steps = [
                ("Your choice [1..9, Q] ?", "2"),
                ("Your choice [1..2, Q] ?", "1"),
                ("Press 0 for the active version, 1 for the inactive", "1"),
                ("Enter the name of the server", REMOTE_SERVER["ip"]),
                ("confirm the installation of a new version", "y"),
                ("Enter the full path of the delivery", f"{self.dir_prefix}.delivery"),
                ("Confirm the full path", "y")
            ]
            self._execute_menu_sequence(steps)
            self._wait_installation_confirmation("end of operation")
            self._execute_menu_sequence([("Press return", "")])
            time.sleep(60)
            self._execute_menu_sequence([("Your choice [1..2, Q] ?", "Q")])
            time.sleep(60)

            self.log_green("Step 2 completed successfully\n")
            return True
        except Exception as e:
            self.log_red(f"Step 2 failed: {str(e)}\n")
            return False

    def _step3_patch(self):
        self.log_blue("\nStarting Step 3: Static Patch Installation")
        try:
            steps = [
                ("Your choice [1..9, Q] ?", "2"),
                ("Your choice [1..2, Q] ?", "1"),
                ("Press 0 for the active version, 1 for the inactive", "1"),
                ("Enter the name of the server", REMOTE_SERVER["ip"]),
                ("confirm the installation of a new version", "y"),
                ("Enter the full path of the delivery", f"patch_{self.dir_prefix}.{self.patch_suffix}"),
                ("Confirm the full path", "y")
            ]
            self._execute_menu_sequence(steps)
            self._wait_installation_confirmation("end of operation")
            self._execute_menu_sequence([("Press return", "")])
            time.sleep(60)

            self.log_green("Step 3 completed successfully\n")
            return True
        except Exception as e:
            self.log_red(f"Step 3 failed: {str(e)}\n")
            return False

    def _execute_menu_sequence(self, steps):
        for prompt, response in steps:
            if self.node["type"].lower() == "telnet":
                self._telnet_wait_send(prompt, response)
            else:
                self._ssh_expect_send(prompt, response)

    def _wait_installation_confirmation(self, expected="installed"):
        start = time.time()
        while time.time() - start < LONG_TIMEOUT:
            leftover = self._read_output().lower()
            if expected in leftover or "press return" in leftover:
                return
            time.sleep(10)
        raise Exception(f"Timeout waiting for '{expected}' or 'press return' within 60min.")

    def _telnet_wait_send(self, prompt, response):
        out_bytes = self.conn.read_until(prompt.encode("utf-8"), DEFAULT_TIMEOUT)
        out_str   = out_bytes.decode("utf-8", errors="replace")
        self.conn.write((response + "\n").encode("utf-8"))
        time.sleep(10)
        return out_str

    def _ssh_expect_send(self, prompt, response):
        logger.debug("Before expecting the prompt, leftover is:\n%r", self.conn.before)
        pattern = re.escape(prompt.strip()) + r"\s*"
        idx = self.conn.expect([pattern, pexpect.EOF, pexpect.TIMEOUT], timeout=DEFAULT_TIMEOUT)
        raw_before = self.conn.before
        before_str = raw_before.decode("utf-8", errors="replace")
        if idx == 1:
            raise Exception("SSH EOF unexpectedly.")
        elif idx == 2:
            raise Exception("SSH TIMEOUT unexpectedly.")

        self.conn.sendline(response)
        time.sleep(10)
        return before_str

    def _read_output(self):
        if self.node["type"].lower() == "telnet":
            out_bytes = self.conn.read_very_eager()
            return out_bytes.decode("utf-8", errors="replace")
        else:
            raw_bytes = self.conn.before
            # read any extra if available
            try:
                extra = self.conn.read_nonblocking(size=1024, timeout=1)
                raw_bytes += extra
            except:
                pass
            return raw_bytes.decode("utf-8", errors="replace")


###############################################################################
# CheckboxTreeview
###############################################################################
class CheckboxTreeview(ttk.Treeview):
    def __init__(self, parent, *args, **kwargs):
        style = ttk.Style()
        style.configure("Treeview", rowheight=28)
        kwargs["columns"] = ("name", "type", "ip")
        super(CheckboxTreeview, self).__init__(parent, *args, **kwargs)

        self.column("#0", width=30, anchor=tk.CENTER)
        self.heading("#0", text="")

        self.column("name", width=150)
        self.heading("name", text="Node Name")

        self.column("type", width=80)
        self.heading("type", text="Protocol")

        self.column("ip", width=120)
        self.heading("ip", text="IP Address")

        self.tag_configure("telnet", background="#ffe6e6")
        self.tag_configure("ssh", background="#e6f3ff")

        script_dir = os.path.dirname(os.path.abspath(__file__))
        unchecked_path = os.path.join(script_dir, "unchecked.png")
        checked_path   = os.path.join(script_dir, "checked.png")

        unchecked_pil = Image.open(unchecked_path).resize((16, 16), Image.ANTIALIAS)
        checked_pil   = Image.open(checked_path).resize((16, 16), Image.ANTIALIAS)

        self.img_unchecked = ImageTk.PhotoImage(unchecked_pil)
        self.img_checked   = ImageTk.PhotoImage(checked_pil)

        self.item_states = {}
        self.bind("<Button-1>", self._on_click)

    def insert_node(self, parent, index, node_name, node_type, node_ip, checked=False):
        row_tag = "telnet" if node_type.lower() == "telnet" else "ssh"
        icon = self.img_checked if checked else self.img_unchecked
        item_id = self.insert(
            parent,
            index,
            text="",
            image=icon,
            values=(node_name, node_type.upper(), node_ip),
            tags=(row_tag,)
        )
        self.item_states[item_id] = checked
        return item_id

    def _on_click(self, event):
        region = self.identify("region", event.x, event.y)
        column = self.identify_column(event.x)
        if region == "tree" and column == "#0":
            item_id = self.identify_row(event.y)
            if item_id:
                old_state = self.item_states.get(item_id, False)
                new_state = not old_state
                self.item_states[item_id] = new_state
                icon = self.img_checked if new_state else self.img_unchecked
                self.item(item_id, image=icon)

    def is_checked(self, item_id):
        return self.item_states.get(item_id, False)

    def check_item(self, item_id, state=True):
        self.item_states[item_id] = state
        icon = self.img_checked if state else self.img_unchecked
        self.item(item_id, image=icon)

    def check_all(self):
        for item in self.get_children():
            self.check_item(item, True)

    def uncheck_all(self):
        for item in self.get_children():
            self.check_item(item, False)

###############################################################################
# MAIN GUI
###############################################################################
class UpgradeGUI(tk.Tk):
    def __init__(self):
        super(UpgradeGUI, self).__init__()
        self.title("Node Upgrade Manager")
        self.geometry("1200x800")

        self.nodes = CONFIG["nodes"]
        self.processing_queue = queue.Queue()
        self.current_processor = None

        self._create_widgets()
        self._setup_tags()

    def _setup_tags(self):
        self.log_area.tag_configure("GREEN", foreground="#008000")
        self.log_area.tag_configure("BLUE", foreground="#0000FF")
        self.log_area.tag_configure("RED", foreground="#CC0000")

    def _create_widgets(self):
        main_pane = ttk.Panedwindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # Left side: Node list
        list_frame = ttk.Frame(main_pane)
        main_pane.add(list_frame, weight=1)

        self.tree = CheckboxTreeview(list_frame)
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Insert each node
        for node in self.nodes:
            self.tree.insert_node(
                "",
                "end",
                node_name=node["name"],
                node_type=node["type"],
                node_ip=node["ip"],
                checked=False
            )

        # Right side: Controls + Log
        right_pane = ttk.Panedwindow(main_pane, orient=tk.VERTICAL)
        main_pane.add(right_pane, weight=3)

        control_frame = ttk.Frame(right_pane)
        right_pane.add(control_frame, weight=1)

        # Version / Linux
        input_frame = ttk.Frame(control_frame)
        input_frame.pack(pady=10, fill=tk.X)

        ttk.Label(input_frame, text="Target Version:").pack(side=tk.LEFT)
        self.version_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.version_var, width=25).pack(side=tk.LEFT, padx=5)

        ttk.Label(input_frame, text="Linux Version:").pack(side=tk.LEFT)
        self.linux_version_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.linux_version_var, width=15).pack(side=tk.LEFT)

        # Step selection
        step_frame = ttk.Frame(control_frame)
        step_frame.pack(pady=5)
        ttk.Label(step_frame, text="Start Step:").pack(side=tk.LEFT)
        self.step_var = tk.IntVar(value=1)
        ttk.Spinbox(step_frame, from_=1, to=3, textvariable=self.step_var, width=5).pack(side=tk.LEFT)

        # Buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Select All", command=self.select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Deselect All", command=self.deselect_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Start Upgrade", command=self.start_upgrade).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Stop", command=self.stop_upgrade).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Force Quit", command=self.force_quit).pack(side=tk.LEFT, padx=5)

        # Log area
        self.log_area = ScrolledText(right_pane, wrap=tk.WORD, font=("Consolas", 10))
        right_pane.add(self.log_area, weight=4)

    def select_all(self):
        self.tree.check_all()

    def deselect_all(self):
        self.tree.uncheck_all()

    def log(self, message, tag="GREEN"):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, message + "\n", tag)
        self.log_area.config(state=tk.DISABLED)
        self.log_area.see(tk.END)
        if tag == "RED":
            logger.error(message)
        elif tag == "BLUE":
            logger.debug(message)
        else:
            logger.info(message)

    def start_upgrade(self):
        version = self.version_var.get().strip()
        custom_linux = self.linux_version_var.get().strip()
        start_step = self.step_var.get()

        if not re.match(r"^[nNmM]\d+\.\d+\.\d+$", version):
            messagebox.showerror("Invalid Version", "Version format should be like n2.534.4")
            return

        selected_items = []
        for item_id in self.tree.get_children():
            if self.tree.is_checked(item_id):
                selected_items.append(item_id)

        if not selected_items:
            messagebox.showwarning("Selection Required", "Please select at least one node.")
            return

        for sel_item in selected_items:
            idx = self.tree.index(sel_item)
            node = self.nodes[idx]
            color = next(NODE_COLORS)
            self.processing_queue.put((node, version, custom_linux, start_step, color))

        self.process_next_node()

    def process_next_node(self):
        if not self.processing_queue.empty():
            node, version, custom_linux, start_step, color = self.processing_queue.get()
            t = threading.Thread(
                target=self.run_upgrade,
                args=(node, version, custom_linux, start_step, color),
                daemon=True
            )
            self.current_processor = t
            t.start()
        else:
            # All done
            global ALL_SUCCESS
            if ALL_SUCCESS:
                # remove debug log
                try:
                    os.remove(DEBUG_LOG_FILE)
                except Exception as e:
                    self.log(f"Warning: unable to delete {DEBUG_LOG_FILE}: {str(e)}", "RED")
            else:
                # keep debug log
                self.log(f"Errors occurred. Debug logs in {DEBUG_LOG_FILE}", "RED")

    def run_upgrade(self, node, version, custom_linux, start_step, color):
        global ALL_SUCCESS
        node_name = node["name"]
        self.log(f"=== Starting upgrade/downgrade procedure for {node_name} ===", "GREEN")
        self.log("", "GREEN")

        # If user gave custom Linux version, use it, else from prefix
        if custom_linux:
            linux_version = custom_linux
        else:
            prefix = version.split(".")[0].lower()
            linux_version = LINUX_VERSIONS.get(prefix, "???")

        from_node = NodeUpgrader(node, version, linux_version, start_step, self.log, color)
        try:
            if not from_node.connect():
                self.log_red(f"Connection failed - aborting node {node_name}.")
                self.process_next_node()
                return

            if not from_node.enter_swinst():
                self.log_red(f"SWINST entry failed - aborting node {node_name}.")
                self.process_next_node()
                return

            success = True
            for step_num in range(start_step, 4):
                step_ok = from_node.execute_step(step_num)
                if not step_ok:
                    success = False
                    break

            if success:
                self.log(f"All steps completed successfully for {node_name}\n", "GREEN")
            else:
                self.log_red(f"Some steps failed for {node_name}\n")

        except Exception as e:
            self.log_red(f"Error on {node_name}: {str(e)}\n")

        finally:
            ending = f"=== End of procedure for {node_name} ==="
            self.log(ending, "GREEN")
            self.log("", "GREEN")
            self.log("", "GREEN")

            self.process_next_node()

    def stop_upgrade(self):
        global ALL_SUCCESS
        ALL_SUCCESS = False
        while not self.processing_queue.empty():
            try:
                self.processing_queue.get_nowait()
            except queue.Empty:
                pass
        self.log("Upgrade process stopped by user", "RED")

    def force_quit(self):
        global ALL_SUCCESS
        ALL_SUCCESS = False
        self.log("Force Quit invoked. Terminating application now.", "RED")
        self.destroy()
        os._exit(0)

def main():
    try:
        app = UpgradeGUI()
        app.mainloop()
    except tk.TclError as e:
        print("\033[91m[ERROR] No X server? Please install X11/Vcxsrv.\033[0m\nDetails:", e)
        sys.exit(1)
    except Exception as ex:
        print("\033[91m[ERROR] Unexpected exception in main:\033[0m", ex)
        sys.exit(1)
    finally:
        logging.shutdown()

if __name__ == "__main__":
    main()
