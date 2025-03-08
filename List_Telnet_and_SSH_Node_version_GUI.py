#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import telnetlib
import time
import re
import pexpect
import threading
import signal

try:
    import Tkinter as tk
    import ttk
except ImportError:
    import tkinter as tk
    import tkinter.ttk as ttk

###############################################################################
#                         Global Variables / Constants
###############################################################################
child_process = None  # Will point to telnetlib.Telnet or pexpect.spawn object
stop_requested = False  # If True, we stop processing further nodes

UNREACHABLE_MSG = "Not reachable (Server down or rebooting)"
DEBUG_LOGFILE = "debug_node_version.log"  # Where we redirect debug prints

###############################################################################
#                            Debug Logging Helper
###############################################################################
def debug_log(msg):
    """
    Appends 'msg' to the debug log file instead of printing to console.
    """
    with open(DEBUG_LOGFILE, "a") as f:
        f.write(msg + "\n")

###############################################################################
#                           Telnet Logic (Unchanged)
###############################################################################
def get_telnet_versions(node):
    """
    Connects to a Telnet node and retrieves version information with graceful error handling.
    """
    global child_process
    ip = node.get('ip')
    username = node.get('login')
    password = node.get('password')
    tn = None
    try:
        tn = telnetlib.Telnet(ip, timeout=10)
        child_process = tn
        tn.read_until(b"login: ")
        tn.write(username.encode('utf-8') + b"\n")
        tn.read_until(b"Password: ")
        tn.write(password.encode('utf-8') + b"\n")
        time.sleep(5)
        output = tn.read_very_eager().decode('utf-8')
        tn.close()
        child_process = None

        active, inactive = parse_versions_telnet(output)
        return active, inactive
    except Exception as e:
        # Log error to debug file
        debug_log("Telnet Error connecting to {}: {}".format(ip, str(e)))
        return UNREACHABLE_MSG, UNREACHABLE_MSG
    finally:
        if child_process == tn:
            child_process = None

def parse_versions_telnet(raw_output):
    """
    Cleans and parses Telnet output to extract active and inactive version details.
    """
    cleaned_output = re.sub(r'\x1b\[[0-9;]*m', '', raw_output).strip()
    active_pattern = r"Active\s*version\s*[:|-]?\s*(R\d+\.\d+-n\d+\.\d+-\d+-fr-[\w\d]+)"
    inactive_pattern = r"Inactive\s*version\s*[:|-]?\s*(R\d+\.\d+-n\d+\.\d+-\d+-fr-[\w\d]+)"
    active_match = re.search(active_pattern, cleaned_output)
    inactive_match = re.search(inactive_pattern, cleaned_output)

    active_version = active_match.group(1) if active_match else "N/A"
    inactive_version = inactive_match.group(1) if inactive_match else "N/A"
    return active_version, inactive_version

###############################################################################
#             SSH Logic (Adapted from Your Sample, with Debug Logging)
###############################################################################
def ssh_connect(server_ip, username, password):
    """
    Start an SSH connection using pexpect.
    Wait for "password:", then send the password.
    Wait for a short prompt/timeout.
    Return the child process object for interaction.
    """
    ssh_command = "ssh {}@{}".format(username, server_ip)
    child = pexpect.spawn(ssh_command, timeout=30)

    # Handle the password prompt
    # If there's an unknown host key prompt, it won't be handled here
    # (You can extend logic if needed.)
    child.expect("password:")
    child.sendline(password)

    # Wait briefly for a shell prompt or leftover banner
    child.expect([pexpect.TIMEOUT, pexpect.EOF], timeout=3)
    return child

def extract_versions_ssh(output):
    """
    Extract active/inactive versions from the command output
    using your sample regex patterns.
    """
    active_version_pattern = r"Active version\s+:\s*(\S+)"
    inactive_version_pattern = r"Inactive version\s+:\s*(\S+)"

    active_match = re.search(active_version_pattern, output)
    inactive_match = re.search(inactive_version_pattern, output)

    active_version = active_match.group(1) if active_match else "N/A"
    inactive_version = inactive_match.group(1) if inactive_match else "N/A"
    return active_version, inactive_version

def get_ssh_versions(node):
    """
    Uses your sample SSH approach to connect, run 'show version',
    parse active/inactive versions, and exit. Errors are logged to debug file.
    """
    global child_process
    ip = node.get('ip')
    username = node.get('login')
    password = node.get('password')

    child = None
    try:
        child = ssh_connect(ip, username, password)
        child_process = child

        # We do NOT print success to console; we log it if needed:
        debug_log("SSH: Logged into {}".format(ip))

        # Send command to fetch version details
        child.sendline("show version")
        # Wait a short time to capture output
        child.expect(pexpect.TIMEOUT, timeout=5)
        version_output = child.before

        if isinstance(version_output, bytes):
            version_output = version_output.decode('utf-8', errors="ignore")

        active_version, inactive_version = extract_versions_ssh(version_output)

        # Exit the SSH session
        child.sendline("exit")
        child.expect(pexpect.EOF)

        debug_log("SSH: Versions for {} -> Active: {}, Inactive: {}".format(ip, active_version, inactive_version))
        child_process = None
        return active_version, inactive_version
    except Exception as e:
        debug_log("SSH Error connecting to {}: {}".format(ip, str(e)))
        return UNREACHABLE_MSG, UNREACHABLE_MSG
    finally:
        if child_process == child:
            child_process = None

###############################################################################
#                 Version String Shortening (Unchanged)
###############################################################################
def get_short_version(full_version):
    if full_version in ["N/A", UNREACHABLE_MSG]:
        return full_version
    match = re.search(r'([nm][^-]+-[^-]+)', full_version)
    if match:
        return match.group(1)
    return full_version

###############################################################################
#                              GUI Section
###############################################################################
class NodeVersionGUI(tk.Tk):
    """
    Single-table GUI with color-coded rows, a stop button, and
    a horizontal separator between Telnet and SSH nodes.
    After all nodes are processed, displays a completion message in the GUI.
    """
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Integrated Node Version Manager")
        self.geometry("1000x600")
        self.configure(bg="#f0f0f0")

        # Bring window to front
        self.lift()
        self.attributes("-topmost", True)
        self.after_idle(self.attributes, "-topmost", False)

        self.completion_label = None
        self.create_widgets()

    def create_widgets(self):
        # Banner
        banner_label = tk.Label(
            self,
            text="Integrated Node Version Manager",
            font=("Arial", 22, "bold"),
            bg="#003366",
            fg="white",
            padx=10,
            pady=10
        )
        banner_label.pack(fill="x")

        # Frame for Stop button
        btn_frame = tk.Frame(self, bg="#f0f0f0")
        btn_frame.pack(fill="x")

        stop_button = tk.Button(
            btn_frame,
            text="Stop",
            font=("Arial", 12, "bold"),
            bg="red",
            fg="white",
            command=self.on_stop
        )
        stop_button.pack(side="right", padx=20, pady=5)

        # Table frame
        table_frame = ttk.Frame(self, padding=(20, 10))
        table_frame.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#ffffff",
            fieldbackground="#ffffff",
            rowheight=30,
            bordercolor="black",
            borderwidth=1,
            relief="solid",
            font=("Arial", 12)
        )
        style.configure(
            "Treeview.Heading",
            background="#cccccc",
            foreground="black",
            bordercolor="black",
            borderwidth=1,
            relief="solid",
            font=("Arial", 14, "bold")
        )
        style.map("Treeview", background=[("selected", "#007acc")])
        style.layout(
            "Treeview",
            [
                (
                    "Treeview.treearea",
                    {"sticky": "nswe"}
                )
            ]
        )

        columns = ("Name", "Type", "IP", "Active Version", "Inactive Version")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            style="Treeview"
        )
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.heading("Name", text="Name")
        self.tree.heading("Type", text="Type")
        self.tree.heading("IP", text="IP")
        self.tree.heading("Active Version", text="Active Version")
        self.tree.heading("Inactive Version", text="Inactive Version")

        self.tree.column("Name", width=140, anchor="center")
        self.tree.column("Type", width=80, anchor="center")
        self.tree.column("IP", width=150, anchor="center")
        self.tree.column("Active Version", width=300, anchor="center")
        self.tree.column("Inactive Version", width=300, anchor="center")

        self.tree.tag_configure("error", background="#ffe8e8", foreground="red")
        self.tree.tag_configure("telnet", background="#e8f1ff", foreground="blue")
        self.tree.tag_configure("ssh", background="#e8ffe8", foreground="green")
        self.tree.tag_configure("normal", background="#ffffff", foreground="black")
        self.tree.tag_configure("separator_line", background="#cccccc", foreground="#000000")

    def add_row(self, node):
        """
        Insert a new row. If 'separator' is True, it's the horizontal line.
        Otherwise, color-code by Telnet/SSH/unreachable.
        """
        if node.get("separator", False):
            dash_line = "----------------------------------------------------------------------------------"
            self.tree.insert(
                "",
                "end",
                values=(dash_line, dash_line, dash_line, dash_line, dash_line),
                tags=("separator_line",)
            )
            return

        name = node.get("name", "N/A")
        node_type = node.get("type", "N/A").lower()
        ip = node.get("ip", "N/A")

        full_active = node.get("active_version", "N/A")
        full_inactive = node.get("inactive_version", "N/A")
        active_version = get_short_version(full_active)
        inactive_version = get_short_version(full_inactive)

        if UNREACHABLE_MSG in (full_active, full_inactive):
            row_tag = "error"
        elif node_type == "telnet":
            row_tag = "telnet"
        elif node_type == "ssh":
            row_tag = "ssh"
        else:
            row_tag = "normal"

        self.tree.insert(
            "",
            "end",
            values=(name, node_type, ip, active_version, inactive_version),
            tags=(row_tag,)
        )

    def on_stop(self):
        """
        Stop the background thread and kill the current connection.
        """
        global stop_requested
        stop_requested = True
        kill_current_process()
        self.destroy()

    def show_completion_message(self):
        """
        Display a green bold message at the bottom indicating all nodes are done.
        """
        if not self.completion_label:
            self.completion_label = tk.Label(
                self,
                text="All node version details completed successfully.",
                font=("Arial", 14, "bold"),
                bg="#f0f0f0",
                fg="green"
            )
            self.completion_label.pack(side="bottom", pady=10)

###############################################################################
#                              Node Processing
###############################################################################
def process_nodes(gui, all_nodes):
    """
    Processes nodes in order. Telnet nodes first, then a separator, then SSH.
    Each node is displayed one by one. If stop_requested is True, we stop.
    After all nodes, we show a completion message in the GUI.
    """
    global stop_requested
    for node in all_nodes:
        if stop_requested:
            break

        if node.get("separator", False):
            gui.after(0, gui.add_row, node)
            time.sleep(1)
            continue

        node_result = node.copy()
        node_type = node.get("type", "").lower()

        try:
            if node_type == "telnet":
                active, inactive = get_telnet_versions(node)
            elif node_type == "ssh":
                active, inactive = get_ssh_versions(node)
            else:
                active, inactive = "N/A", "N/A"
        except Exception as e:
            # Log error to debug file, but do not print to console
            debug_log("Error processing node {}: {}".format(node.get("ip", "Unknown"), str(e)))
            active, inactive = UNREACHABLE_MSG, UNREACHABLE_MSG

        node_result["active_version"] = active
        node_result["inactive_version"] = inactive

        gui.after(0, gui.add_row, node_result)
        time.sleep(1)

    # If we haven't stopped, show the completion message in the GUI
    if not stop_requested:
        gui.after(0, gui.show_completion_message)

###############################################################################
#                              Main Entry Point
###############################################################################
def main():
    # Clear the debug log at start (optional)
    with open(DEBUG_LOGFILE, "w") as f:
        f.write("=== Debug Log Started ===\n")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "master_config.json")

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except Exception as e:
        debug_log("Failed to load configuration file at {}: {}".format(config_path, e))
        return

    all_nodes = config.get("nodes", [])
    telnet_nodes = []
    ssh_nodes = []

    # Separate Telnet vs SSH
    for node in all_nodes:
        ntype = node.get("type", "").lower()
        if ntype == "telnet":
            telnet_nodes.append(node)
        elif ntype == "ssh":
            ssh_nodes.append(node)
        else:
            telnet_nodes.append(node)

    # Insert a separator row between Telnet and SSH
    separator_node = {"separator": True}
    combined_list = telnet_nodes + [separator_node] + ssh_nodes

    app = NodeVersionGUI()

    # Background thread for incremental loading
    processing_thread = threading.Thread(target=process_nodes, args=(app, combined_list))
    processing_thread.daemon = True
    processing_thread.start()

    app.mainloop()

if __name__ == "__main__":
    main()
