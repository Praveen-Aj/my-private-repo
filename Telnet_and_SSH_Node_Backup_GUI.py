#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import re
import sys
import time
import glob
import shutil
import telnetlib
import getpass
import pexpect
import tempfile
import select
import subprocess
import signal
import pty
from datetime import datetime

# Python 2/3 compatibility for Tkinter
try:
    import Tkinter as tk
    import ttk
    import tkMessageBox
    from ScrolledText import ScrolledText
except ImportError:
    import tkinter as tk
    from tkinter import ttk, messagebox as tkMessageBox
    from tkinter.scrolledtext import ScrolledText

###############################################################################
#                           Color Codes & Globals
###############################################################################
RED   = "\033[91m"
GREEN = "\033[92m"
BLUE  = "\033[94m"
RESET = "\033[0m"

UNREACHABLE_MSG = "Not reachable (Server down or rebooting)"
SUCCESS_MSG     = "Backup completed successfully"

child_process   = None
DEFAULT_DEBUG_LOG = "debug_backup.log"

# The directory where final backups should be placed
TARGET_BACKUP_FOLDER = os.path.join("/users", getpass.getuser(), "Node_Backup")

###############################################################################
#                            Logging & Utility
###############################################################################
def print_error(msg):
    print(RED + str(msg) + RESET)

def log_debug(debug_file, message):
    with open(debug_file, "a") as f:
        timestamp = time.ctime()
        f.write("{}: {}\n".format(timestamp, message))

def get_local_date():
    now = datetime.now()
    return now.strftime("%b") + str(now.day)

def kill_current_process():
    global child_process
    if child_process is not None:
        try:
            if hasattr(child_process, "terminate"):
                child_process.terminate(force=True)
            else:
                os.killpg(os.getpgid(child_process.pid), signal.SIGKILL)
        except:
            pass
        child_process = None
        print_error("Active backup process was killed.")

###############################################################################
#                            Telnet/SSH Routines
###############################################################################
def run_telnet_command(tn, command, debug_file, timeout=10, marker="~~~END~~~"):
    """
    Telnet command with bytes for Python 3 compatibility.
    """
    tn.read_very_eager()
    full_cmd = command + "; echo " + marker
    tn.write((full_cmd + "\n").encode("ascii"))
    output = tn.read_until(marker.encode("ascii"), timeout=timeout)
    lines = output.splitlines()
    filtered = []
    for line in lines:
        line_str = line.decode("ascii", errors="ignore").strip()
        if marker not in line_str and full_cmd.strip() not in line_str and line_str != "":
            filtered.append(line_str)

    if filtered:
        log_debug(debug_file, "[Telnet Cmd] {} => {}".format(command, filtered[-1]))
    return "\n".join(filtered)

def telnet_create_backup(node_ip, username, password, debug_file):
    """
    Telnet backup logic with extra waits after login and after backup creation.
    """
    node_name = "node" + node_ip.split(".")[-1]
    date_str = get_local_date()
    now = datetime.now()
    time_str = now.strftime("%H") + "H_" + now.strftime("%M") + "M"
    zip_file = "{}_time_{}_{}_backup.zip".format(date_str, time_str, node_name)

    try:
        log_debug(debug_file, "[Telnet] Connecting to node: {}".format(node_ip))
        tn = telnetlib.Telnet(node_ip, timeout=15)

        # Wait for login prompt
        tn.read_until(b"login: ", timeout=10)
        tn.write((username + "\n").encode("ascii"))
        tn.read_until(b"Password: ", timeout=10)
        tn.write((password + "\n").encode("ascii"))
        log_debug(debug_file, "[Telnet] Logged in successfully to {}".format(node_ip))

        # Wait a bit for banner
        time.sleep(2)
        tn.read_very_eager()  # flush banner

        # Cleanup existing *.zip and zi*
        cleanup_cmd = "cd /usr4/BACKUP/IMMED && rm -f *.zip zi*"
        log_debug(debug_file, "[Telnet] Cleanup: {}".format(cleanup_cmd))
        run_telnet_command(tn, cleanup_cmd, debug_file, timeout=10)

        log_debug(debug_file, "[Telnet] Creating backup: {}".format(zip_file))
        backup_cmd = (
            "cd /usr4/BACKUP/IMMED && "
            "find . -type f ! -iname '*.zip' | while read file; do "
            "if [ -r \"$file\" ]; then "
            "zip -r -9 {} \"$file\" >/dev/null 2>&1; "
            "else echo \"Skipping $file (no read permission)\"; "
            "fi; done"
        ).format(zip_file)
        run_telnet_command(tn, backup_cmd, debug_file, timeout=120)

        # Wait 5s to ensure finalization
        time.sleep(5)
        tn.read_very_eager()

        # Final cleanup of partial files (zi*)
        final_cleanup = "cd /usr4/BACKUP/IMMED && rm -f zi*"
        run_telnet_command(tn, final_cleanup, debug_file, timeout=10)

        tn.write(b"exit\n")
        tn.close()

        log_debug(debug_file, "[Telnet] Backup successfully created: {}".format(zip_file))
        return zip_file, None
    except Exception as e:
        err_msg = "[Telnet] Error creating backup on {}: {}".format(node_ip, str(e))
        log_debug(debug_file, err_msg)
        return None, err_msg

def read_until(fd, expected, timeout=30):
    """Reads from file descriptor `fd` until the expected string is found or timeout occurs."""
    buffer = ""
    end_time = time.time() + timeout
    while time.time() < end_time:
        r, _, _ = select.select([fd], [], [], 1)
        if fd in r:
            try:
                data = os.read(fd, 1024)
                if isinstance(data, bytes):  # Convert bytes to string if needed
                    data = data.decode("utf-8", "ignore")
            except OSError:
                break
            if not data:
                break
            buffer += data
            if expected in buffer:
                break
    return buffer

def create_backup_ssh(node, debug_file):
    ip       = node["ip"]
    username = node["login"]
    password = node["password"]

    node_name = "node" + ip.split(".")[-1]
    date_str = get_local_date()
    now = datetime.now()
    time_str = now.strftime("%H") + "H_" + now.strftime("%M") + "M"
    zip_file = "{}_time_{}_{}_backup.zip".format(date_str, time_str, node_name)

    try:
        cleanup_node_backups_ssh(ip, username, password, debug_file)
        log_debug(debug_file, "[SSH] Creating backup: {}".format(zip_file))

        backup_cmd = (
            "cd /usr4/BACKUP/IMMED && "
            "find . -type f -not -iname '*.zip' | while read f; do "
            "if [ -r \"$f\" ]; then zip -r -9 {} \"$f\" >/dev/null 2>&1; fi; "
            "done"
        ).format(zip_file)
        run_ssh_command(ip, username, password, backup_cmd, debug_file, timeout=120)
        time.sleep(3)

        stat_cmd = "cd /usr4/BACKUP/IMMED && stat -c %s {} 2>/dev/null".format(zip_file)
        output = run_ssh_command(ip, username, password, stat_cmd, debug_file, timeout=10)
        try:
            size = int(output.strip())
        except:
            size = 0
        if size > 0:
            log_debug(debug_file, "[SSH] Backup file created: {} (size={})".format(zip_file, size))
            return zip_file, None
        else:
            err = "[SSH] Backup file verification failed. Size=0"
            log_debug(debug_file, err)
            return None, err
    except Exception as e:
        err_msg = "[SSH] Error creating backup on {}: {}".format(ip, str(e))
        log_debug(debug_file, err_msg)
        return None, err_msg

    log_debug(debug_file, "[SSH] Creating backup for node: {} => {}".format(ip, zip_file))
    return zip_file, None

###############################################################################
#                     Telnet Backup Retrieval Function
###############################################################################
def telnet_retrieve_backup(node_ip, username, password, zip_file, debug_file):
    """
    Connects to a remote node via FTP over Telnet, retrieves a backup file,
    and saves it directly into the TARGET_BACKUP_FOLDER.
    """
    target_dir = TARGET_BACKUP_FOLDER
    if not os.path.exists(target_dir):
        try:
            os.makedirs(target_dir)
            log_debug(debug_file, "[Telnet] Created target backup folder: {}".format(target_dir))
        except Exception as e:
            log_debug(debug_file, "[Telnet] Failed to create target folder {}: {}".format(target_dir, str(e)))
            return (None, "[ERROR] Could not create target folder: " + str(e))
    
    local_path = os.path.join(target_dir, zip_file)
    
    log_debug(debug_file, "[Telnet] Connecting to node: {}".format(node_ip))
    # Allow extra time for remote file finalization
    time.sleep(10)
    
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execvp("ftp", ["ftp", node_ip])
        except Exception:
            sys.exit(1)
    else:
        read_until(fd, "Name:")
        os.write(fd, (username + "\n").encode("utf-8"))
        read_until(fd, "Password:")
        os.write(fd, (password + "\n").encode("utf-8"))
        read_until(fd, "ftp>")
        os.write(fd, "cd /usr4/BACKUP/IMMED\n".encode("utf-8"))
        read_until(fd, "ftp>")
        os.write(fd, "ls -l {}\n".format(zip_file).encode("utf-8"))
        ls_output = read_until(fd, "ftp>")
        log_debug(debug_file, "[FTP] ls output for {}: {}".format(zip_file, ls_output.strip()))
    
        if zip_file not in ls_output:
            err_msg = "[ERROR] FTP ls did not find the file: " + zip_file
            log_debug(debug_file, err_msg)
            os.write(fd, "bye\n".encode("utf-8"))
            os.waitpid(pid, 0)
            return (None, err_msg)
    
        os.write(fd, "binary\n".encode("utf-8"))
        read_until(fd, "ftp>")
        os.write(fd, "get {} {}\n".format(zip_file, local_path).encode("utf-8"))
        read_until(fd, "ftp>")
        os.write(fd, "bye\n".encode("utf-8"))
        os.waitpid(pid, 0)
    
        if not os.path.exists(local_path):
            err_msg = "[ERROR] FTP retrieval did not create local file: " + local_path
            log_debug(debug_file, err_msg)
            return (None, err_msg)
    
        log_debug(debug_file, "[SUCCESS] Backup file retrieved directly to: " + local_path)

        # Extra cleanup if a leftover file remains in current working directory
        leftover_in_cwd = os.path.join(os.getcwd(), zip_file)
        if os.path.exists(leftover_in_cwd) and leftover_in_cwd != local_path:
            try:
                os.remove(leftover_in_cwd)
                log_debug(debug_file, "Removed leftover Telnet file from working dir: " + leftover_in_cwd)
            except Exception as ex:
                log_debug(debug_file, "Could not remove leftover file {}: {}".format(leftover_in_cwd, str(ex)))

        return (local_path, None)

def retrieve_backup_ssh(node, debug_file, zip_file):
    ip       = node["ip"]
    username = node["login"]
    password = node["password"]
    local_path = os.path.join("/tmp", zip_file)

    scp_cmd = "scp {}@{}:/usr4/BACKUP/IMMED/{} {}".format(username, ip, zip_file, local_path)
    try:
        global child_process
        child_process = pexpect.spawn(scp_cmd, timeout=30)
        i = child_process.expect(["(yes/no)", "[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT])
        if i == 0:
            child_process.sendline("yes")
            child_process.expect("[Pp]assword:")
            child_process.sendline(password)
        elif i == 1:
            child_process.sendline(password)
        child_process.expect(pexpect.EOF)
    except Exception as e:
        err = "[SSH SCP] Error retrieving file: {}".format(str(e))
        log_debug(debug_file, err)
        child_process = None
        return None, err
    finally:
        child_process = None

    if not os.path.exists(local_path):
        err = "[SSH SCP] Local file not found after scp: {}".format(local_path)
        log_debug(debug_file, err)
        return None, err

    log_debug(debug_file, "[SSH SCP] Backup retrieved: {}".format(local_path))
    return local_path, None

def cleanup_node_backups_ssh(ip, username, password, debug_file):
    cleanup_cmd = "cd /usr4/BACKUP/IMMED && rm -f '*.zip' 'zi*'"
    log_debug(debug_file, "[SSH] Cleanup: {}".format(cleanup_cmd))
    run_ssh_command(ip, username, password, cleanup_cmd, debug_file, timeout=15)

def run_ssh_command(ip, username, password, command, debug_file, timeout=10):
    ssh_cmd = "ssh {}@{} '{}'".format(username, ip, command)
    output = ""
    try:
        global child_process
        child_process = pexpect.spawn(ssh_cmd, timeout=timeout)
        i = child_process.expect(["(yes/no)", "[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT])
        if i == 0:
            child_process.sendline("yes")
            child_process.expect("[Pp]assword:")
            child_process.sendline(password)
        elif i == 1:
            child_process.sendline(password)
        child_process.expect(pexpect.EOF)
        output = child_process.before
    except pexpect.EOF:
        pass
    except Exception as e:
        log_debug(debug_file, "[SSH CMD] Error: {}".format(str(e)))
    finally:
        child_process = None

    log_debug(debug_file, "[SSH CMD] {} => {}".format(command, output.strip()))
    return output

###############################################################################
#                             Local Move/Cleanup
###############################################################################
def move_backup_locally(zip_file, local_path, debug_file):
    """
    Moves the backup file to Node_Backup folder, removing older backups for the same node.
    Also handles stray Telnet files if the source path is duplicated.
    """
    try:
        if not os.path.exists(local_path):
            os.makedirs(local_path)
            log_debug(debug_file, "Created local backup folder: {}".format(local_path))

        base = os.path.basename(zip_file)
        # Extract the node identifier (e.g. "node10") from the backup file name.
        node_match = re.search(r"(node\d+)_backup\.zip", base, re.IGNORECASE)
        if node_match:
            node_id = node_match.group(1)
            # In the Node_Backup folder, delete only files whose names contain this node_id.
            for f in os.listdir(local_path):
                if node_id in f and f != base:
                    old_file = os.path.join(local_path, f)
                    os.remove(old_file)
                    log_debug(debug_file, "Deleted older backup: {}".format(old_file))

        dest_path = os.path.join(local_path, base)
        # If the source == destination, it might just be a no-op; otherwise we move it.
        if os.path.abspath(zip_file) != os.path.abspath(dest_path):
            shutil.move(zip_file, dest_path)
            log_debug(debug_file, "Backup moved to: {}".format(dest_path))

            # If for some reason the original file still exists, delete it
            if os.path.exists(zip_file):
                try:
                    os.remove(zip_file)
                    log_debug(debug_file, "Cleaned up leftover Telnet file: {}".format(zip_file))
                except Exception as e:
                    log_debug(debug_file, "Failed to remove leftover Telnet file {}: {}".format(zip_file, str(e)))
        else:
            log_debug(debug_file, "File already in final location: {}".format(dest_path))

        return True, None
    except Exception as e:
        err = "Error moving backup file {}: {}".format(zip_file, str(e))
        log_debug(debug_file, err)
        return False, err

def final_local_cleanup(debug_file):
    """
    Delete any stray backup zip files from the current working directory
    (/users/<username>) except Node_Backup subfolder.
    """
    current_dir = os.getcwd()
    stray_files = glob.glob(os.path.join(current_dir, "*_backup.zip"))
    for f in stray_files:
        # Skip files in the Node_Backup folder.
        if os.path.dirname(f) == os.path.join(current_dir, "Node_Backup"):
            continue
        try:
            os.remove(f)
            log_debug(debug_file, "Deleted stray backup file: " + f)
        except Exception as e:
            log_debug(debug_file, "Failed to delete stray backup file {}: {}".format(f, str(e)))

###############################################################################
#                          CheckboxTreeview for Left Pane
###############################################################################
class CheckboxTreeview(ttk.Treeview):
    """
    A Treeview that uses the #0 column for a checkbox icon.
    Telnet nodes = light green (#e1ffe1), SSH nodes = light yellow (#fff7cc).
    """
    def __init__(self, parent, *args, **kwargs):
        style = ttk.Style()
        style.configure("Treeview", rowheight=28)  # match reference script's rowheight

        # Use both the tree column (#0) and headings
        kwargs["show"] = "tree headings"
        kwargs["columns"] = ("name", "type", "ip")
        super(CheckboxTreeview, self).__init__(parent, *args, **kwargs)

        # The checkbox icons live in column #0
        self.column("#0", width=30, anchor=tk.CENTER)
        self.heading("#0", text="")

        self.column("name", width=150, anchor=tk.W)
        self.heading("name", text="Node Name")

        self.column("type", width=80, anchor=tk.W)
        self.heading("type", text="Protocol")

        self.column("ip", width=120, anchor=tk.W)
        self.heading("ip", text="IP Address")

        # Distinguish Telnet vs. SSH rows with new colors
        self.tag_configure("telnet", background="#e1ffe1")  # light green
        self.tag_configure("ssh", background="#fff7cc")     # light yellow

        script_dir = os.path.dirname(os.path.abspath(__file__))
        unchecked_path = os.path.join(script_dir, "unchecked.png")
        checked_path   = os.path.join(script_dir, "checked.png")

        # Attempt Pillow-based image loading
        try:
            from PIL import Image, ImageTk
            unchecked_pil = Image.open(unchecked_path).resize((16, 16), Image.ANTIALIAS)
            checked_pil   = Image.open(checked_path).resize((16, 16), Image.ANTIALIAS)
            self.img_unchecked = ImageTk.PhotoImage(unchecked_pil)
            self.img_checked   = ImageTk.PhotoImage(checked_pil)
        except Exception as e:
            print("Note: Pillow image loading failed:", e)
            self.img_unchecked = ""
            self.img_checked   = ""

        self.item_states = {}
        self.bind("<Button-1>", self._on_click)

    def insert_node(self, parent, index, node_name, node_type, node_ip, checked=True):
        row_tag = "telnet" if node_type.lower() == "telnet" else "ssh"
        icon = self.img_checked if checked else self.img_unchecked
        item_id = self.insert(
            parent,
            index,
            text="",  # the checkbox icon goes in #0
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
#                      Main Backup Manager GUI (Updated Colors)
###############################################################################
class BackupManagerGUI(tk.Tk):
    def __init__(self, config):
        super(BackupManagerGUI, self).__init__()
        self.title("Node Backup Manager")
        self.geometry("1200x700")
        self.config = config
        self.debug_log = config.get("global_settings", {}).get("debug_log", DEFAULT_DEBUG_LOG)
        self.configure(background='#f0f8ff')

        # Attempt to open debug log
        with open(self.debug_log, "w") as df:
            df.write("Backup Process Log\n==================\n")

        self.remote_account_choice = tk.StringVar(value="own")
        self.protocol("WM_DELETE_WINDOW", self.on_quit)

        self._create_layout()
        self._configure_styles()

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure("Treeview.Heading",
            font=("Arial", 11, "bold"),
            foreground="white",
            background="#4a7a8c")
        style.configure("Treeview",
            font=("Arial", 10),
            rowheight=25,
            background="#ffffff",
            fieldbackground="#ffffff")
        style.map("Treeview", background=[("selected", "#e0e0e0")])

        self.results_tree.tag_configure("headingLine", foreground="#009900", font=("Helvetica", 10, "bold"))
        self.results_tree.tag_configure("stepLine", foreground="#0000ff", font=("Helvetica", 10))
        self.results_tree.tag_configure("errorLine", foreground="#cc0000", font=("Helvetica", 10, "bold"))
        self.results_tree.tag_configure("nodeEven", background="#f0f8ff")
        self.results_tree.tag_configure("nodeOdd", background="#e8f8f8")

    def _create_layout(self):
        # PanedWindow with sashwidth=6 for easier resizing
        self.main_pane = tk.PanedWindow(self, orient=tk.VERTICAL,
                                        sashrelief=tk.RAISED,
                                        bg="#cccccc",
                                        sashwidth=6)
        self.main_pane.pack(fill="both", expand=True)

        top_frame = tk.Frame(self.main_pane, bg="#f0f8ff")
        bottom_frame = tk.Frame(self.main_pane, bg="#f0f8ff")

        # Add frames to the PanedWindow
        self.main_pane.add(top_frame)
        self.main_pane.add(bottom_frame)

        horizontal_pane = tk.PanedWindow(top_frame, orient=tk.HORIZONTAL,
                                         sashrelief=tk.RAISED,
                                         bg="#cccccc",
                                         sashwidth=6)
        horizontal_pane.pack(fill="both", expand=True)

        # Left Frame: CheckboxTreeview
        left_frame = tk.LabelFrame(horizontal_pane, text="Select Nodes", font=("Helvetica", 12, "bold"),
                                   bg="#f0f8ff", fg="#003366", padx=10, pady=10)
        right_frame = tk.LabelFrame(horizontal_pane, text="Remote Server Config", font=("Helvetica", 12, "bold"),
                                    bg="#f0f8ff", fg="#003366", padx=10, pady=10)

        horizontal_pane.add(left_frame)
        horizontal_pane.add(right_frame)

        # "Select All / Deselect All" Buttons
        btn_sel_frame = tk.Frame(left_frame, bg="#f0f8ff")
        btn_sel_frame.pack(anchor="w", pady=5)

        btn_select_all = tk.Button(btn_sel_frame, text="Select All", command=self.on_select_all,
                                   font=("Helvetica", 10))
        btn_select_all.pack(side="left", padx=5)

        btn_deselect_all = tk.Button(btn_sel_frame, text="Deselect All", command=self.on_deselect_all,
                                     font=("Helvetica", 10))
        btn_deselect_all.pack(side="left", padx=5)

        # CheckboxTreeview
        self.node_tree = CheckboxTreeview(left_frame)
        vsb = tk.Scrollbar(left_frame, orient="vertical", command=self.node_tree.yview)
        self.node_tree.configure(yscrollcommand=vsb.set)
        self.node_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Insert each node from config
        for i, node in enumerate(self.config.get("nodes", [])):
            self.node_tree.insert_node(
                parent="",
                index="end",
                node_name=node["name"],
                node_type=node["type"],
                node_ip=node["ip"],
                checked=True  # default to selected
            )

        # Right Frame: Remote Server Config
        remote_servers = self.config.get("remote_server", [])
        remote_server = remote_servers[0] if remote_servers else {}

        rowi = 0
        tk.Label(right_frame, text="Remote Server IP:", bg="#f0f8ff").grid(row=rowi, column=0, sticky="w", pady=3)
        self.remote_ip = tk.Entry(right_frame)
        self.remote_ip.grid(row=rowi, column=1, sticky="ew", pady=3)
        self.remote_ip.insert(0, remote_server.get("ip", ""))
        self.remote_ip.config(state="readonly")
        rowi += 1

        tk.Label(right_frame, text="Select Account Type:", bg="#f0f8ff").grid(row=rowi, column=0, sticky="w", pady=3)
        frame_radio = tk.Frame(right_frame, bg="#f0f8ff")
        frame_radio.grid(row=rowi, column=1, sticky="w", pady=3)
        tk.Radiobutton(frame_radio, text="Own Account", variable=self.remote_account_choice, value="own",
                       bg="#f0f8ff").pack(side="left")
        tk.Radiobutton(frame_radio, text="Alternate Account", variable=self.remote_account_choice, value="alternate",
                       bg="#f0f8ff").pack(side="left")
        rowi += 1

        tk.Label(right_frame, text="Remote Username:", bg="#f0f8ff").grid(row=rowi, column=0, sticky="w", pady=3)
        self.remote_username = tk.Entry(right_frame)
        self.remote_username.grid(row=rowi, column=1, sticky="ew", pady=3)
        rowi += 1

        tk.Label(right_frame, text="Remote Password:", bg="#f0f8ff").grid(row=rowi, column=0, sticky="w", pady=3)
        self.remote_password = tk.Entry(right_frame, show="*")
        self.remote_password.grid(row=rowi, column=1, sticky="ew", pady=3)
        rowi += 1

        right_frame.columnconfigure(1, weight=1)
        self.populate_remote_credentials("own")
        self.remote_account_choice.trace("w", lambda *args: self.populate_remote_credentials(self.remote_account_choice.get()))

        # Top Buttons
        button_frame = tk.Frame(top_frame, bg="#f0f8ff")
        button_frame.pack(fill="x", padx=10, pady=5)

        btn_start = tk.Button(button_frame, text="Start Backup", font=("Helvetica", 12, "bold"),
                              bg="#003366", fg="white", command=self.on_start_backup)
        btn_start.pack(side="left", padx=5)

        btn_stop = tk.Button(button_frame, text="Stop Backup", font=("Helvetica", 12, "bold"),
                             bg="red", fg="white", command=self.on_stop_backup)
        btn_stop.pack(side="left", padx=5)

        btn_quit = tk.Button(button_frame, text="Quit", font=("Helvetica", 12, "bold"),
                             bg="#555555", fg="white", command=self.on_quit)
        btn_quit.pack(side="left", padx=5)

        # Bottom Frame: Treeview for results
        self.results_tree = ttk.Treeview(bottom_frame, columns=("Name", "Type", "IP", "Result"), show="headings")
        self.results_tree.heading("Name", text="Name")
        self.results_tree.heading("Type", text="Type")
        self.results_tree.heading("IP", text="IP")
        self.results_tree.heading("Result", text="Result")

        self.results_tree.column("Name", width=200, anchor="center")
        self.results_tree.column("Type", width=80, anchor="center")
        self.results_tree.column("IP", width=120, anchor="center")
        self.results_tree.column("Result", width=600, anchor="w")

        self.results_tree.pack(side="left", fill="both", expand=True)

        scroll_y2 = tk.Scrollbar(bottom_frame, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scroll_y2.set)
        scroll_y2.pack(side="right", fill="y")

        # Insert each node as parent row
        self.node_items = []
        self.node_index = 0
        for node in self.config.get("nodes", []):
            parent_id = self.results_tree.insert("", "end",
                values=(node["name"], node["type"], node["ip"], ""),
                text=node["name"])
            node_tag = "nodeEven" if (self.node_index % 2 == 0) else "nodeOdd"
            self.results_tree.item(parent_id, open=True, tags=(node_tag,))
            self.node_items.append((node, parent_id, node_tag))
            self.node_index += 1

    def populate_remote_credentials(self, remote_account):
        remote_servers = self.config.get("remote_server", [])
        remote_server = remote_servers[0] if remote_servers else {}
        if remote_account == "own":
            self.remote_username.delete(0, tk.END)
            self.remote_username.insert(0, remote_server.get("own_login", ""))
            self.remote_password.delete(0, tk.END)
            self.remote_password.insert(0, remote_server.get("own_password", ""))
        else:
            self.remote_username.delete(0, tk.END)
            self.remote_username.insert(0, remote_server.get("others_remote_login", ""))
            self.remote_password.delete(0, tk.END)
            self.remote_password.insert(0, remote_server.get("others_remote_password", ""))

    def on_select_all(self):
        self.node_tree.check_all()

    def on_deselect_all(self):
        self.node_tree.uncheck_all()

    def on_stop_backup(self):
        kill_current_process()
        tkMessageBox.showinfo("Stop Backup", "Attempted to stop any running backup process.")

    def on_quit(self):
        kill_current_process()
        self.destroy()

    def on_start_backup(self):
        # Build a list of nodes to back up based on the checkboxes
        all_items = self.node_tree.get_children()
        for idx, item_id in enumerate(all_items):
            # If checked, mark that node for backup
            if self.node_tree.is_checked(item_id):
                self.config["nodes"][idx]["backup"] = True
            else:
                self.config["nodes"][idx]["backup"] = False

        self.config.setdefault("global_settings", {})
        self.config["global_settings"]["remote_ip"]   = self.remote_ip.get()
        self.config["global_settings"]["remote_user"] = self.remote_username.get()
        self.config["global_settings"]["remote_pass"] = self.remote_password.get()
        self.config["global_settings"]["target_backup_folder"] = "/users/{}/Node_Backup".format(self.remote_username.get())

        # Clear the bottom results tree and re-insert parent rows for only the selected nodes
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.node_items = []
        self.node_index = 0

        for node in self.config.get("nodes", []):
            if node.get("backup", False):
                parent_id = self.results_tree.insert("", "end",
                    values=(node["name"], node["type"], node["ip"], ""),
                    text=node["name"])
                node_tag = "nodeEven" if (self.node_index % 2 == 0) else "nodeOdd"
                self.results_tree.item(parent_id, open=True, tags=(node_tag,))
                self.node_items.append((node, parent_id, node_tag))
                self.node_index += 1

        self.run_backups_live()

    def run_backups_live(self):
        debug_log = self.debug_log
        remote_server_path = self.config["global_settings"].get("target_backup_folder",
                                                               "/users/{}/Node_Backup".format(getpass.getuser()))
        final_local_cleanup(debug_log)
        any_error = False

        for node, parent_id, node_tag in self.node_items:
            ip        = node["ip"]
            node_type = node["type"].lower()
            username  = node.get("login", "mtcl")
            password  = node.get("password", "mtcl")

            # Start heading line
            self._append_child_row(parent_id,
                "=== Starting backup procedure for node: {} ===".format(ip),
                tags=("headingLine", node_tag))
            self.update()  # allow UI refresh

            try:
                # Step 1: Creating
                self._append_child_row(parent_id, "Step 1: Creating backup...", tags=("stepLine", node_tag))
                self.update()
                if node_type == "telnet":
                    zip_file, err = telnet_create_backup(ip, username, password, debug_log)
                else:
                    zip_file, err = create_backup_ssh(node, debug_log)
                if err:
                    self._append_child_row(parent_id, "Error in Step 1: {}".format(err),
                                           tags=("errorLine", node_tag))
                    any_error = True
                    self.update()
                    continue

                # Step 2: Retrieving
                self._append_child_row(parent_id, "Step 2: Retrieving backup file from node...",
                                       tags=("stepLine", node_tag))
                self.update()
                if node_type == "telnet":
                    local_file, err = telnet_retrieve_backup(ip, username, password, zip_file, debug_log)
                else:
                    local_file, err = retrieve_backup_ssh(node, debug_log, zip_file)
                if err:
                    self._append_child_row(parent_id, "Error in Step 2: {}".format(err),
                                           tags=("errorLine", node_tag))
                    any_error = True
                    self.update()
                    continue

                # Step 3: Moving
                self._append_child_row(parent_id, "Step 3: Moving backup file to Node_Backup folder...",
                                       tags=("stepLine", node_tag))
                self.update()
                success, move_err = move_backup_locally(local_file, remote_server_path, debug_log)
                if not success:
                    self._append_child_row(parent_id, "Error in Step 3: {}".format(move_err),
                                           tags=("errorLine", node_tag))
                    any_error = True
                    self.update()
                    continue

                # Completed
                self._append_child_row(parent_id,
                    "=== Completed backup procedure for node: {} ===".format(ip),
                    tags=("headingLine", node_tag))
                self.update()

            except Exception as e:
                self._append_child_row(parent_id, "Unexpected error: {}".format(str(e)),
                                       tags=("errorLine", node_tag))
                any_error = True
                self.update()

        # Final summary message
        if any_error:
            print_error("Process completed with errors. Check debug log => {}".format(os.path.abspath(debug_log)))
            self._append_child_row("", "All node backups are completed (with errors).", tags=("errorLine",))
        else:
            # If no errors, remove debug log and print success
            print(GREEN + "All steps completed successfully." + RESET)
            self._append_child_row("", "All node backups are completed successfully.", tags=("headingLine",))
            try:
                os.remove(debug_log)
            except Exception as e:
                print_error("Failed to delete debug log: {}".format(str(e)))

    def _append_child_row(self, parent_id, message, tags=()):
        """
        Inserts a new row as a child of `parent_id`, with `message` in the "Result" column.
        We apply the specified `tags` for coloring (headingLine, stepLine, errorLine, nodeEven, nodeOdd).
        """
        if parent_id:
            self.results_tree.insert(
                parent_id,
                "end",
                values=("", "", "", message),
                tags=tags
            )
            self.results_tree.item(parent_id, open=True)
            self.results_tree.see(parent_id)
        else:
            # If parent_id is empty, we insert at the top level
            self.results_tree.insert(
                "",
                "end",
                values=("", "", "", message),
                tags=tags
            )
            self.results_tree.see(self.results_tree.get_children()[-1])

        self.update_idletasks()

###############################################################################
#                                   Main
###############################################################################
def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "master_config.json")

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except Exception as e:
        print_error("Failed to load master_config.json: " + str(e))
        sys.exit(1)

    # If no X server, print a warning in red and exit
    try:
        app = BackupManagerGUI(config)
        app.mainloop()
    except tk.TclError as ex:
        print_error("Warning: Could not open GUI. Please ensure X is installed (Vcxsrv, X11, etc.).")
        sys.exit(1)

if __name__ == "__main__":
    main()