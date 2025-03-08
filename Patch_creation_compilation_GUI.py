#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GUI Patch Creation Tool (Extended):
 - If username == current_user => local approach
 - Else => su approach with pexpect
 - Steps: clone/connect => cd build => cmake => make => finalize
 - Minimal GUI output (only step messages)
 - Detailed logs in DEBUG_LOG_FILE
 - Uses universal_newlines in local approach to avoid bytes vs. str issues

Enhancements:
 1) Find existing patch ignoring 'patch_' prefix, ignoring case.
 2) Optional Patch Name field in GUI (if blank => patch_{version}).
 3) Accept any branch strings (br_, tag_, bis_, main_, or none).
 4) Retry on 'network' issues.
 5) Fallback to 'tag_{version}' if 'unknown revision' is encountered.
"""

import os
import sys
import signal
import subprocess
import threading
import getpass
import pexpect

try:
    import tkinter as tk
    from tkinter import messagebox
    from tkinter.scrolledtext import ScrolledText
except ImportError:
    sys.exit("Error: tkinter not found. Install python3-tk or use a conda environment with Tkinter.")

DEBUG_LOG_FILE = "debug_log.txt"
stop_requested = False

local_process = None
pexpect_child = None
shared_script_dir = "/users/paruljot/patchfinder/GUI"
remove_debug_log = False

RED    = "\033[91m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
RESET  = "\033[0m"

#
# -------------------- Logging Helpers --------------------
#
def debug_print(msg):
    """
    Writes debug logs ONLY to debug_log.txt (no console printing).
    """
    with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def gui_log(text_widget, line, tag=None):
    """
    Append a line to the GUI text widget (for step messages, errors, etc.).
    """
    text_widget.config(state=tk.NORMAL)
    if tag:
        text_widget.insert(tk.END, line + "\n", tag)
    else:
        text_widget.insert(tk.END, line + "\n")
    text_widget.see(tk.END)
    text_widget.config(state=tk.DISABLED)

def kill_local_process():
    global local_process
    if local_process:
        try:
            os.killpg(os.getpgid(local_process.pid), signal.SIGKILL)
        except:
            pass
        local_process = None

def kill_pexpect_child():
    global pexpect_child
    if pexpect_child:
        try:
            pexpect_child.terminate(force=True)
        except:
            pass
        pexpect_child = None

#
# -------------------- Helpers for Enhanced Logic --------------------
#
def parse_version_from_branch(branch_str):
    """
    Remove known prefixes: 'br_', 'tag_', 'bis_', 'main_'.
    Return the remainder as version_only.
    e.g. 'br_n2.515.26' => 'n2.515.26'
         'tag_n2.515.26' => 'n2.515.26'
         'n2.515.26' => 'n2.515.26'
    """
    out = branch_str
    for prefix in ("br_", "tag_", "bis_", "main_"):
        if out.startswith(prefix):
            out = out[len(prefix):]
    return out

def find_existing_patch_dir(hg_ws_path, version_string):
    """
    Return the name of a subdirectory in hg_ws_path that
    matches version_string ignoring 'patch_' prefix and ignoring case.
    e.g. if version_string='n2.515.26', match 'patch_n2.515.26', 'n2.515.26', etc.
    Return None if none found.
    """
    version_lower = version_string.lower()
    for entry in os.listdir(hg_ws_path):
        full_path = os.path.join(hg_ws_path, entry)
        if os.path.isdir(full_path):
            entry_lower = entry.lower()
            # strip 'patch_' if present
            if entry_lower.startswith("patch_"):
                entry_lower = entry_lower[len("patch_"):]
            if entry_lower == version_lower:
                return entry
    return None

#
# Attempt clone with local logic => retry on 'network' => fallback to tag_{version}
#
def attempt_clone_with_retry(clone_cmd, branch_str, patch_dir, max_retries=3):
    """
    Repeatedly run run_command_local(clone_cmd) up to max_retries if 'network' is found.
    If 'unknown revision' is found => fallback to 'tag_{version}' once.
    """
    for attempt in range(1, max_retries + 1):
        rc = run_command_local(clone_cmd)
        if rc == 0:
            return rc  # success

        with open(DEBUG_LOG_FILE, "r", encoding="utf-8") as f:
            logs = f.read().lower()

        if "unknown revision" in logs:
            # fallback
            version_only = parse_version_from_branch(branch_str)
            fallback_branch = f"tag_{version_only}"
            debug_print(f"[FALLBACK] Trying clone with {fallback_branch}")
            clone_cmd_2 = f"hg clone https://oxe-hg.app.ale-international.com/oxe_ch -r {fallback_branch} {patch_dir}"
            rc2 = run_command_local(clone_cmd_2)
            return rc2
        elif "network" in logs:
            if attempt < max_retries:
                debug_print(f"[RETRY] network error attempt {attempt}/{max_retries}")
                continue
            else:
                debug_print("[RETRY] Gave up after max_retries on network error.")
                return rc
        else:
            return rc
    return rc

#
# SU version => attempt clone with run_command_su
#
def attempt_clone_su_with_retry(child, clone_cmd, branch_str, patch_dir, max_retries=3):
    for attempt in range(1, max_retries+1):
        rc, lines = run_command_su(child, clone_cmd)
        if rc == 0:
            return 0

        with open(DEBUG_LOG_FILE, "r", encoding="utf-8") as f:
            logs = f.read().lower()

        if "unknown revision" in logs:
            version_only = parse_version_from_branch(branch_str)
            fallback_branch = f"tag_{version_only}"
            debug_print(f"[SU-FALLBACK] Trying clone with {fallback_branch}")
            clone_cmd_2 = f"hg clone https://oxe-hg.app.ale-international.com/oxe_ch -r {fallback_branch} {patch_dir}"
            rc2, lines2 = run_command_su(child, clone_cmd_2)
            return rc2
        elif "network" in logs:
            if attempt < max_retries:
                debug_print(f"[SU-RETRY] network error attempt {attempt}/{max_retries}")
                continue
            else:
                debug_print("[SU-RETRY] Gave up after max_retries on network error.")
                return rc
        else:
            return rc
    return rc

#
# -------------------- Local Command Logic --------------------
#
def run_command_local(command):
    debug_print(f"[LOCAL] Running command: {command}")
    shell = "/bin/bash"
    process = subprocess.Popen(
        command, shell=True, executable=shell,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        preexec_fn=os.setsid
    )
    global local_process
    local_process = process
    while True:
        if stop_requested:
            debug_print("[LOCAL] stop_requested=True => killing process.")
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except:
                pass
            break

        line = process.stdout.readline()
        if not line:
            break

        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)

    process.stdout.close()
    rc = process.wait()
    local_process = None
    debug_print(f"[LOCAL] Return code: {rc}")
    return rc

#
# -------------------- run_command_su for su approach --------------------
#
def run_command_su(child, command, check_make=False):
    debug_print(f"[SU] Sending command: {command}")
    child.sendline(command)
    lines = []
    rc = 0

    fallback_pattern = (
        r"(?:"
        r"\d+:\s*$|"
        r"\$|\#|\>|\:|"
        r"[A-Za-z0-9@\-_]*]?\s*\d+:\s"
        r")"
    )

    while True:
        if stop_requested:
            debug_print("[SU] stop_requested=True => terminate child.")
            child.terminate(force=True)
            raise RuntimeError("Stopped by user mid-command (su).")

        idx = child.expect([fallback_pattern, pexpect.EOF, pexpect.TIMEOUT], timeout=120)
        chunk = child.before
        if chunk:
            chunk_list = chunk.splitlines()
            for cl in chunk_list:
                debug_print("[SU-OUT] " + cl)
                lines.append(cl)
        if idx == 0:
            debug_print("[SU] matched fallback prompt => command ended.")
            break
        else:
            rc = 1
            debug_print(f"[ERROR] su command encountered idx={idx} => EOF/TIMEOUT.")
            break

    # Basic error detection
    if rc == 0:
        for ln in lines:
            if "error" in ln.lower() or "abort" in ln.lower():
                rc = 1
                debug_print("[ERROR] Found 'error' or 'abort' in su lines => rc=1.")
                break

    if rc == 0 and check_make:
        last5 = lines[-5:] if len(lines) >= 5 else lines
        success_found = any(("100%" in x or "99%" in x) for x in last5)
        if not success_found:
            rc = 2
            debug_print("[ERROR] No 99% or 100% found => rc=2 in su approach.")

    debug_print(f"[SU] returning rc={rc}, lines count={len(lines)}")
    return (rc, lines)

#
# -------------------- run_su_connect_patch, run_su_cmake, run_su_make_compile --------------------
#
def run_su_connect_patch(child, connect_cmd, success_str="Patch connection established successfully."):
    """
    Wait only for success_str or EOF/TIMEOUT => no fallback pattern used here.
    """
    debug_print(f"[SU-CONNECT] Sending connect command: {connect_cmd}")
    child.sendline(connect_cmd)

    lines = []
    rc = 0
    while True:
        idx = child.expect([success_str, pexpect.EOF, pexpect.TIMEOUT], timeout=120)
        chunk = child.before
        if chunk:
            for cl in chunk.splitlines():
                debug_print("[SU-CONNECT-OUT] " + cl)
                lines.append(cl)
        if idx == 0:
            debug_print("[SU-CONNECT] Found success_str => patch connected.")
            break
        elif idx == 1:
            rc = 1
            debug_print("[ERROR] su connect encountered EOF.")
            break
        else:
            rc = 1
            debug_print("[ERROR] su connect TIMEOUT.")
            break

    if rc == 0:
        for ln in lines:
            if "error" in ln.lower() or "abort" in ln.lower():
                rc = 1
                debug_print("[ERROR] Found 'error' or 'abort' in su connect lines => rc=1.")
                break

    debug_print(f"[SU-CONNECT] returning rc={rc}, lines count={len(lines)}")
    return (rc, lines)

def run_su_cmake(child, cmake_cmd="cmake ..", success_str="-- Build files have been written to", timeout=2000):
    debug_print(f"[SU-CMAKE] {cmake_cmd}")
    child.sendline(cmake_cmd)

    lines = []
    rc = 0
    while True:
        idx = child.expect([success_str, pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)
        chunk = child.before
        if chunk:
            for cl in chunk.splitlines():
                debug_print("[SU-CMAKE-OUT] " + cl)
                lines.append(cl)
                if "error" in cl.lower():
                    rc = 1
                    debug_print("[ERROR] Found 'error' in cmake => rc=1.")
                    break
            if rc == 1:
                break
        if idx == 0:
            debug_print("[SU-CMAKE] Found success_str => cmake success.")
            break
        elif idx == 1:
            rc = 1
            debug_print("[ERROR] su cmake encountered EOF => rc=1.")
            break
        else:
            rc = 1
            debug_print("[ERROR] su cmake TIMEOUT => rc=1.")
            break

    return (rc, lines)

def run_su_make_compile(child, make_cmd="make -j10", timeout=12000, success_tokens=("99%", "100%")):
    debug_print(f"[SU-MAKE] {make_cmd}")
    child.sendline(make_cmd)

    lines = []
    rc = 0
    success_found = False

    while True:
        idx = child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)
        chunk = child.before
        if chunk:
            for cl in chunk.splitlines():
                debug_print("[SU-MAKE-OUT] " + cl)
                lines.append(cl)
                if any(token in cl for token in success_tokens):
                    success_found = True
                if "error" in cl.lower():
                    rc = 1
                    debug_print("[ERROR] Found 'error' => rc=1.")
                    break
            if rc == 1:
                break
        if idx == 0:
            debug_print("[SU-MAKE] Reached EOF => done reading.")
            break
        else:
            rc = 1
            debug_print("[ERROR] su make TIMEOUT => rc=1.")
            break

    if not success_found:
        rc = 1
        debug_print("[ERROR] No 99% or 100% found => rc=1 in su make approach.")
    return (rc, lines)

#
# -------------------- patch_creation_local, patch_creation_su --------------------
#
def patch_creation_local(branch, username, patch_name_input, text_widget):
    """
    Local approach, includes:
      - parse version from branch
      - find existing patch ignoring 'patch_' prefix
      - optional patch name if user typed it
      - clone with retry on network, fallback to tag_{version}
    """
    open(DEBUG_LOG_FILE, "w").close()
    version_str = parse_version_from_branch(branch)
    hg_ws_path = os.path.join("/users", username, "hg_ws")
    if not os.path.exists(hg_ws_path):
        raise RuntimeError(f"hg_ws not found at {hg_ws_path}")
    os.chdir(hg_ws_path)

    existing_patch_dir = find_existing_patch_dir(hg_ws_path, version_str)

    if patch_name_input:
        final_patch_dir = patch_name_input
    else:
        final_patch_dir = "patch_" + version_str

    gui_log(text_widget, "Step 4: Checking patch directory (local)...", "step_tag")
    if existing_patch_dir:
        gui_log(text_widget, f"Found existing patch '{existing_patch_dir}'. Connecting (local)...", "step_tag")
        connect_cmd = f"/bin/bash {shared_script_dir}/oxe_connect.sh {existing_patch_dir}"
        rc = run_command_local(connect_cmd)
        if rc != 0:
            raise RuntimeError("Connect script failed locally. Check debug log.")
        gui_log(text_widget, f"Patch '{existing_patch_dir}' connected successfully (local).", "step_tag")
        patch_dir = os.path.join(hg_ws_path, existing_patch_dir)
    else:
        gui_log(text_widget, f"No existing patch for version '{version_str}'. Cloning new => {final_patch_dir}", "step_tag")
        clone_cmd = f"hg clone https://oxe-hg.app.ale-international.com/oxe_ch -r {branch} {final_patch_dir}"
        rc = attempt_clone_with_retry(clone_cmd, branch, final_patch_dir, max_retries=3)
        if rc != 0:
            raise RuntimeError("Clone failed locally (even after retry/fallback). See debug log.")
        gui_log(text_widget, f"Patch '{final_patch_dir}' cloned successfully (local).", "step_tag")
        patch_dir = os.path.join(hg_ws_path, final_patch_dir)

    gui_log(text_widget, "Step 5: cd build & cmake (local)...", "step_tag")
    build_dir = os.path.join(patch_dir, "build")
    if not os.path.exists(build_dir):
        raise RuntimeError(f"Build directory not found: {build_dir}")
    os.chdir(build_dir)
    rc = run_command_local("cmake ..")
    if rc != 0:
        raise RuntimeError("CMake failed locally.")

    gui_log(text_widget, "Step 6: make -j10 (local)...", "step_tag")
    rc = run_command_local("make -j10")
    with open(DEBUG_LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    last5 = lines[-5:] if len(lines) >= 5 else lines
    success_found = any(("100%" in x or "99%" in x) for x in last5)

    global remove_debug_log
    if rc != 0:
        if success_found:
            gui_log(text_widget, "Patch compiled with some errors (local). Check debug log.", "step_tag")
            remove_debug_log = True
        else:
            raise RuntimeError("Compilation failed (no 99% or 100% near end) (local).")
    else:
        gui_log(text_widget, "Compilation completed successfully (local).", "step_tag")

    gui_log(text_widget, "Step 7: removing debug log, done (local).", "step_tag")
    if os.path.exists(DEBUG_LOG_FILE):
        if remove_debug_log:
            os.remove(DEBUG_LOG_FILE)
    gui_log(text_widget, "All steps completed (local).", "step_tag")

def patch_creation_su(branch, username, password, patch_name_input, text_widget):
    """
    Similar to local but in su mode. 
    """
    open(DEBUG_LOG_FILE, "w").close()
    version_str = parse_version_from_branch(branch)
    hg_ws_path = os.path.join("/users", username, "hg_ws")
    if not os.path.exists(hg_ws_path):
        raise RuntimeError(f"hg_ws not found at {hg_ws_path}")

    existing_patch_dir = find_existing_patch_dir(hg_ws_path, version_str)
    if patch_name_input:
        final_patch_dir = patch_name_input
    else:
        final_patch_dir = "patch_" + version_str

    child = pexpect.spawn("/bin/bash", encoding='utf-8', echo=False)
    global pexpect_child
    pexpect_child = child

    try:
        child.expect(r"\$ ", timeout=5)
    except:
        pass

    debug_print(f"[SU] su {username}")
    child.sendline(f"su {username}")
    idx = child.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT], timeout=10)
    if idx == 0:
        child.sendline(password)
        try:
            child.expect(r":\s*", timeout=10)
        except:
            pass
    elif idx == 1:
        debug_print("[SU] Possibly no password needed.")
    else:
        raise RuntimeError("Did not see password prompt or encountered EOF/TIMEOUT for su approach.")

    gui_log(text_widget, "Step 4 (su): Checking patch directory...", "step_tag")
    if existing_patch_dir:
        gui_log(text_widget, f"Found existing patch '{existing_patch_dir}' in {username}'s bin. Connecting...", "step_tag")
        connect_cmd = f"/bin/bash {shared_script_dir}/oxe_connect.sh {existing_patch_dir}"
        rc, lines = run_su_connect_patch(child, connect_cmd)
        if rc != 0:
            raise RuntimeError("Connect script failed in su mode (did not see success_str).")
        gui_log(text_widget, f"Patch '{existing_patch_dir}' connected successfully (su).", "step_tag")
        patch_dir = os.path.join(hg_ws_path, existing_patch_dir)
    else:
        gui_log(text_widget, f"No existing patch for version '{version_str}' in {username}'s bin. Cloning new => {final_patch_dir}", "step_tag")
        clone_cmd = f"hg clone https://oxe-hg.app.ale-international.com/oxe_ch -r {branch} {final_patch_dir}"
        rc = attempt_clone_su_with_retry(child, clone_cmd, branch, final_patch_dir, max_retries=3)
        if rc != 0:
            raise RuntimeError("Clone failed in su mode (after retry/fallback).")
        connect_cmd = f"/bin/bash {shared_script_dir}/oxe_connect.sh {final_patch_dir}"
        rc, lines = run_su_connect_patch(child, connect_cmd)
        if rc != 0:
            raise RuntimeError("Connect script failed in su mode (did not see success_str).")
        gui_log(text_widget, f"Patch '{final_patch_dir}' cloned & connected successfully (su).", "step_tag")
        patch_dir = os.path.join(hg_ws_path, final_patch_dir)

    gui_log(text_widget, "Step 5 (su): cd build & cmake..", "step_tag")
    rc, lines = run_command_su(child, f"cd {patch_dir}/build")
    if rc != 0:
        raise RuntimeError("Could not cd to build dir in su mode.")
    rc, lines = run_su_cmake(child, "cmake ..", success_str="-- Build files have been written to")
    if rc != 0:
        raise RuntimeError("CMake.. failed in su mode.")

    gui_log(text_widget, "Step 6 (su): make -j10..", "step_tag")
    rc, lines = run_su_make_compile(child, "make -j10", success_tokens=("99%", "100%"))
    global remove_debug_log
    if rc != 0:
        if rc == 2:
            raise RuntimeError("Compilation failed (no 99% or 100% near end) in su mode.")
        else:
            gui_log(text_widget, "Patch compiled with some errors (su). Check debug log.", "step_tag")
    else:
        gui_log(text_widget, "Compilation completed successfully (su).", "step_tag")
        remove_debug_log = True

    gui_log(text_widget, "Step 7 (su): removing debug log, done.", "step_tag")
    if os.path.exists(DEBUG_LOG_FILE):
        if remove_debug_log:
            os.remove(DEBUG_LOG_FILE)
    gui_log(text_widget, "All steps completed under su approach.", "step_tag")

    child.sendline("exit")
    child.close()
    pexpect_child = None

#
# -------------------- GUI Handler --------------------
#
def on_create_patch(branch_entry, username_entry, password_entry, patchname_entry,
                   text_widget, create_btn, stop_btn):
    global stop_requested
    stop_requested = False

    branch = branch_entry.get().strip()
    user = username_entry.get().strip()
    pwd = password_entry.get().strip()
    patch_name_input = patchname_entry.get().strip()

    if not branch or not user or not pwd:
        messagebox.showwarning("Input Error", "Please fill in Branch, Username, and Password.")
        return

    create_btn.config(state=tk.DISABLED)
    stop_btn.config(state=tk.NORMAL)

    text_widget.config(state=tk.NORMAL)
    text_widget.delete("1.0", tk.END)
    text_widget.config(state=tk.DISABLED)

    def worker():
        global local_process, pexpect_child
        try:
            try:
                current_user = os.environ.get("USER") or os.getlogin()
            except:
                current_user = os.getenv("LOGNAME", "")

            if user == current_user:
                patch_creation_local(branch, user, patch_name_input, text_widget)
            else:
                patch_creation_su(branch, user, pwd, patch_name_input, text_widget)

            gui_log(text_widget, "[INFO] All steps completed.", "info_tag")
        except Exception as e:
            gui_log(text_widget, f"[ERROR] {str(e)}", "error_tag")
        finally:
            create_btn.config(state=tk.NORMAL)
            stop_btn.config(state=tk.DISABLED)
            kill_local_process()
            kill_pexpect_child()

    t = threading.Thread(target=worker)
    t.start()

def on_stop():
    global stop_requested
    stop_requested = True
    kill_local_process()
    kill_pexpect_child()

def main():
    root = tk.Tk()
    root.title("Patch Creation Tool (Extended)")
    root.geometry("900x600")

    font_label = ("Helvetica", 14)

    title_label = tk.Label(root, text="GUI Patch Creation Tool (Extended)", font=("Helvetica", 18, "bold"))
    title_label.pack(pady=5)

    input_frame = tk.Frame(root)
    input_frame.pack(pady=5)

    tk.Label(input_frame, text="Branch Name:", font=font_label).grid(row=0, column=0, padx=10, pady=5, sticky=tk.E)
    branch_entry = tk.Entry(input_frame, font=font_label, width=25)
    branch_entry.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(input_frame, text="Username:", font=font_label).grid(row=1, column=0, padx=10, pady=5, sticky=tk.E)
    username_entry = tk.Entry(input_frame, font=font_label, width=25)
    username_entry.grid(row=1, column=1, padx=10, pady=5)

    tk.Label(input_frame, text="Password:", font=font_label).grid(row=2, column=0, padx=10, pady=5, sticky=tk.E)
    password_entry = tk.Entry(input_frame, font=font_label, width=25, show="*")
    password_entry.grid(row=2, column=1, padx=10, pady=5)

    # New optional Patch Name field
    tk.Label(input_frame, text="Optional Patch Name:", font=font_label).grid(row=3, column=0, padx=10, pady=5, sticky=tk.E)
    patchname_entry = tk.Entry(input_frame, font=font_label, width=25)
    patchname_entry.grid(row=3, column=1, padx=10, pady=5)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)

    create_btn = tk.Button(button_frame, text="Create Patch", font=font_label,
                           command=lambda: on_create_patch(branch_entry, username_entry,
                                                           password_entry, patchname_entry,
                                                           text_widget, create_btn, stop_btn))
    create_btn.grid(row=0, column=0, padx=10)

    stop_btn = tk.Button(button_frame, text="Stop", font=font_label, command=on_stop, state=tk.DISABLED)
    stop_btn.grid(row=0, column=1, padx=10)

    text_widget = ScrolledText(root, font=("Courier", 12), wrap=tk.WORD)
    text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    text_widget.config(state=tk.DISABLED)

    # Tag configs for colored text
    text_widget.tag_config("error_tag", foreground="red", font=("Courier", 12, "bold"))
    text_widget.tag_config("info_tag", foreground="magenta", font=("Courier", 12, "italic"))
    text_widget.tag_config("step_tag", foreground="blue", font=("Courier", 12, "bold"))

    root.mainloop()

if __name__ == "__main__":
    main()
