#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GUI Patch Creation Tool (Steps 4–7):
 - If username == current_user => local approach
 - Else => su approach with pexpect
 - Steps: clone/connect => cd build => cmake => make => finalize
 - Minimal GUI output (only step messages)
 - Detailed logs in DEBUG_LOG_FILE
 - Uses universal_newlines in local approach to avoid bytes vs. str issues
"""

import os
import sys
import signal
import subprocess
import threading
import getpass
import pexpect

# ---------- Python 3 tkinter imports ----------
try:
    import tkinter as tk
    from tkinter import messagebox
    from tkinter.scrolledtext import ScrolledText
except ImportError:
    # Fallback if needed, but ideally this won't happen if you're on Python 3 with tkinter
    sys.exit("Error: tkinter not found. Install python3-tk or use a conda environment with Tkinter.")

DEBUG_LOG_FILE = "debug_log.txt"
stop_requested = False

local_process = None
pexpect_child = None
shared_script_dir = "/users/paruljot/patchfinder/GUI"
remove_debug_log = False

# ANSI color codes for optional console logs
RED    = "\033[91m"
BLUE   = "\033[94m"
GREEN  = "\033[92m"
RESET  = "\033[0m"

#
# -------------------- Logging Helpers --------------------
#
def debug_print(msg):
    """
    Previously printed to console + debug file.
    Now ONLY writes to debug file, so debug logs won't appear in user terminal.
    """
    # Removed: print(msg)
    with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def gui_log(text_widget, line, tag=None):
    """Append a line to the GUI text widget."""
    text_widget.config(state=tk.NORMAL)
    if tag:
        text_widget.insert(tk.END, line + "\n", tag)
    else:
        text_widget.insert(tk.END, line + "\n")
    text_widget.see(tk.END)
    text_widget.config(state=tk.DISABLED)

#
# -------------------- STOP / KILL Logic --------------------
#
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
# -------------------- Local Command (Universal Newlines) --------------------
#
def run_command_local(command):
    """
    Run a shell command locally, capturing all output in DEBUG_LOG_FILE,
    using text=True/universal_newlines=True so we get strings, not bytes.
    Returns exit code.
    """
    debug_print(f"[LOCAL] Running command: {command}")
    shell = "/bin/bash"
    process = subprocess.Popen(
        command, shell=True, executable=shell,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True,  # universal_newlines => True
        bufsize=1,
        preexec_fn=os.setsid
    )
    global local_process
    local_process = process
    while True:
        if stop_requested:
            debug_print("[LOCAL] stop_requested=True, killing process.")
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except:
                pass
            break

        line = process.stdout.readline()
        if not line:
            break

        # Write line to debug log
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)

    process.stdout.close()
    rc = process.wait()
    local_process = None
    debug_print(f"[LOCAL] Return code: {rc}")
    return rc

#
# -------------------- Local Steps (Clone/Connect/Build) --------------------
#
def patch_creation_local(branch, username, text_widget):
    """
    Steps 4–7 locally:
      4) clone or connect
      5) cd build & cmake
      6) make -j10
      7) remove debug log, finalize
    """
    # Clear debug log
    open(DEBUG_LOG_FILE, "w").close()

    patch_name = branch.replace("br_", "patch_")
    hg_ws_path = os.path.join("/users", username, "hg_ws")
    if not os.path.exists(hg_ws_path):
        raise RuntimeError(f"hg_ws not found at {hg_ws_path}")
    os.chdir(hg_ws_path)

    patch_dir = os.path.join(hg_ws_path, patch_name)

    # Step 4: clone or connect
    gui_log(text_widget, "Step 4: Checking patch directory (local)...", "step_tag")
    if not os.path.exists(patch_dir):
        gui_log(text_widget, "Patch not found. Cloning (local)...", "step_tag")
        clone_cmd = f"hg clone https://oxe-hg.app.ale-international.com/oxe_ch -r {branch} {patch_name}"
        rc = run_command_local(clone_cmd)
        if rc != 0:
            raise RuntimeError("Clone failed locally. Check debug log.")
        gui_log(text_widget, "Patch cloned successfully (local).", "step_tag")
    else:
        gui_log(text_widget, "Patch found. Connecting (local)...", "step_tag")
        # define shared_script_dir
        connect_cmd = f"/bin/bash {shared_script_dir}/oxe_connect.sh {patch_name}"
        rc = run_command_local(connect_cmd)
        if rc != 0:
            raise RuntimeError("Connect script failed locally. Check debug log.")
        gui_log(text_widget, "Patch connected successfully (local).", "step_tag")

    # Step 5: cd build & cmake
    gui_log(text_widget, "Step 5: cd build & cmake (local)...", "step_tag")
    build_dir = os.path.join(patch_dir, "build")
    if not os.path.exists(build_dir):
        raise RuntimeError(f"Build directory not found: {build_dir}")
    os.chdir(build_dir)
    rc = run_command_local("cmake ..")
    if rc != 0:
        raise RuntimeError("CMake failed locally.")

    # Step 6: make -j10
    gui_log(text_widget, "Step 6: make -j10 (local)...", "step_tag")
    rc = run_command_local("make -j10")
    # Check last lines for 99% or 100%
    with open(DEBUG_LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    last5 = lines[-5:] if len(lines) >= 5 else lines
    success_found = any(("100%" in x or "99%" in x) for x in last5)
    if rc != 0:
        if success_found:
            gui_log(text_widget, "Patch compiled with some errors (local). Check debug log.", "step_tag")
            remove_debug_log = True
        else:
            raise RuntimeError("Compilation failed (no 99% or 100% near end) (local).")
    else:
        gui_log(text_widget, "Compilation completed successfully (local).", "step_tag")

    # Step 7
    gui_log(text_widget, "Step 7: removing debug log, done (local).", "step_tag")
    if os.path.exists(DEBUG_LOG_FILE):
        if(remove_debug_log):
            os.remove(DEBUG_LOG_FILE)
    gui_log(text_widget, "All steps completed (local).", "step_tag")

#
# -------------------- SU Command Block --------------------
#
def run_command_su(child, command, check_make=False):
    """
    Send command to su shell, read chunk until fallback prompt,
    store lines in debug log. Return (rc, lines).
    If check_make=True, check last lines for 99% or 100%.
    """
    debug_print(f"[SU] Sending command: {command}")
    child.sendline(command)
    lines = []
    rc = 0

    fallback_pattern = (
        r"(?:" 
        r"\d+:\s*$|"           # line number + colon
        r"\$|\#|\>|\:|"        # typical $ # > :
        r"[A-Za-z0-9@\-_]*]?\s*\d+:\s"  # bracketed user
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
# -------------------- SU Patch connection --------------------
#
def run_su_connect_patch(child, connect_cmd, success_str="Patch connection established successfully."):
    """
    Send the connect command (oxe_connect.sh <patch>),
    read until we see the 'success_str' or a fallback prompt,
    ensuring we don't skip lines.
    """
    debug_print(f"[SU-CONNECT] Sending connect command: {connect_cmd}")
    child.sendline(connect_cmd)

    lines = []
    rc = 0

    while True:
        # Expect either success_str, fallback prompt, EOF, or TIMEOUT
        idx = child.expect([success_str, pexpect.EOF, pexpect.TIMEOUT], timeout=120)
        chunk = child.before
        if chunk:
            chunk_list = chunk.splitlines()
            for cl in chunk_list:
                debug_print("[SU-CONNECT-OUT] " + cl)
                lines.append(cl)

        if idx == 0:
            # success_str found => fully connected
            debug_print("[SU-CONNECT] Found success_str => patch connected.")
            break
        elif idx == 1:
            # EOF
            rc = 1
            debug_print("[ERROR] su connect encountered EOF.")
            break
        else:
            # TIMEOUT
            rc = 1
            debug_print("[ERROR] su connect TIMEOUT.")
            break

    # If you want basic error detection in the lines:
    if rc == 0:
        for ln in lines:
            if "error" in ln.lower() or "abort" in ln.lower():
                rc = 1
                debug_print("[ERROR] Found 'error' or 'abort' in su connect lines => rc=1.")
                break

    debug_print(f"[SU-CONNECT] returning rc={rc}, lines count={len(lines)}")
    return (rc, lines)

#
# -------------------- SU cmake.. --------------------
#
def run_su_cmake(child, cmake_cmd="cmake ..", 
                 success_str="-- Build files have been written to", 
                 timeout=2000):
    """
    Send cmake command. Keep reading lines until:
      1) success_str is found => success
      2) EOF/TIMEOUT => fail
      3) 'error' in any line => fail
    No fallback prompt is used.
    """
    debug_print(f"[SU-CMAKE-NF] {cmake_cmd}")
    child.sendline(cmake_cmd)

    lines = []
    rc = 0
    while True:
        idx = child.expect([success_str, pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)
        chunk = child.before
        if chunk:
            chunk_list = chunk.splitlines()
            for cl in chunk_list:
                debug_print("[SU-CMAKE-NF-OUT] " + cl)
                lines.append(cl)
                if "error" in cl.lower():
                    rc = 1
                    debug_print("[ERROR] Found 'error' in cmake lines => rc=1.")
                    break
            if rc == 1:
                break

        if idx == 0:
            # success_str found => cmake success
            debug_print("[SU-CMAKE-NF] Found success_str => CMake successful.")
            break
        elif idx == 1:
            # EOF
            rc = 1
            debug_print("[ERROR] su cmake encountered EOF without success_str => rc=1.")
            break
        else:
            # TIMEOUT
            rc = 1
            debug_print("[ERROR] su cmake TIMEOUT => rc=1.")
            break

    return (rc, lines)

#
# -------------------- SU make -j10 compilation --------------------
#
def run_su_make_compile(child, make_cmd="make -j10", 
                        timeout=12000, 
                        success_tokens=("99%", "100%")):
    """
    Send make command. Keep reading lines until:
      1) we see any of success_tokens (e.g. '99%', '100%') => success
      2) EOF/TIMEOUT => fail
      3) 'error' in lines => fail
    No fallback prompt is used.
    """
    debug_print(f"[SU-MAKE-NF] {make_cmd}")
    child.sendline(make_cmd)

    lines = []
    rc = 0
    success_found = False

    while True:
        idx = child.expect([pexpect.EOF, pexpect.TIMEOUT], timeout=timeout)
        chunk = child.before
        if chunk:
            chunk_list = chunk.splitlines()
            for cl in chunk_list:
                debug_print("[SU-MAKE-NF-OUT] " + cl)
                lines.append(cl)
                # Check for success tokens
                if any(token in cl for token in success_tokens):
                    success_found = True
                # Check for 'error'
                if "error" in cl.lower():
                    rc = 1
                    debug_print("[ERROR] Found 'error' => rc=1.")
                    break
            if rc == 1:
                break

        if idx == 0:
            # EOF => we read everything
            debug_print("[SU-MAKE-NF] Reached EOF => done reading.")
            break
        else:
            # TIMEOUT
            rc = 1
            debug_print("[ERROR] su make TIMEOUT => rc=1.")
            break

    if not success_found:
        rc = 1
        debug_print("[ERROR] No 99% or 100% found => rc=1 in su make approach.")

    return (rc, lines)

#
# -------------------- SU Steps --------------------
#
def patch_creation_su(branch, username, password, text_widget):
    """
    Steps 4-7 in su mode:
      4) clone/connect
      5) cd build & cmake
      6) make -j10
      7) remove debug log, finalize
    """
    open(DEBUG_LOG_FILE, "w").close()

    patch_name = branch.replace("br_", "patch_")
    hg_ws_path = os.path.join("/users", username, "hg_ws")
    if not os.path.exists(hg_ws_path):
        raise RuntimeError(f"hg_ws not found at {hg_ws_path}")

    child = pexpect.spawn("/bin/bash", encoding='utf-8', echo=False)
    global pexpect_child
    pexpect_child = child

    # try local prompt
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

    patch_dir = os.path.join(hg_ws_path, patch_name)

    # Step 4
    gui_log(text_widget, "Step 4 (su): Checking patch directory...", "step_tag")
    if not os.path.exists(patch_dir):
        # clone
        clone_cmd = ...
        rc, lines = run_command_su(child, clone_cmd)
        if rc != 0:
            raise RuntimeError("Clone failed in su mode.")
        # Now connect with our special function
        connect_cmd = f"/bin/bash {shared_script_dir}/oxe_connect.sh {patch_name}"
        rc, lines = run_su_connect_patch(child, connect_cmd)
        if rc != 0:
            raise RuntimeError("Connect script failed in su mode (did not see success_str).")
        ...
    else:
        # patch exists => connect
        connect_cmd = f"/bin/bash {shared_script_dir}/oxe_connect.sh {patch_name}"
        rc, lines = run_su_connect_patch(child, connect_cmd)
        if rc != 0:
            raise RuntimeError("Connect script failed in su mode (did not see success_str).")
        gui_log(text_widget, "Patch connected successfully (su).", "step_tag")

    # Step 5
    gui_log(text_widget, "Step 5 (su): cd build & cmake..", "step_tag")
    rc, lines = run_command_su(child, f"cd {patch_dir}/build")
    if rc != 0:
        raise RuntimeError("Could not cd to build dir in su mode.")
    rc, lines = run_su_cmake(child, "cmake ..", 
                                success_str="-- Build files have been written to")
    if rc != 0:
        raise RuntimeError("CMake.. failed in su mode.")

    # Step 6
    gui_log(text_widget, "Step 6 (su): make -j10..", "step_tag")
    rc, lines = run_su_make_compile(child, "make -j10", success_tokens=("99%", "100%"))
    if rc != 0:
        if rc == 2:
            raise RuntimeError("Compilation failed (no 99% or 100% near end) in su mode.")
        else:
            gui_log(text_widget, "Patch compiled with some errors (su). Check debug log.", "step_tag")
    else:
        gui_log(text_widget, "Compilation completed successfully (su).", "step_tag")
        remove_debug_log = True

    # Step 7
    gui_log(text_widget, "Step 7 (su): removing debug log, done.", "step_tag")
    if os.path.exists(DEBUG_LOG_FILE):
        if(remove_debug_log):
            os.remove(DEBUG_LOG_FILE)
    gui_log(text_widget, "All steps completed under su approach.", "step_tag")

    child.sendline("exit")
    child.close()
    pexpect_child = None

#
# -------------------- GUI Code --------------------
#
def on_create_patch(branch_entry, username_entry, password_entry, text_widget,
                   create_btn, stop_btn):
    global stop_requested
    stop_requested = False

    branch = branch_entry.get().strip()
    user = username_entry.get().strip()
    pwd = password_entry.get().strip()

    if not branch or not user or not pwd:
        messagebox.showwarning("Input Error", "Please fill in all fields.")
        return

    create_btn.config(state=tk.DISABLED)
    stop_btn.config(state=tk.NORMAL)

    # Clear the text area
    text_widget.config(state=tk.NORMAL)
    text_widget.delete("1.0", tk.END)
    text_widget.config(state=tk.DISABLED)

    def worker():
        global local_process, pexpect_child
        try:
            # Compare user vs current system user
            try:
                current_user = os.environ.get("USER") or os.getlogin()
            except:
                current_user = os.getenv("LOGNAME", "")

            if user == current_user:
                # local approach
                patch_creation_local(branch, user, text_widget)
            else:
                # su approach
                patch_creation_su(branch, user, pwd, text_widget)

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
    root.title("Patch Creation Tool (Steps 4–7) - Python 3")
    root.geometry("900x600")

    title_label = tk.Label(root, text="GUI Patch Creation Tool", font=("Helvetica", 18, "bold"))
    title_label.pack(pady=5)

    input_frame = tk.Frame(root)
    input_frame.pack(pady=5)

    font_label = ("Helvetica", 14)

    tk.Label(input_frame, text="Branch Name:", font=font_label).grid(row=0, column=0, padx=10, pady=5, sticky=tk.E)
    branch_entry = tk.Entry(input_frame, font=font_label, width=25)
    branch_entry.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(input_frame, text="Username:", font=font_label).grid(row=1, column=0, padx=10, pady=5, sticky=tk.E)
    username_entry = tk.Entry(input_frame, font=font_label, width=25)
    username_entry.grid(row=1, column=1, padx=10, pady=5)

    tk.Label(input_frame, text="Password:", font=font_label).grid(row=2, column=0, padx=10, pady=5, sticky=tk.E)
    password_entry = tk.Entry(input_frame, font=font_label, width=25, show="*")
    password_entry.grid(row=2, column=1, padx=10, pady=5)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)

    create_btn = tk.Button(button_frame, text="Create Patch", font=font_label,
                           command=lambda: on_create_patch(branch_entry, username_entry, password_entry,
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