#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import subprocess

try:
    import Tkinter as tk
    import ttk
    import tkMessageBox as messagebox
    import json
except ImportError:
    import tkinter as tk
    from tkinter import ttk, messagebox
    import json

# If running inside a PyInstaller .exe, we read scripts from sys._MEIPASS
if getattr(sys, 'frozen', False):
    BASE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Paths to assets
CONFIG_FILE = os.path.join(BASE_DIR, "master_config.json")
ICON_IMAGE = os.path.join(BASE_DIR, "checked.png")    # Replace with actual image if needed
BACKGROUND_IMAGE = os.path.join(BASE_DIR, "unchecked.png")  # Replace with actual image if needed
OXE_SCRIPT = os.path.join(BASE_DIR, "oxe_connect.sh")       # Path to the shell script if used

# Load configuration
try:
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
except Exception as e:
    messagebox.showerror("Error", "Failed to load config: {}".format(str(e)))
    sys.exit(1)

# Four script files, each will be embedded with --add-data
SCRIPT_PATHS = {
    "1) List Node Version": os.path.join(BASE_DIR, "List_Telnet_and_SSH_Node_version_GUI.py"),
    "2) Node Backup":       os.path.join(BASE_DIR, "Telnet_and_SSH_Node_Backup_GUI.py"),
    "3) Node Upgrade":      os.path.join(BASE_DIR, "Node_upgrade_Downgrade_GUI.py"),
    "4) Patch Creation":    os.path.join(BASE_DIR, "Patch_creation_compilation_GUI.py")
}

class MainLauncher(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Master Tool Launcher")
        self.geometry("500x420")
        self.configure(bg="#e6f2ff")  # Light pastel background

        # Keep track of processes for "Quit All Scripts"
        self.running_scripts = []

        # --- Dark Blue Header ---
        header_frame = tk.Frame(self, bg="#003366")
        header_frame.pack(fill="x")

        header_label = tk.Label(header_frame,
                                text="Node Management Tool",
                                font=("Helvetica", 18, "bold"),
                                fg="white",
                                bg="#003366",
                                padx=10,
                                pady=10)
        header_label.pack()

        # --- Subtitle ---
        sub_label = tk.Label(self,
                             text="Select an operation below:",
                             font=("Arial", 12),
                             bg="#e6f2ff",
                             fg="#333333")
        sub_label.pack(pady=(15, 10))

        # --- Buttons Frame ---
        btn_frame = tk.Frame(self, bg="#e6f2ff")
        btn_frame.pack(pady=10)

        # Create a button for each script with distinct color
        self._create_script_button(btn_frame,
            "1) List Node Version", "#009999")  # teal
        self._create_script_button(btn_frame,
            "2) Node Backup", "#cc6600")        # burnt orange
        self._create_script_button(btn_frame,
            "3) Node Upgrade", "#3366cc")       # medium blue
        self._create_script_button(btn_frame,
            "4) Patch Creation", "#990099")     # purple

        # --- Quit All Scripts Button ---
        quit_all_btn = tk.Button(self,
                                 text="Quit All Scripts",
                                 font=("Helvetica", 10, "bold"),
                                 fg="white",
                                 bg="#555555",
                                 width=18,
                                 command=self.quit_all_scripts)
        quit_all_btn.pack(pady=(10, 5))

        # --- Quit Launcher Button ---
        quit_btn = tk.Button(self,
                             text="Quit Launcher",
                             font=("Helvetica", 10, "bold"),
                             fg="white",
                             bg="#555555",
                             width=18,
                             command=self.on_quit)
        quit_btn.pack(pady=5)

    def _create_script_button(self, parent, script_key, bg_color):
        """
        Helper to create a styled button that launches a script,
        storing the process handle in self.running_scripts.
        """
        btn = tk.Button(parent,
                        text=script_key,
                        font=("Helvetica", 11, "bold"),
                        fg="white",
                        bg=bg_color,
                        width=25,
                        command=lambda: self.launch_script(script_key))
        btn.pack(pady=5)

    def launch_script(self, script_key):
        """
        Launch the selected script in a new process and store its handle.
        Using sys.executable ensures we run with the same Python environment
        that PyInstaller provides.
        """
        script_path = SCRIPT_PATHS[script_key]
        proc = subprocess.Popen([sys.executable, script_path])
        self.running_scripts.append(proc)

    def quit_all_scripts(self):
        """
        Terminates all running script processes.
        """
        for proc in self.running_scripts:
            try:
                proc.terminate()  # or proc.kill()
            except:
                pass
        self.running_scripts = []  # Clear the list

    def on_quit(self):
        """
        Closes the launcher window.
        (Doesn't kill scripts unless you call quit_all_scripts first.)
        """
        self.destroy()

if __name__ == "__main__":
    app = MainLauncher()
    app.mainloop()
