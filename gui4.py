import os
import subprocess
import tkinter as tk
from tkinter import ttk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox

# ========== Helper Functions ==========
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout + result.stderr
    except Exception as e:
        return str(e)

def scan_directory():
    path = filedialog.askdirectory()
    if path:
        scan_output.delete(1.0, "end")
        scan_output.insert("end", f"Scanning directory: {path}\n")
        output = run_command(f"bash permission_audit_modified2.sh --target \"{path}\"")
        scan_output.insert("end", output)

def fix_permissions():
    output = run_command("bash permission_audit_modified2.sh --fix ")
    messagebox.showinfo("Fix Permissions", output)

def undo_changes():
    output = run_command("bash undo.sh")
    messagebox.showinfo("Undo Changes", output)

def set_custom_permission():
    path = filedialog.askopenfilename()
    if path:
        permission = custom_permission_entry.get()
        if permission:
            output = run_command(f"chmod {permission} \"{path}\"")
            messagebox.showinfo("Custom Permission", output)
        else:
            messagebox.showwarning("Input Required", "Enter a permission code (e.g., 755)")

def change_ownership():
    path = filedialog.askopenfilename()
    if path:
        user = user_entry.get()
        group = group_entry.get()
        if user and group:
            output = run_command(f"chown {user}:{group} \"{path}\"")
            messagebox.showinfo("Change Ownership", output)
        else:
            messagebox.showwarning("Input Required", "Enter both username and group")

# ========== GUI Setup ==========
app = ttk.Window(themename="flatly")
app.title("Linux Permission Repair Utility")
app.geometry("920x720")
app.resizable(False, False)

# ========== Banner ==========
# banner_text = run_command("bash permission_audit_modified2.sh --banner")
# help_text = run_command("permission_audit_modified2.sh --help")

# banner_frame = ttk.Frame(app, padding=10)
# banner_frame.pack(fill='x')

# banner_label = ttk.Label(banner_frame, text=banner_text.strip(), font=("Courier", 10, "bold"), foreground="#00d1b2")
# banner_label.pack(anchor="center")

# ========== Help Section ==========
help_frame = ttk.Labelframe(app, text="📖 Help Menu", padding=10)
help_frame.pack(fill='x', padx=10, pady=(0, 10))

help_textbox = ttk.Text(help_frame, wrap="word", height=8, font=("Courier", 9))
#help_textbox.insert("1.0", help_text.strip())

#---------------
help_textbox.pack(fill='x')

try:
    result = subprocess.run(["bash", "permission_audit_modified2.sh", "--helpforgui"], capture_output=True, text=True, check=True)
    help_output = result.stdout
except subprocess.CalledProcessError as e:
    help_output = f"Failed to load help: {e}"

help_textbox.configure(state="normal")  # Make it writable
help_textbox.insert("1.0", help_output.strip())
help_textbox.configure(state="disabled")  # Make it read-only again


# help_textbox.configure(state="disabled")
# help_textbox.pack(fill='x')

# ========== Notebook ==========
notebook = ttk.Notebook(app)
notebook.pack(fill='both', expand=True, padx=15, pady=15)

# ========== Tab 1: Scan ==========
tab_scan = ttk.Frame(notebook)
notebook.add(tab_scan, text="📁 Scan")

scan_frame = ttk.Frame(tab_scan, padding=10)
scan_frame.pack(fill='both', expand=True)

scan_btn = ttk.Button(scan_frame, text="Scan Directory", bootstyle=SUCCESS, command=scan_directory)
scan_btn.grid(row=0, column=0, pady=10, sticky="w")


text_scroll_frame = ttk.Frame(scan_frame)
text_scroll_frame.grid(row=1, column=0, pady=10)

# Create the Text widget
scan_output = ttk.Text(text_scroll_frame, wrap="word", height=28, width=105, bg="#1e1e1e", fg="white")
scan_output.pack(side="left", fill="both", expand=True)

# Add vertical scrollbar
scrollbar = ttk.Scrollbar(text_scroll_frame, orient="vertical", command=scan_output.yview)
scrollbar.pack(side="right", fill="y")

# Link Text widget to scrollbar
scan_output.configure(yscrollcommand=scrollbar.set)


# scan_output = ttk.Text(scan_frame, wrap="word", height=28, width=105, background="#1e1e1e", foreground="white")
# scan_output.grid(row=1, column=0, pady=10)

# ========== Tab 2: Fix & Undo ==========
tab_fix = ttk.Frame(notebook)
notebook.add(tab_fix, text="🛠️ Fix & Undo")

fix_frame = ttk.Frame(tab_fix, padding=40)
fix_frame.pack(expand=True)

fix_btn = ttk.Button(fix_frame, text="Fix Permissions", bootstyle=PRIMARY, width=25, command=fix_permissions)
fix_btn.grid(row=0, column=0, pady=15)

undo_btn = ttk.Button(fix_frame, text="Undo Changes", bootstyle=WARNING, width=25, command=undo_changes)
undo_btn.grid(row=1, column=0, pady=15)

# ========== Tab 3: Custom Permissions ==========
tab_custom = ttk.Frame(notebook)
notebook.add(tab_custom, text="🔧 Custom Permissions")

perm_frame = ttk.Frame(tab_custom, padding=40)
perm_frame.pack(expand=True)

ttk.Label(perm_frame, text="Permission (e.g. 755):", font=("Helvetica", 11)).grid(row=0, column=0, pady=5, sticky='w')
custom_permission_entry = ttk.Entry(perm_frame, width=30)
custom_permission_entry.grid(row=1, column=0, pady=5)

custom_btn = ttk.Button(perm_frame, text="Set Custom Permission", bootstyle=INFO, width=25, command=set_custom_permission)
custom_btn.grid(row=2, column=0, pady=20)

# ========== Tab 4: Change Ownership ==========
tab_owner = ttk.Frame(notebook)
notebook.add(tab_owner, text="👤 Change Ownership")

owner_frame = ttk.Frame(tab_owner, padding=40)
owner_frame.pack(expand=True)

ttk.Label(owner_frame, text="Username:", font=("Helvetica", 11)).grid(row=0, column=0, pady=5, sticky='w')
user_entry = ttk.Entry(owner_frame, width=30)
user_entry.grid(row=1, column=0, pady=5)

ttk.Label(owner_frame, text="Group:", font=("Helvetica", 11)).grid(row=2, column=0, pady=5, sticky='w')
group_entry = ttk.Entry(owner_frame, width=30)
group_entry.grid(row=3, column=0, pady=5)

owner_btn = ttk.Button(owner_frame, text="Change Ownership", bootstyle=SECONDARY, width=25, command=change_ownership)
owner_btn.grid(row=4, column=0, pady=20)

app.mainloop()
