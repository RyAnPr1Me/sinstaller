# GUI for Secure Installer
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, simpledialog
import os
import json
import threading
import queue

def run_gui(main_callback):
    root = tk.Tk()
    root.title("Secure Installer")
    root.geometry("900x650")
    root.configure(bg="#23272e")
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background="#23272e", foreground="#f8f8f2", fieldbackground="#23272e", bordercolor="#44475a")
    style.configure('TButton', background="#0078d7", foreground="#f8f8f2", borderwidth=2, focusthickness=3, focuscolor='none', font=("Segoe UI", 11, "bold"))
    style.map('TButton', background=[('active', '#005a9e')])
    style.configure('TLabel', background="#23272e", foreground="#f8f8f2", font=("Segoe UI", 11))
    style.configure('TEntry', fieldbackground="#282a36", foreground="#f8f8f2", font=("Segoe UI", 11))
    style.configure('TCheckbutton', background="#23272e", foreground="#f8f8f2", font=("Segoe UI", 11))
    style.configure('TLabelframe', background="#23272e", foreground="#f8f8f2", font=("Segoe UI", 12, "bold"))
    style.configure('Treeview', background="#282a36", fieldbackground="#282a36", foreground="#f8f8f2", font=("Segoe UI", 10))
    style.configure('Treeview.Heading', background="#0078d7", foreground="#f8f8f2", font=("Segoe UI", 11, "bold"))

    frame = ttk.Frame(root, padding=20)
    frame.pack(expand=True, fill='both')

    # Title and logo
    title_frame = ttk.Frame(frame)
    title_frame.pack(fill='x', pady=(0, 10))
    logo = tk.PhotoImage(width=1, height=1)  # Placeholder for logo
    logo_label = tk.Label(title_frame, image=logo, bg="#23272e")
    logo_label.pack(side=tk.LEFT, padx=(0, 10))
    label = ttk.Label(title_frame, text="Secure Installer", font=("Segoe UI", 28, "bold"))
    label.pack(side=tk.LEFT, anchor='w')

    # Input area
    input_frame = ttk.LabelFrame(frame, text="Source (URL(s), File, or Folder)", padding=10)
    input_frame.pack(fill='x', pady=10)
    entry = ttk.Entry(input_frame, font=("Segoe UI", 12), width=60)
    entry.pack(side=tk.LEFT, padx=5, pady=5, expand=True, fill='x')
    ttk.Button(input_frame, text="Browse File", command=lambda: entry.insert(0, filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")]))).pack(side=tk.LEFT, padx=5)
    ttk.Button(input_frame, text="Browse Folder", command=lambda: entry.insert(0, filedialog.askdirectory())).pack(side=tk.LEFT, padx=5)
    ttk.Button(input_frame, text="Paste URLs", command=lambda: entry.insert(0, root.clipboard_get())).pack(side=tk.LEFT, padx=5)

    # Install options
    options_frame = ttk.LabelFrame(frame, text="Install Options", padding=10)
    options_frame.pack(pady=10, fill='x')
    scan_var = tk.BooleanVar(value=True)
    sandbox_var = tk.BooleanVar(value=True)
    sig_var = tk.BooleanVar(value=True)
    unsigned_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(options_frame, text="Scan with Windows Defender", variable=scan_var).pack(side=tk.LEFT, padx=10)
    ttk.Checkbutton(options_frame, text="Run in Sandbox", variable=sandbox_var).pack(side=tk.LEFT, padx=10)
    ttk.Checkbutton(options_frame, text="Require Digital Signature", variable=sig_var).pack(side=tk.LEFT, padx=10)
    ttk.Checkbutton(options_frame, text="Allow Unsigned Installers (Override)", variable=unsigned_var).pack(side=tk.LEFT, padx=10)

    # Progress bar
    progress = tk.DoubleVar(value=0)
    progress_bar = ttk.Progressbar(frame, variable=progress, maximum=100, length=800, mode='determinate')
    progress_bar.pack(pady=10, fill='x')

    # Results table
    table_frame = ttk.LabelFrame(frame, text="Installer Results", padding=10)
    table_frame.pack(pady=10, fill='both', expand=True)
    columns = ("File", "Status", "Hash", "Thumbprint", "Signed", "Scan", "Sandbox", "Install", "Error")
    tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=8)
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=110, anchor='w')
    tree.pack(fill='both', expand=True)

    # Status bar
    status_var = tk.StringVar(value="Ready.")
    status_bar = ttk.Label(root, textvariable=status_var, anchor='w', background="#23272e", foreground="#f8f8f2")
    status_bar.pack(side=tk.BOTTOM, fill='x')

    # Results log
    results_frame = ttk.LabelFrame(frame, text="Log / Timeline / Blocklist Events", padding=10)
    results_frame.pack(pady=10, fill='both', expand=True)
    results_text = tk.Text(results_frame, height=7, bg="#282a36", fg="#f8f8f2", wrap='word', font=("Consolas", 10))
    results_text.pack(fill='both', expand=True)

    # Buttons
    btn2_frame = ttk.Frame(frame)
    btn2_frame.pack(pady=5)
    ttk.Button(btn2_frame, text="Clear Results", command=lambda: (results_text.delete(1.0, tk.END), [tree.delete(row) for row in tree.get_children()], status_var.set("Results cleared."))).pack(side=tk.LEFT, padx=5)
    ttk.Button(btn2_frame, text="Export Log", command=lambda: export_log(results_text, status_var)).pack(side=tk.LEFT, padx=5)

    # Menu
    menu = tk.Menu(root)
    root.config(menu=menu)
    tools_menu = tk.Menu(menu, tearoff=0)
    menu.add_cascade(label="Tools", menu=tools_menu)
    tools_menu.add_command(label="Show Blocklist", command=lambda: show_blocklist(status_var))
    tools_menu.add_command(label="Show Installer Log", command=lambda: show_installer_log(status_var))
    tools_menu.add_separator()
    tools_menu.add_command(label="About", command=lambda: show_about(status_var))

    # Helper functions
    def export_log(results_text, status_var):
        log_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if log_path:
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write(results_text.get(1.0, tk.END))
            status_var.set(f"Log exported to {log_path}")

    def show_blocklist(status_var):
        try:
            with open('blocklist.json', 'r', encoding='utf-8') as f:
                data = f.read()
            messagebox.showinfo("Blocklist", data)
        except Exception as e:
            messagebox.showerror("Blocklist", str(e))
            status_var.set("Failed to load blocklist.")

    def show_installer_log(status_var):
        try:
            with open('installer_behavior_log.jsonl', 'r', encoding='utf-8') as f:
                data = f.read()
            messagebox.showinfo("Installer Log", data[:5000] + ("..." if len(data) > 5000 else ""))
        except Exception as e:
            messagebox.showerror("Installer Log", str(e))
            status_var.set("Failed to load installer log.")

    def show_about(status_var):
        messagebox.showinfo("About", "Secure Installer\nVersion 1.0\n© 2025")
        status_var.set("About shown.")

    def show_result(msg, status=None):
        tag = 'success' if status == 'success' else 'error' if status == 'error' else None
        results_text.insert(tk.END, msg + "\n", tag)
        results_text.see(tk.END)
        status_var.set(msg)

    results_text.tag_config('error', foreground='#ff5555')
    results_text.tag_config('success', foreground='#50fa7b')

    def start_install():
        source = entry.get().strip()
        if not source:
            messagebox.showerror("Error", "Please enter a URL or select a file/folder.")
            return
        opts = {
            'scan': scan_var.get(),
            'sandbox': sandbox_var.get(),
            'sig': sig_var.get(),
            'allow_unsigned': unsigned_var.get()
        }
        # Clear previous results
        results_text.delete(1.0, tk.END)
        for row in tree.get_children():
            tree.delete(row)
        status_var.set("Starting installation...")
        def gui_progress(val):
            progress.set(val)
            progress_bar.update()
        def gui_result(msg, status=None):
            show_result(msg, status)
        threading.Thread(target=main_callback, args=(source, opts, gui_progress, gui_result)).start()

    ttk.Button(btn2_frame, text="Install", command=start_install).pack(side=tk.LEFT, padx=5)

    root.mainloop()
