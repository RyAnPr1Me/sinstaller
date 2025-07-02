# GUI for Secure Installer
def run_gui(main_callback):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk, simpledialog
    import os
    import json
    import threading
    import queue
    root = tk.Tk()
    root.title("Secure Installer")
    root.geometry("950x700")
    # --- Improved Google-inspired GUI ---
    root.option_add('*Font', 'Segoe UI 12')
    root.tk.call('tk', 'scaling', 1.2)
    root.configure(bg="#18191A")
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background="#18191A", foreground="#E4E6EB", fieldbackground="#242526", bordercolor="#3A3B3C")
    style.configure('TButton', background="#242526", foreground="#E4E6EB", borderwidth=0, focusthickness=3, focuscolor='none', font=("Segoe UI", 12, "bold"), relief='flat')
    style.map('TButton', background=[('active', '#2D88FF'), ('pressed', '#1A73E8')], foreground=[('active', '#fff')])
    style.configure('TLabel', background="#18191A", foreground="#E4E6EB", font=("Segoe UI", 13))
    style.configure('TEntry', fieldbackground="#242526", foreground="#E4E6EB", font=("Segoe UI", 13), borderwidth=0)
    style.configure('TFrame', background="#18191A")
    style.configure('TLabelframe', background="#18191A", foreground="#E4E6EB", font=("Segoe UI", 13, "bold"), borderwidth=0)
    style.configure('TLabelframe.Label', background="#18191A", foreground="#E4E6EB", font=("Segoe UI", 13, "bold"))
    style.configure('Treeview', background="#242526", fieldbackground="#242526", foreground="#E4E6EB", rowheight=32, font=("Segoe UI", 12))
    style.configure('Treeview.Heading', background="#18191A", foreground="#2D88FF", font=("Segoe UI", 13, "bold"))
    style.map('Treeview', background=[('selected', '#2D88FF')], foreground=[('selected', '#fff')])
    style.configure('TCheckbutton', background="#18191A", foreground="#E4E6EB", font=("Segoe UI", 12))
    style.map('TCheckbutton', background=[('active', '#23272A')])
    style.configure('TProgressbar', background="#2D88FF", troughcolor="#242526", bordercolor="#18191A", thickness=8)

    frame = ttk.Frame(root, padding=32)
    frame.pack(expand=True, fill='both')

    label = ttk.Label(frame, text="Secure Installer", font=("Google Sans", 32, "bold"), anchor='center', foreground="#2D88FF")
    label.pack(pady=(0, 18))

    entry = ttk.Entry(frame, font=("Segoe UI", 14), width=60)
    entry.pack(pady=10, ipady=6)
    entry.focus_set()

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
            progress_bar.update_idletasks()
        def gui_result(msg, status=None):
            show_result(msg, status)
            root.update_idletasks()
        threading.Thread(target=main_callback, args=(source, opts, gui_progress, gui_result)).start()

    btn_frame = ttk.Frame(frame)
    btn_frame.pack(pady=10)
    browse_file_btn = ttk.Button(btn_frame, text="Browse File", command=lambda: entry.insert(0, filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")]))
    )
    scan_var = tk.BooleanVar(value=True)
    sandbox_var = tk.BooleanVar(value=True)
    sig_var = tk.BooleanVar(value=True)
    unsigned_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(options_frame, text="Scan with Windows Defender", variable=scan_var, style='TCheckbutton').pack(anchor='w')
    ttk.Checkbutton(options_frame, text="Run in Sandbox", variable=sandbox_var, style='TCheckbutton').pack(anchor='w')
    ttk.Checkbutton(options_frame, text="Require Digital Signature", variable=sig_var, style='TCheckbutton').pack(anchor='w')
    ttk.Checkbutton(options_frame, text="Allow Unsigned Installers (Override)", variable=unsigned_var, style='TCheckbutton').pack(anchor='w')

    table_frame = ttk.LabelFrame(frame, text="Installer Results", padding=10)
    table_frame.pack(pady=10, fill='both', expand=True)
    columns = ("File", "Status", "Hash", "Thumbprint", "Signed", "Scan", "Sandbox", "Install", "Error")
    tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=10, style='Treeview')
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=120, anchor='w')
    tree.pack(fill='both', expand=True)

    status_var = tk.StringVar(value="Ready.")
    status_bar = ttk.Label(root, textvariable=status_var, anchor='w', background="#18191A", foreground="#E4E6EB", font=("Segoe UI", 11))
    status_bar.pack(side=tk.BOTTOM, fill='x')

    results_frame = ttk.LabelFrame(frame, text="Log / Timeline / Blocklist Events", padding=10)
    results_frame.pack(pady=10, fill='both', expand=True)
    results_text = tk.Text(results_frame, height=8, bg="#242526", fg="#E4E6EB", wrap='word', font=("Consolas", 11))
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
    tools_menu.add_separator()
    tools_menu.add_command(label="Create Desktop Shortcut", command=create_desktop_shortcut)

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

    def create_desktop_shortcut():
        import sys
        import os
        import winshell
        from win32com.client import Dispatch
        desktop = winshell.desktop()
        shortcut_path = os.path.join(desktop, "Secure Installer.lnk")
        target = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
        icon = os.path.abspath("icon.ico") if os.path.exists("icon.ico") else target
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = os.path.dirname(target)
        shortcut.IconLocation = icon
        shortcut.Arguments = '--gui'
        shortcut.save()
        messagebox.showinfo("Shortcut Created", f"Desktop shortcut created at:\n{shortcut_path}")

    results_text.tag_config('error', foreground='#ff5555')
    results_text.tag_config('success', foreground='#50fa7b')

    root.mainloop()
