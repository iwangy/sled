import cmath
import json
import os
import sys
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import filedialog, messagebox, ttk

import pandas as pd
import requests

if getattr(sys, "frozen", False):
    Current_Path = os.path.expanduser("~")
else:
    Current_Path = os.path.dirname(__file__)

PEMFILE_PATH = "Sample/path/to/certificate.pem"
KEYFILE_PATH = "Sample/path/to/private_key.key"
GROUP_NAME = "your group here"
URL = "https://groups.uw.edu/group_sws/v3/"

CONFIG_FILE = os.path.join(Current_Path, "config.json")


def load_config():
    global PEMFILE_PATH, KEYFILE_PATH, GROUP_NAME, URL
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as file:
            config = json.load(file)
            PEMFILE_PATH = config.get("PEMFILE_PATH", PEMFILE_PATH)
            KEYFILE_PATH = config.get("KEYFILE_PATH", KEYFILE_PATH)
            GROUP_NAME = config.get("GROUP_NAME", GROUP_NAME)
            URL = config.get("ENDPOINT", URL)
    else:
        # If no config exists, create a new one with empty values
        save_config()


def save_config():
    config = {
        "PEMFILE_PATH": PEMFILE_PATH,
        "KEYFILE_PATH": KEYFILE_PATH,
        "GROUP_NAME": GROUP_NAME,
        "ENDPOINT": URL,
    }
    try:
        with open(CONFIG_FILE, "w") as file:
            json.dump(config, file)
    except OSError as e:
        print(f"Error saving config file: {e}")


def create_session():
    # Create a session with the certificate and key
    session = requests.Session()
    session.cert = (PEMFILE_PATH, KEYFILE_PATH)
    return session


load_config()
session = create_session()


def main():
    root = tk.Tk()
    root.title("SLED: UW Group Manager")
    root.geometry("600x600")

    # Create tabs using Notebook widget
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    # Create and add each tab
    group_members_page = GroupMembersPage(notebook, root)
    verify_member_page = VerifyMemberPage(notebook, root)
    add_users_page = AddUsersPage(notebook, root)
    delete_users_page = DeleteUsersPage(notebook, root)
    settings_page = SettingsPage(notebook, root)

    notebook.add(group_members_page.frame, text="Group Members")
    notebook.add(verify_member_page.frame, text="Verify NetIDs")
    notebook.add(add_users_page.frame, text="Add NetIDs")
    notebook.add(delete_users_page.frame, text="Delete NetIDs")
    notebook.add(settings_page.frame, text="Settings")

    root.mainloop()


class GroupMembersPage:
    def __init__(self, notebook, root):
        self.frame = tk.Frame(notebook)
        self.data = None
        self.root = root

        # Get Members Button
        self.get_btn = tk.Button(
            self.frame, text="Get Members", command=self.get_members
        )
        self.get_btn.grid(row=0, column=0, sticky="ew", padx=10, pady=5)

        # Export as CSV Button
        self.export_btn = tk.Button(
            self.frame, text="Export as CSV", command=self.export_csv
        )
        self.export_btn.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

        # Data Table (Treeview)
        self.tree = ttk.Treeview(self.frame, columns=("Type", "NetID"), show="headings")
        self.tree.heading("Type", text="Type")
        self.tree.heading("NetID", text="NetID")
        self.tree.grid(row=1, column=0, columnspan=2, sticky="nsew")

        # Scrollbar for Treeview
        self.scrollbar = ttk.Scrollbar(
            self.frame, orient="vertical", command=self.tree.yview
        )
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.grid(row=1, column=2, sticky="ns")

        self.frame.grid_rowconfigure(1, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)

    def get_members(self):
        try:
            response = session.get(URL + f"group/{GROUP_NAME}/member")
            response.raise_for_status()
            self.data = response.json().get("data", [])
            self.update_table()
        except OSError as e:
            if "Could not find the TLS certificate file" in str(e):
                messagebox.showerror(
                    "Error",
                    "Could not find the TLS certificate file. Please add your cert and private key.",
                )
            else:
                messagebox.showerror("Error", str(e))

    def update_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for member in self.data:
            self.tree.insert("", "end", values=(member.get("type"), member.get("id")))

    def export_csv(self):
        if not self.data:
            messagebox.showwarning("Warning", "No data to export.")
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV files", "*.csv")]
        )
        if filepath:
            df = pd.DataFrame(self.data)
            df.to_csv(filepath, index=False)
            messagebox.showinfo("Exported", f"Data exported to {filepath}")


class VerifyMemberPage:
    def __init__(self, notebook, root):
        self.frame = tk.Frame(notebook)
        self.users = []
        self.root = root

        # Label for NetIDs input
        self.netid_label = tk.Label(self.frame, text="NetIDs (one per line):")
        self.netid_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        # Text widget for multiple NetIDs input
        self.netid_entry = tk.Text(self.frame, height=10, width=40, wrap="none")
        self.netid_entry.grid(
            row=1, column=0, columnspan=3, padx=5, pady=5, sticky="nsew"
        )

        # Check entry content dynamically
        self.netid_entry.bind("<KeyRelease>", self.check_input)

        # Verify button
        self.netid_verify_btn = tk.Button(
            self.frame, text="Verify", command=self.verify_netids
        )
        self.netid_verify_btn.grid(row=2, column=0, padx=5, pady=5, sticky="ew")

        # Import button
        self.import_btn = tk.Button(
            self.frame, text="Import NetIDs", command=self.import_csv
        )
        self.import_btn.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        # Export button, initially disabled
        self.export_btn = tk.Button(
            self.frame,
            text="Export Results",
            command=self.export_results,
            state=tk.DISABLED,
        )
        self.export_btn.grid(row=2, column=2, padx=5, pady=5, sticky="ew")

        # Treeview for displaying verification results
        self.tree = ttk.Treeview(
            self.frame, columns=("NetID", "Status"), show="headings"
        )
        self.tree.heading("NetID", text="NetID")
        self.tree.heading("Status", text="Status")
        self.tree.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        # Configure the layout to be responsive
        self.frame.grid_rowconfigure(1, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_columnconfigure(1, weight=1)
        self.frame.grid_columnconfigure(2, weight=1)

    def verify_netids(self):
        netids = self.netid_entry.get("1.0", "end-1c").strip().splitlines()
        self.tree.delete(*self.tree.get_children())  # Clear the Treeview

        for netid in netids:
            netid = netid.strip()
            if netid:  # Skip empty lines
                try:
                    reqURL = URL + f"group/{GROUP_NAME}/member/{netid}"
                    response = session.get(reqURL)
                    response.raise_for_status()

                    result_message = f"Member"
                except requests.exceptions.HTTPError as http_err:
                    if response.status_code == 404:
                        result_message = f"Non-Member"
                    else:
                        result_message = "An unexpected error occurred."
                except requests.exceptions.RequestException as e:
                    result_message = f"Could not verify {netid}: {e}"
                    status = "Error"

                # Insert result into Treeview
                self.tree.insert("", "end", values=(netid, result_message))

    def import_csv(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filepath:
            try:
                df = pd.read_csv(filepath)
                self.users = df["id"].tolist()
                self.netid_entry.delete("1.0", tk.END)  # Clear the textbox
                self.netid_entry.insert("1.0", "\n".join(self.users))
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file: {e}")

    def export_results(self):
        # Open a file dialog to choose the export location
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if file_path:
            with open(file_path, "w") as file:
                file.write("NetID,Status\n")  # Write the header
                for item in self.tree.get_children():
                    netid, status = self.tree.item(item)["values"]
                    file.write(f"{netid},{status}\n")  # Write each result
            messagebox.showinfo("Export Successful", f"Results exported to {file_path}")

    def check_input(self, event):
        # Enable Add Users button if there is text in the entry box
        if self.netid_entry.get("1.0", "end-1c").strip():
            self.export_btn.config(state=tk.NORMAL)
        else:
            self.export_btn.config(state=tk.DISABLED)


class AddUsersPage:
    def __init__(self, notebook, root):
        self.frame = tk.Frame(notebook)
        self.users = []
        self.root = root

        # Import from CSV button
        self.import_csv_btn = tk.Button(
            self.frame, text="Import CSV", command=self.import_csv
        )
        self.import_csv_btn.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        # Manual Entry Label and Text Box
        self.manual_entry_label = tk.Label(
            self.frame, text="or paste NetIDs (one per line):"
        )
        self.manual_entry_label.grid(row=0, column=1, sticky="w", padx=5)

        self.user_entry = tk.Text(self.frame, height=10, undo=True)
        self.user_entry.grid(
            row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5
        )

        # Add Users Button
        self.add_users_btn = tk.Button(
            self.frame, text="Add NetIDs to Group", command=self.confirm_add_users
        )
        self.add_users_btn.grid(
            row=3, column=0, columnspan=2, sticky="ew", padx=5, pady=5
        )

        self.progress = ttk.Progressbar(
            self.frame, orient="horizontal", length=200, mode="determinate"
        )
        self.progress.grid(row=4, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        # Allow the text box to expand
        self.frame.grid_rowconfigure(2, weight=1)
        # Allow button column to expand
        self.frame.grid_columnconfigure(0, weight=1)
        # Allow label column to expand
        self.frame.grid_columnconfigure(1, weight=1)

        # Initially disable Add Users button
        self.add_users_btn.config(state=tk.DISABLED)

        # Monitor changes in the text box to enable the button
        self.user_entry.bind("<KeyRelease>", self.check_input)

    def import_csv(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filepath:
            try:
                df = pd.read_csv(filepath)
                self.users = df["id"].tolist()
                self.user_entry.delete("1.0", tk.END)  # Clear the textbox
                self.user_entry.insert("1.0", "\n".join(self.users))

                if self.users:  # Ensure there are user IDs
                    self.add_users_btn.config(state=tk.NORMAL)
                else:
                    self.add_users_btn.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file: {e}")

    def check_input(self, event):
        # Enable Add Users button if there is text in the entry box
        if self.user_entry.get("1.0", "end-1c").strip():
            self.add_users_btn.config(state=tk.NORMAL)
        else:
            self.add_users_btn.config(state=tk.DISABLED)

    def confirm_add_users(self):
        try:
            user_ids = self.user_entry.get("1.0", "end-1c").splitlines()
            self.users = [user_id.strip() for user_id in user_ids if user_id.strip()]
            if messagebox.askyesno(
                "Confirm",
                f"Are you sure you want to add {len(self.users)} users to {GROUP_NAME} ?",
            ):
                self.start_add_users_thread()
        except OSError as e:
            if "Could not find the TLS certificate file" in str(e):
                messagebox.showerror(
                    "Error",
                    "Could not find the TLS certificate file. Please add your cert and private key.",
                )
            else:
                messagebox.showerror("Error", str(e))

    def start_add_users_thread(self):
        self.add_users_btn.config(state=tk.DISABLED)
        thread = threading.Thread(target=self.add_users)
        thread.start()

    def add_users(self):
        try:
            self.progress["value"] = 0
            self.frame.update_idletasks()

            user_ids = self.user_entry.get("1.0", "end-1c").splitlines()
            self.users = [user_id.strip() for user_id in user_ids if user_id.strip()]
            results = []

            total_users = len(self.users)
            batch_size = 10  # Controls the number of users processed in parallel

            # Using ThreadPoolExecutor to handle multiple users concurrently
            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                futures = {
                    executor.submit(self.add_user_to_group, user_id): user_id
                    for user_id in self.users
                }

                for i, future in enumerate(as_completed(futures)):
                    time.sleep(0.1)
                    result = future.result()
                    results.append(result)
                    self.progress.after(0, self.update_progress, i + 1, total_users)

            self.show_results(results, "added")
        except Exception as e:
            error = e
            self.root.after(0, lambda: messagebox.showerror("Error", error))
        finally:
            # Re-enable the button and hide the progress bar
            self.add_users_btn.config(state=tk.NORMAL)
            self.progress["value"] = 0

    def add_user_to_group(self, user_id):
        try:
            reqURL = URL + f"group/{GROUP_NAME}/member/{user_id}"
            response = session.put(reqURL)

            # Check for 401 Unauthorized error specifically
            if response.status_code == 401:
                messagebox.showerror("Authorization Error", "The account associated with this Cert is not a Group Manager")
                return  # Quit the operation on 401
            
            response.raise_for_status()
            return f"{user_id}"
        except requests.exceptions.RequestException as e:
            error_message = f"Could not add user {user_id}: {e}"
            self.root.after(
                0,
                lambda: messagebox.showerror("Error", error_message),
            )

    def update_progress(self, current_user, total_users):
        """Update the progress bar to reflect the current progress."""
        progress = int((current_user / total_users) * 100)
        self.progress["value"] = progress
        self.frame.update_idletasks()  # Update the progress bar visually

    def show_results(self, results, action):
        # Display results in a messagebox
        results_message = str(len(results))
        messagebox.showinfo(
            f"Add Users Results", "Successfully added " + results_message + " NetIDs"
        )


class DeleteUsersPage:
    def __init__(self, notebook, root):
        self.frame = tk.Frame(notebook)
        self.users = []
        self.root = root

        # Import from CSV button
        self.import_csv_btn = tk.Button(
            self.frame, text="Import CSV", command=self.import_csv
        )
        self.import_csv_btn.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        # Manual Entry Label and Text Box
        self.manual_entry_label = tk.Label(
            self.frame, text=" or paste NetIDs (one per line):"
        )
        self.manual_entry_label.grid(row=0, column=1, sticky="w", padx=5)

        self.user_entry = tk.Text(self.frame, height=10, undo=True)
        self.user_entry.grid(
            row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5
        )

        # Delete Users Button
        self.delete_users_btn = tk.Button(
            self.frame,
            text="Delete NetIDs from Group",
            command=self.confirm_delete_users,
        )
        self.delete_users_btn.grid(
            row=3, column=0, columnspan=2, sticky="ew", padx=5, pady=5
        )

        self.progress = ttk.Progressbar(
            self.frame, orient="horizontal", length=200, mode="determinate"
        )
        self.progress.grid(row=4, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        # Allow the text box to expand
        self.frame.grid_rowconfigure(2, weight=1)
        # Allow button column to expand
        self.frame.grid_columnconfigure(0, weight=1)
        # Allow label column to expand
        self.frame.grid_columnconfigure(1, weight=1)

        # Initially disable Delete Users button
        self.delete_users_btn.config(state=tk.DISABLED)

        # Monitor changes in the text box to enable the button
        self.user_entry.bind("<KeyRelease>", self.check_input)

    def import_csv(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if filepath:
            try:
                df = pd.read_csv(filepath)
                self.users = df["id"].tolist()
                self.user_entry.delete("1.0", tk.END)  # Clear the textbox
                self.user_entry.insert("1.0", "\n".join(self.users))

                if self.users:  # Ensure there are user IDs
                    self.delete_users_btn.config(state=tk.NORMAL)
                else:
                    self.delete_users_btn.config(state=tk.DISABLED)

            except Exception as e:
                messagebox.showerror("Error", f"Could not read file: {e}")

    def check_input(self, event):
        # Enable Add Users button if there is text in the entry box
        if self.user_entry.get("1.0", "end-1c").strip():
            self.delete_users_btn.config(state=tk.NORMAL)
        else:
            self.delete_users_btn.config(state=tk.DISABLED)

    def confirm_delete_users(self):
        try:
            user_ids = self.user_entry.get("1.0", "end-1c").splitlines()
            self.users = [user_id.strip() for user_id in user_ids if user_id.strip()]
            if messagebox.askyesno(
                "Confirm",
                f"Are you sure you want to delete {len(self.users)} users from {GROUP_NAME}?",
            ):
                self.start_delete_users_thread()
        except OSError as e:
            if "Could not find the TLS certificate file" in str(e):
                messagebox.showerror(
                    "Error",
                    "Could not find the TLS certificate file. Please add your cert and private key.",
                )
            else:
                messagebox.showerror("Error", str(e))

    def start_delete_users_thread(self):
        self.delete_users_btn.config(state=tk.DISABLED)
        thread = threading.Thread(target=self.delete_users)
        thread.start()

    def delete_users(self):
        try:
            self.progress["value"] = 0
            self.frame.update_idletasks()

            user_ids = self.user_entry.get("1.0", "end-1c").splitlines()
            self.users = [user_id.strip() for user_id in user_ids if user_id.strip()]
            results = []

            total_users = len(self.users)
            batch_size = 10  # Controls the number of users processed in parallel

            # Using ThreadPoolExecutor to handle multiple users concurrently
            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                futures = {
                    executor.submit(self.delete_user_from_group, user_id): user_id
                    for user_id in self.users
                }

                for i, future in enumerate(as_completed(futures)):
                    time.sleep(0.1)
                    result = (
                        future.result()
                    )  # Result of add_user_to_group, could be True/False
                    results.append(result)
                    self.progress.after(0, self.update_progress, i + 1, total_users)
                    self.frame.update_idletasks()

            # Show a completion message
            self.show_results(results, "deleted")
        except Exception as e:
            # messagebox.showerror("Error", str(e))
            self.root.after(0, lambda: messagebox.showerror("Error", e))
        finally:
            # Re-enable the button and hide the progress bar
            self.delete_users_btn.config(state=tk.NORMAL)
            self.progress["value"] = 0

    def delete_user_from_group(self, user_id):
        try:
            reqURL = URL + f"group/{GROUP_NAME}/member/{user_id}"
            response = session.delete(reqURL)

            # Check for 401 Unauthorized error specifically
            if response.status_code == 401:
                messagebox.showerror("Authorization Error", "The account associated with this Cert is not a Group Manager")
                return  # Quit the operation on 401
        
            response.raise_for_status()
            return f"{user_id}"
        except requests.exceptions.RequestException as e:
            error_message = f"Could not delete user {user_id}: {e}"
            self.root.after(
                0,
                lambda: messagebox.showerror("Error", error_message),
            )

    def update_progress(self, current_user, total_users):
        """Update the progress bar to reflect the current progress."""
        progress = int((current_user / total_users) * 100)
        self.progress["value"] = progress
        self.frame.update_idletasks()  # Update the progress bar visually

    def show_results(self, results, action):
        # Display results in a messagebox
        results_message = str(len(results))
        messagebox.showinfo(
            f"Delete Users Results",
            "Successfully deleted " + results_message + " NetIDs",
        )


class SettingsPage:
    def __init__(self, notebook, root):
        self.frame = tk.Frame(notebook)

        # Group Name Label and Entry
        self.group_name_label = tk.Label(self.frame, text="Group Name:")
        self.group_name_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.group_name_entry = tk.Entry(self.frame)
        self.group_name_entry.insert(0, GROUP_NAME)
        self.group_name_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # PEM and Key file paths
        self.pem_path_label = tk.Label(self.frame, text="Cert File Path:")
        self.pem_path_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.pem_path_entry = tk.Entry(self.frame)
        self.pem_path_entry.insert(0, PEMFILE_PATH)
        self.pem_path_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        self.pem_browse_btn = tk.Button(
            self.frame, text="Browse", command=self.browse_pem
        )
        self.pem_browse_btn.grid(row=1, column=2, padx=5, pady=5)

        self.key_path_label = tk.Label(self.frame, text="Key File Path:")
        self.key_path_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.key_path_entry = tk.Entry(self.frame)
        self.key_path_entry.insert(0, KEYFILE_PATH)
        self.key_path_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        self.key_browse_btn = tk.Button(
            self.frame, text="Browse", command=self.browse_key
        )
        self.key_browse_btn.grid(row=2, column=2, padx=5, pady=5)

        # Dropdown Menu for Selecting a Setting
        self.endpoint_label = tk.Label(self.frame, text="Select API Endpoint:")
        self.endpoint_label.grid(row=3, column=0, padx=5, pady=5, sticky="w")

        self.endpoint_combobox = ttk.Combobox(self.frame)
        self.endpoint_combobox["values"] = [
            "https://groups.uw.edu/group_sws/v3/",
            "https://eval.groups.uw.edu/group_sws/v3/",
            "https://dev.groups.uw.edu/group_sws/v3/",
            "https://iam-ws.u.washington.edu/group_sws/v3/",
        ]
        self.endpoint_combobox.set(URL)
        self.endpoint_combobox.grid(row=3, column=1, padx=5, pady=5, sticky="ew")

        # Save Button to update settings
        self.save_button = tk.Button(
            self.frame, text="Save Settings", command=self.save_settings
        )
        self.save_button.grid(row=4, column=0, columnspan=2, pady=10)

        # Configure column expansion
        self.frame.grid_columnconfigure(1, weight=1)

    def browse_pem(self):
        try:
            file_path = filedialog.askopenfilename(
                filetypes=[("Certificate files", "*cer")]
            )
            if file_path:
                self.pem_path_entry.delete(0, tk.END)  # Clear existing path
                self.pem_path_entry.insert(0, file_path)  # Insert the new path
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}")

    def browse_key(self):
        try:
            file_path = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])
            if file_path:
                self.key_path_entry.delete(0, tk.END)  # Clear existing path
                self.key_path_entry.insert(0, file_path)  # Insert the new path
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"{e}")

    def save_settings(self):
        global GROUP_NAME, PEMFILE_PATH, KEYFILE_PATH, URL
        GROUP_NAME = self.group_name_entry.get().strip()
        PEMFILE_PATH = self.pem_path_entry.get().strip()
        KEYFILE_PATH = self.key_path_entry.get().strip()
        URL = self.endpoint_combobox.get()

        # Update the session's certificate with new paths
        session.cert = (PEMFILE_PATH, KEYFILE_PATH)
        save_config()
        # Confirm the settings have been saved
        messagebox.showinfo("Settings Saved", "Your settings have been updated.")


if __name__ == "__main__":
    main()
