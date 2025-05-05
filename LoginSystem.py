import tkinter as tk
from tkinter import messagebox
import hashlib
import os

class LoginSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Login System with Gender Selection")
        self.root.geometry("450x400")
        
        # Database file (stores username, password hash, and gender)
        self.db_file = "users.db"
        self.users = {}  # Format: {username: {"password": hash, "gender": "M/F/O"}}
        self.load_users()
        
        self.current_user = None
        self.create_login_widgets()

    def load_users(self):
        """Load users from database file"""
        if os.path.exists(self.db_file):
            with open(self.db_file, "r") as f:
                for line in f:
                    if line.strip():
                        username, pwd_hash, gender = line.strip().split(",")
                        self.users[username] = {"password": pwd_hash, "gender": gender}

    def save_users(self):
        """Save users to database file"""
        with open(self.db_file, "w") as f:
            for username, data in self.users.items():
                f.write(f"{username},{data['password']},{data['gender']}\n")

    def create_login_widgets(self):
        """Login screen widgets"""
        self.clear_window()
        
        tk.Label(self.root, text="Login", font=("Arial", 16)).pack(pady=15)
        
        # Username
        tk.Label(self.root, text="Username:").pack()
        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack(pady=5)
        
        # Password
        tk.Label(self.root, text="Password:").pack()
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=5)
        
        # Login Button
        tk.Button(self.root, text="Login", command=self.login).pack(pady=10)
        
        # Register Button
        tk.Button(self.root, text="Register New Account", command=self.create_register_widgets).pack()

    def create_register_widgets(self):
        """Registration screen with gender selection"""
        self.clear_window()
        
        tk.Label(self.root, text="Register", font=("Arial", 16)).pack(pady=15)
        
        # Username
        tk.Label(self.root, text="Username:").pack()
        self.reg_username_entry = tk.Entry(self.root)
        self.reg_username_entry.pack(pady=5)
        
        # Password
        tk.Label(self.root, text="Password:").pack()
        self.reg_password_entry = tk.Entry(self.root, show="*")
        self.reg_password_entry.pack(pady=5)
        
        # Confirm Password
        tk.Label(self.root, text="Confirm Password:").pack()
        self.reg_confirm_entry = tk.Entry(self.root, show="*")
        self.reg_confirm_entry.pack(pady=5)
        
        # Gender Selection
        tk.Label(self.root, text="Gender:").pack()
        self.gender_var = tk.StringVar(value="O")  # Default: Other
        
        gender_frame = tk.Frame(self.root)
        gender_frame.pack(pady=5)
        
        tk.Radiobutton(gender_frame, text="Male", variable=self.gender_var, value="M").pack(side=tk.LEFT)
        tk.Radiobutton(gender_frame, text="Female", variable=self.gender_var, value="F").pack(side=tk.LEFT)
        tk.Radiobutton(gender_frame, text="Other", variable=self.gender_var, value="O").pack(side=tk.LEFT)
        
        # Register Button
        tk.Button(self.root, text="Register", command=self.register).pack(pady=10)
        
        # Back to Login
        tk.Button(self.root, text="Back to Login", command=self.create_login_widgets).pack()

    def login(self):
        """Handle login"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        if username in self.users:
            # In a real app, you would hash the input password and compare hashes
            if self.users[username]["password"] == self.simple_hash(password):  # Simple demo
                self.current_user = username
                gender = self.users[username]["gender"]
                gender_text = {"M": "Male", "F": "Female", "O": "Other"}.get(gender, "Other")
                messagebox.showinfo("Success", f"Welcome {username}!\nGender: {gender_text}")
            else:
                messagebox.showerror("Error", "Invalid password")
        else:
            messagebox.showerror("Error", "Username not found")

    def register(self):
        """Handle registration with gender"""
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()
        gender = self.gender_var.get()
        
        if not username or not password or not confirm:
            messagebox.showerror("Error", "All fields are required")
            return
            
        if password != confirm:
            messagebox.showerror("Error", "Passwords don't match")
            return
            
        if username in self.users:
            messagebox.showerror("Error", "Username already exists")
            return
            
        # Store user data (in real app, store password hash only)
        self.users[username] = {
            "password": self.simple_hash(password),
            "gender": gender
        }
        self.save_users()
        
        messagebox.showinfo("Success", "Registration successful!")
        self.create_login_widgets()

    def simple_hash(self, password):
        """Simple demo hashing - in real apps use proper hashing like bcrypt"""
        return hashlib.sha256(password.encode()).hexdigest()

    def clear_window(self):
        """Clear all widgets from window"""
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginSystem(root)
    root.mainloop()