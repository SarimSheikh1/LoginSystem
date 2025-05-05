import tkinter as tk
from tkinter import messagebox

# File to store user credentials
USER_DATABASE = "users.txt"

class LoginSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Login System")
        self.root.geometry("400x300")
        
        # Initialize user database
        self.users = {}
        self.load_users()
        
        # Create widgets
        self.create_login_widgets()
    
    def load_users(self):
        """Load users from the database file"""
        try:
            with open(USER_DATABASE, "r") as file:
                for line in file:
                    username, password = line.strip().split(",")
                    self.users[username] = password
        except FileNotFoundError:
            # File doesn't exist yet, will be created when first user registers
            pass
    
    def save_users(self):
        """Save users to the database file"""
        with open(USER_DATABASE, "w") as file:
            for username, password in self.users.items():
                file.write(f"{username},{password}\n")
    
    def create_login_widgets(self):
        """Create the login screen widgets"""
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Title
        tk.Label(self.root, text="Login System", font=("Arial", 16)).pack(pady=20)
        
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
        tk.Button(self.root, text="Register", command=self.create_register_widgets).pack()
    
    def create_register_widgets(self):
        """Create the registration screen widgets"""
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Title
        tk.Label(self.root, text="Register New Account", font=("Arial", 16)).pack(pady=20)
        
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
        
        # Register Button
        tk.Button(self.root, text="Register", command=self.register).pack(pady=10)
        
        # Back to Login Button
        tk.Button(self.root, text="Back to Login", command=self.create_login_widgets).pack()
    
    def login(self):
        """Handle login attempt"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        if username in self.users and self.users[username] == password:
            messagebox.showinfo("Success", "Login successful!")
            # Here you would typically open the main application window
            # For this example, we'll just show a success message
        else:
            messagebox.showerror("Error", "Invalid username or password")
    
    def register(self):
        """Handle new user registration"""
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        confirm = self.reg_confirm_entry.get()
        
        if not username or not password or not confirm:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if username in self.users:
            messagebox.showerror("Error", "Username already exists")
            return
        
        # Add new user
        self.users[username] = password
        self.save_users()
        
        messagebox.showinfo("Success", "Registration successful! You can now login.")
        self.create_login_widgets()

# Create and run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = LoginSystem(root)
    root.mainloop()