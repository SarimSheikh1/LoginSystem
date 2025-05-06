import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk, ImageSequence
import os
import json
import hashlib

class AnimatedGIF(tk.Label):
    def __init__(self, master, path, size=None):
        self.master = master
        self.path = path
        self.size = size
        
        # Load the GIF
        self.gif = Image.open(path)
        self.frames = []
        
        # Resize if needed and extract frames
        for frame in ImageSequence.Iterator(self.gif):
            if self.size:
                frame = frame.resize(self.size, Image.LANCZOS)
            self.frames.append(ImageTk.PhotoImage(frame))
        
        self.index = 0
        self.delay = self.gif.info.get('duration', 100)
        
        super().__init__(master, image=self.frames[self.index])
        self.animate()

    def animate(self):
        self.index = (self.index + 1) % len(self.frames)
        self.config(image=self.frames[self.index])
        self.after(self.delay, self.animate)

class LoginSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Login System")
        self.root.geometry("800x600")
        self.root.resizable(False, False)
        
        # Database file
        self.db_file = "users.json"
        self.users = self.load_users()
        
        # Create main container
        self.main_frame = tk.Frame(root, bg='#f0f0f0')
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left side with animated GIF
        self.left_frame = tk.Frame(self.main_frame, bg='#f0f0f0')
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Load and display animated GIF (replace with your own GIF path)
        try:
            self.animated_gif = AnimatedGIF(self.left_frame, "login_animation.gif", size=(400, 400))
            self.animated_gif.pack(pady=20)
        except:
            # Fallback if GIF not found
            self.fallback_label = tk.Label(self.left_frame, text="Animated Login", 
                                          font=("Helvetica", 24), bg='#f0f0f0')
            self.fallback_label.pack(pady=20)
        
        # Right side with login form
        self.right_frame = tk.Frame(self.main_frame, bg='#f0f0f0')
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Login form
        self.create_login_form()
        
        # Initially show login form
        self.show_login()
    
    def create_login_form(self):
        # Title
        self.title_label = tk.Label(self.right_frame, text="Welcome Back!", 
                                   font=("Helvetica", 24, "bold"), bg='#f0f0f0')
        self.title_label.pack(pady=(20, 10))
        
        # Subtitle
        self.subtitle_label = tk.Label(self.right_frame, text="Please login to continue", 
                                      font=("Helvetica", 12), bg='#f0f0f0', fg='#666')
        self.subtitle_label.pack(pady=(0, 30))
        
        # Username
        self.username_label = tk.Label(self.right_frame, text="Username:", 
                                      font=("Helvetica", 10), bg='#f0f0f0', anchor='w')
        self.username_label.pack(fill=tk.X, padx=50)
        
        self.username_entry = tk.Entry(self.right_frame, font=("Helvetica", 12))
        self.username_entry.pack(fill=tk.X, padx=50, pady=(0, 20))
        
        # Password
        self.password_label = tk.Label(self.right_frame, text="Password:", 
                                      font=("Helvetica", 10), bg='#f0f0f0', anchor='w')
        self.password_label.pack(fill=tk.X, padx=50)
        
        self.password_entry = tk.Entry(self.right_frame, font=("Helvetica", 12), show="*")
        self.password_entry.pack(fill=tk.X, padx=50, pady=(0, 20))
        
        # Login button
        self.login_button = tk.Button(self.right_frame, text="Login", 
                                     font=("Helvetica", 12, "bold"), 
                                     bg="#4CAF50", fg="white",
                                     command=self.login)
        self.login_button.pack(fill=tk.X, padx=50, pady=(10, 5))
        
        # Register button
        self.register_button = tk.Button(self.right_frame, text="Create Account", 
                                        font=("Helvetica", 10), 
                                        bg="#f0f0f0", fg="#333",
                                        command=self.show_register)
        self.register_button.pack(fill=tk.X, padx=50, pady=(5, 20))
    
    def create_register_form(self):
        # Clear the right frame
        for widget in self.right_frame.winfo_children():
            widget.destroy()
        
        # Title
        self.title_label = tk.Label(self.right_frame, text="Create Account", 
                                   font=("Helvetica", 24, "bold"), bg='#f0f0f0')
        self.title_label.pack(pady=(20, 10))
        
        # Subtitle
        self.subtitle_label = tk.Label(self.right_frame, text="Join us today!", 
                                      font=("Helvetica", 12), bg='#f0f0f0', fg='#666')
        self.subtitle_label.pack(pady=(0, 30))
        
        # Username
        self.username_label = tk.Label(self.right_frame, text="Username:", 
                                      font=("Helvetica", 10), bg='#f0f0f0', anchor='w')
        self.username_label.pack(fill=tk.X, padx=50)
        
        self.username_entry = tk.Entry(self.right_frame, font=("Helvetica", 12))
        self.username_entry.pack(fill=tk.X, padx=50, pady=(0, 20))
        
        # Password
        self.password_label = tk.Label(self.right_frame, text="Password:", 
                                      font=("Helvetica", 10), bg='#f0f0f0', anchor='w')
        self.password_label.pack(fill=tk.X, padx=50)
        
        self.password_entry = tk.Entry(self.right_frame, font=("Helvetica", 12), show="*")
        self.password_entry.pack(fill=tk.X, padx=50, pady=(0, 20))
        
        # Confirm Password
        self.confirm_password_label = tk.Label(self.right_frame, text="Confirm Password:", 
                                              font=("Helvetica", 10), bg='#f0f0f0', anchor='w')
        self.confirm_password_label.pack(fill=tk.X, padx=50)
        
        self.confirm_password_entry = tk.Entry(self.right_frame, font=("Helvetica", 12), show="*")
        self.confirm_password_entry.pack(fill=tk.X, padx=50, pady=(0, 20))
        
        # Register button
        self.register_button = tk.Button(self.right_frame, text="Register", 
                                       font=("Helvetica", 12, "bold"), 
                                       bg="#2196F3", fg="white",
                                       command=self.register)
        self.register_button.pack(fill=tk.X, padx=50, pady=(10, 5))
        
        # Back to login button
        self.login_button = tk.Button(self.right_frame, text="Already have an account? Login", 
                                     font=("Helvetica", 10), 
                                     bg="#f0f0f0", fg="#333",
                                     command=self.show_login)
        self.login_button.pack(fill=tk.X, padx=50, pady=(5, 20))
    
    def show_login(self):
        # Clear the right frame
        for widget in self.right_frame.winfo_children():
            widget.destroy()
        
        # Recreate login form
        self.create_login_form()
    
    def show_register(self):
        # Clear the right frame
        for widget in self.right_frame.winfo_children():
            widget.destroy()
        
        # Recreate register form
        self.create_register_form()
    
    def load_users(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    return {}
        return {}
    
    def save_users(self):
        with open(self.db_file, 'w') as f:
            json.dump(self.users, f)
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        if username in self.users:
            hashed_password = self.hash_password(password)
            if self.users[username] == hashed_password:
                messagebox.showinfo("Success", "Login successful!")
                # Here you would typically open the main application window
                # For this example, we'll just clear the fields
                self.username_entry.delete(0, tk.END)
                self.password_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Error", "Incorrect password")
        else:
            messagebox.showerror("Error", "Username not found")
    
    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "Please fill in all fields")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if username in self.users:
            messagebox.showerror("Error", "Username already exists")
            return
        
        # Hash the password before storing
        hashed_password = self.hash_password(password)
        self.users[username] = hashed_password
        self.save_users()
        
        messagebox.showinfo("Success", "Registration successful! You can now login.")
        self.show_login()

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginSystem(root)
    root.mainloop()