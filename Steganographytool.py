import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk  # For modern widgets like progress bar
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
import zlib
import threading

# AES encryption with random IV and secure password hashing
def encrypt_message(message, password):
    salt = b'secure_salt'  # Ideally, this should be randomly generated and stored
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    compressed_message = zlib.compress(message.encode('utf-8'))
    encrypted_message = cipher.encrypt(pad(compressed_message, AES.block_size))
    return iv + encrypted_message

# AES decryption
def decrypt_message(encrypted_message, password):
    salt = b'secure_salt'  # Use the same salt as encryption
    key = PBKDF2(password, salt, dkLen=32, count=1000000)
    iv = encrypted_message[:AES.block_size]
    encrypted_message = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return zlib.decompress(decrypted_message).decode('utf-8')

# Encode message into image
def encode_message(image_path, message, output_image_path, delimiter='1111111111111110', password=None):
    try:
        img = Image.open(image_path)
        img_data = np.array(img)

        if password:
            # Encrypt message if a password is provided
            message = encrypt_message(message, password)
            message = ''.join(format(byte, '08b') for byte in message)
        else:
            # Compress and then convert to binary
            compressed_message = zlib.compress(message.encode('utf-8'))
            message = ''.join(format(byte, '08b') for byte in compressed_message)

        binary_message = message + delimiter
        if len(binary_message) > img_data.size:
            raise ValueError("Message is too large to fit in the image.")

        flat_img_data = img_data.flatten()

        for i in range(len(binary_message)):
            flat_img_data[i] = (flat_img_data[i] & 0xFE) | int(binary_message[i])

        encoded_img_data = flat_img_data.reshape(img_data.shape)
        encoded_img = Image.fromarray(encoded_img_data.astype(np.uint8))
        encoded_img.save(output_image_path)

        return "Message successfully encoded and saved in " + output_image_path

    except Exception as e:
        return str(e)

# Decode message from image
def decode_message(image_path, delimiter='1111111111111110', password=None):
    try:
        img = Image.open(image_path)
        img_data = np.array(img)

        flat_img_data = img_data.flatten()
        binary_message = ''.join(str(flat_img_data[i] & 1) for i in range(len(flat_img_data)))

        if delimiter in binary_message:
            binary_message = binary_message[:binary_message.index(delimiter)]
        else:
            raise ValueError("No hidden message found or invalid delimiter.")

        # Process the binary message based on whether it is encrypted
        if password:
            # Attempt to decrypt the binary message
            byte_message = bytearray(int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8))
            try:
                return decrypt_message(byte_message, password)
            except Exception:
                raise ValueError("The message appears to be encrypted, but the password is incorrect or image was not encoded with encryption.")
        else:
            # Decompress the binary message if not encrypted
            try:
                byte_message = bytearray(int(binary_message[i:i+8], 2) for i in range(0, len(binary_message), 8))
                message = zlib.decompress(byte_message).decode('utf-8')
                return message
            except zlib.error:
                raise ValueError("The message was not compressed correctly. Please ensure it was encoded without encryption.")

    except Exception as e:
        return str(e)

# GUI Implementation with better UI/UX and threading for responsiveness
class SteganographyGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool")
        self.root.geometry("600x400")
        self.root.configure(bg="#f7f7f7")  # Light gray background

        # Header with modern font and color
        self.header = tk.Label(root, text="Steganography Tool", font=("Helvetica", 20, "bold"), bg="#4caf50", fg="white", pady=15)
        self.header.pack(fill=tk.X)

        # Status bar for feedback with neutral color
        self.status_label = tk.Label(root, text="Welcome to the Steganography Tool", font=("Arial", 12), bg="#f7f7f7", fg="black")
        self.status_label.pack(pady=10)

        # Encode and Decode Button Frame
        self.encode_decode_frame = tk.Frame(root, bg="#f7f7f7")
        self.encode_decode_frame.pack(pady=20)

        # Stylish Encode Button
        self.encode_btn = tk.Button(self.encode_decode_frame, text="Encode Message", font=("Arial", 12), bg="#00796b", fg="grey", width=20, height=3,
                                    bd=0, relief="raised", activebackground="#004d40", activeforeground="white", command=self.encode_message_gui)
        self.encode_btn.grid(row=0, column=0, padx=10, pady=10)

        # Stylish Decode Button
        self.decode_btn = tk.Button(self.encode_decode_frame, text="Decode Message", font=("Arial", 12), bg="#0288d1", fg="grey", width=20, height=3,
                                    bd=0, relief="raised", activebackground="#01579b", activeforeground="white", command=self.decode_message_gui)
        self.decode_btn.grid(row=0, column=1, padx=10, pady=10)

        # Adding hover effect
        self.encode_btn.bind("<Enter>", lambda e: self.on_hover(self.encode_btn, "#005c51"))
        self.encode_btn.bind("<Leave>", lambda e: self.on_leave(self.encode_btn, "#00796b"))
        self.decode_btn.bind("<Enter>", lambda e: self.on_hover(self.decode_btn, "#01579b"))
        self.decode_btn.bind("<Leave>", lambda e: self.on_leave(self.decode_btn, "#0288d1"))

        # Progress bar for encoding/decoding process with better aesthetics and percentage label
        style = ttk.Style()
        style.configure("TProgressbar", thickness=20, troughcolor='#e0e0e0', background='#4caf50')
        self.progress = ttk.Progressbar(root, mode='determinate', length=250, style="TProgressbar")
        self.progress.pack(pady=20)

        

    def on_hover(self, button, color):
        button.configure(bg=color)

    def on_leave(self, button, color):
        button.configure(bg=color)

    def start_progress(self):
        self.progress['value'] = 0
        self.progress.start()

    def stop_progress(self):
        self.progress.stop()


    def run_in_thread(self, target):
        threading.Thread(target=target).start()

    def encode_message_gui(self):
        image_path = filedialog.askopenfilename(title="Select Image", filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
        if not image_path:
            return

        message = simpledialog.askstring("Input", "Enter the message to encode:")
        if message is None:
            return

        output_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if not output_image_path:
            return

        use_encryption = messagebox.askyesno("Encryption", "Do you want to encrypt the message?")
        password = None
        if use_encryption:
            password = self.ask_password()
            if password is None or len(password) not in [16, 24, 32]:
                messagebox.showerror("Error", "Invalid password length! Must be 16, 24, or 32 characters.")
                return

        self.start_progress()
        self.run_in_thread(lambda: self.encode_task(image_path, message, output_image_path, password))

    def encode_task(self, image_path, message, output_image_path, password):
        
        result = encode_message(image_path, message, output_image_path, password=password)
        self.stop_progress()
        if "successfully" in result:
            messagebox.showinfo("Success", result)
        else:
            messagebox.showerror("Error", result)

    def decode_message_gui(self):
        image_path = filedialog.askopenfilename(title="Select Encoded Image", filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
        if not image_path:
            return

        use_encryption = messagebox.askyesno("Encryption", "Was the message encrypted?")
        password = None
        if use_encryption:
            password = self.ask_password()
            if password is None or len(password) not in [16, 24, 32]:
                messagebox.showerror("Error", "Invalid password length! Must be 16, 24, or 32 characters.")
                return

        self.start_progress()
        self.run_in_thread(lambda: self.decode_task(image_path, password))

    def decode_task(self, image_path, password):

        result = decode_message(image_path, password=password)
        self.stop_progress()
        if "No hidden message" in result or "error" in result:
            messagebox.showerror("Error", result)
        else:
            messagebox.showinfo("Decoded Message", result)

    def ask_password(self):
        password_var = tk.StringVar()
        password_window = tk.Toplevel(self.root)
        password_window.title("Enter Password")
        password_window.geometry("300x150")

        tk.Label(password_window, text="Enter password:", pady=10).pack()
        password_entry = tk.Entry(password_window, textvariable=password_var, show='*', width=25)
        password_entry.pack(pady=10)

        show_password_var = tk.BooleanVar()
        show_password_check = tk.Checkbutton(password_window, text="Show Password", variable=show_password_var, command=lambda: self.toggle_password_visibility(password_entry, show_password_var))
        show_password_check.pack()

        tk.Button(password_window, text="OK", command=lambda: self.on_password_ok(password_window, password_var)).pack(pady=4)

        password_window.transient(self.root)
        password_window.grab_set()
        self.root.wait_window(password_window)

        return password_var.get()

    def toggle_password_visibility(self, entry, show_var):
        entry.config(show='' if show_var.get() else '*')

    def on_password_ok(self, window, password_var):
        password = password_var.get()
        if password:
            window.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyGUI(root)
    root.mainloop()
