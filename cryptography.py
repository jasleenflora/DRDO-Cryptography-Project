import tkinter as tk
from tkinter import ttk
import random
import string
import csv
import tempfile
import os

# Cipher Definitions
stream_ciphers = {
    "RC4": {"key_size_bits": "Variable", "block_size_bits": "N/A"},
    "A5/1": {"key_size_bits": "64 (Key stream)", "block_size_bits": "64 (Keystream)"}
}

block_ciphers = {
    "SM4": {"key_size_bits": "128", "block_size_bits": "128"},
    "HIGHT": {"key_size_bits": "128", "block_size_bits": "64"},
    "PRESENT": {"key_size_bits": "80 or 128", "block_size_bits": "64"}
}

# GUI Setup
def update_description(cipher_name):
    description_label.config(text=f"{cipher_name}")

def select_cipher_type(event):
    selected_cipher_type = cipher_type.get()
    if selected_cipher_type == "Stream Cipher":
        cipher
import tkinter as tk
from tkinter import ttk
import random
import string
import csv
import tempfile
import os

# Cipher Definitions
stream_ciphers = {
    "RC4": {"key_size_bits": "Variable", "block_size_bits": "N/A"},
    "A5/1": {"key_size_bits": "64 (Key stream)", "block_size_bits": "64 (Keystream)"}
}

block_ciphers = {
    "SM4": {"key_size_bits": "128", "block_size_bits": "128"},
    "HIGHT": {"key_size_bits": "128", "block_size_bits": "64"},
    "PRESENT": {"key_size_bits": "80 or 128", "block_size_bits": "64"}
}

# GUI Setup
def update_description(cipher_name):
    description_label.config(text=f"{cipher_name}")

def select_cipher_type(event):
    selected_cipher_type = cipher_type.get()
    if selected_cipher_type == "Stream Cipher":
        cipher
import tkinter as tk
from tkinter import ttk
import random
import string
import csv
import tempfile
import os

# Cipher Definitions
stream_ciphers = {
    "RC4": {"key_size_bits": "Variable", "block_size_bits": "N/A"},
    "A5/1": {"key_size_bits": "64 (Key stream)", "block_size_bits": "64 (Keystream)"}
}

block_ciphers = {
    "SM4": {"key_size_bits": "128", "block_size_bits": "128"},
    "HIGHT": {"key_size_bits": "128", "block_size_bits": "64"},
    "PRESENT": {"key_size_bits": "80 or 128", "block_size_bits": "64"}
}

# GUI Setup
def update_description(cipher_name):
    description_label.config(text=f"{cipher_name}")

def select_cipher_type(event):
    selected_cipher_type = cipher_type.get()
    if selected_cipher_type == "Stream Cipher":
        cipher_menu["menu"].delete(0, "end")
        for cipher in stream_ciphers.keys():
            cipher_menu["menu"].add_command(label=cipher, command=tk._setit(cipher_var, cipher))
        cipher_var.set(list(stream_ciphers.keys())[0])
    elif selected_cipher_type == "Block Cipher":
        cipher_menu["menu"].delete(0, "end")
        for cipher in block_ciphers.keys():
            cipher_menu["menu"].add_command(label=cipher, command=tk._setit(cipher_var, cipher))
        cipher_var.set(list(block_ciphers.keys())[0])
    update_description(cipher_var.get())

def start_action():
    file_size_value = file_size_entry.get().strip()

    if not file_size_value.isdigit() or int(file_size_value) <= 0:
        result_label.config(text="Please enter a valid file size (positive integer).", foreground="red")
        return

    file_size = int(file_size_value)
    num_rows = 10 ** file_size

    start_button.config(state=tk.DISABLED)
    result_label.config(text="", foreground="black")
    progress_bar.start()
    progress_bar_label.config(text="Generating Cipher...")
    root.update_idletasks()

    random_data = generate_random_data(num_rows)

    selected_cipher = cipher_var.get()

    with tempfile.NamedTemporaryFile(delete=False, suffix='.csv') as temp_file:
        temp_file_name = temp_file.name
        write_to_csv(temp_file_name, random_data)

    progress_bar.stop()
    progress_bar_label.config(text="")
    start_button.config(state=tk.NORMAL)
    result_label.config(text=f"{selected_cipher} generated successfully with {num_rows} rows of 8-byte key streams.",
                        foreground="green")

    open_popup(temp_file_name)

def generate_random_data(num_rows):
    random_data = []
    for _ in range(num_rows):
        key_stream = ''.join(random.choices(string.hexdigits.lower(), k=16))  # 16 characters for 8 bytes
        random_data.append([key_stream])
    return random_data

def write_to_csv(file_name, data):
    with open(file_name, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Key Stream"])
        for row in data:
            writer.writerow(row)

def open_popup(file_name):
    popup = tk.Toplevel()
    popup.title(f"{file_name} - Random Key Streams")
    popup.geometry("600x600")

    with open(file_name, 'r') as file:
        content = file.readlines()[1:]  # Read all lines except the first one (header)

    text_widget = tk.Text(popup, wrap="none")
    text_widget.insert(tk.END, ''.join(content))
    text_widget.pack(fill=tk.BOTH, expand=True)

    input_label = tk.Label(popup, text="Enter Text:")
    input_label.pack()

    plaintext_entry = tk.Entry(popup, width=50)
    plaintext_entry.pack()

    encrypt_button = tk.Button(popup, text="Encrypt", command=lambda: perform_encryption(plaintext_entry.get(), content))
    encrypt_button.pack(pady=5)

    decrypt_button = tk.Button(popup, text="Decrypt", command=lambda: perform_decryption(plaintext_entry.get(), content))
    decrypt_button.pack(pady=5)

    result_text = tk.Text(popup, wrap="none")
    result_text.pack(fill=tk.BOTH, expand=True)

    def perform_encryption(plaintext, key_streams_content):
        if not plaintext:
            result_text.insert(tk.END, "Please enter text for encryption.\n")
            return

        key_streams = [line.strip() for line in key_streams_content]
        selected_cipher = cipher_var.get()

        if selected_cipher == "RC4":
            ciphertext = rc4_encrypt(plaintext, key_streams)
            result_text.insert(tk.END, "Encrypted Data (RC4):\n")
            result_text.insert(tk.END, ''.join(ciphertext).upper() + "\n")
        elif selected_cipher == "A5/1":
            ciphertext = a5_1_encrypt(plaintext, key_streams)
            result_text.insert(tk.END, "Encrypted Data (A5/1):\n")
            result_text.insert(tk.END, ''.join(ciphertext).upper() + "\n")
        else:
            ciphertext = xor_encrypt(plaintext, key_streams)
            result_text.insert(tk.END, "Encrypted Data (XOR):\n")
            result_text.insert(tk.END, ''.join(ciphertext).upper() + "\n")

    def perform_decryption(ciphertext, key_streams_content):
        if not ciphertext:
            result_text.insert(tk.END, "Please enter ciphertext for decryption.\n")
            return

        key_streams = [line.strip() for line in key_streams_content]
        selected_cipher = cipher_var.get()

        if selected_cipher == "RC4":
            decrypted_plaintext = rc4_decrypt(ciphertext, key_streams)
            result_text.insert(tk.END, "Decrypted Data (RC4):\n")
            result_text.insert(tk.END, decrypted_plaintext + "\n")
        elif selected_cipher == "A5/1":
            decrypted_plaintext = a5_1_decrypt(ciphertext, key_streams)
            result_text.insert(tk.END, "Decrypted Data (A5/1):\n")
            result_text.insert(tk.END, decrypted_plaintext + "\n")
        else:
            decrypted_plaintext = xor_decrypt(ciphertext, key_streams)
            result_text.insert(tk.END, "Decrypted Data (XOR):\n")
            result_text.insert(tk.END, decrypted_plaintext + "\n")

    popup.protocol("WM_DELETE_WINDOW", lambda: (os.remove(file_name), popup.destroy()))

def xor_encrypt(plaintext, key_streams):
    ciphertext = []
    key_streams = [bytes.fromhex(key) for key in key_streams]
    for i, char in enumerate(plaintext):
        key_stream = key_streams[i % len(key_streams)]
        char_byte = ord(char)
        key_byte = key_stream[i % len(key_stream)]
        xor_byte = char_byte ^ key_byte
        ciphertext.append(f"{xor_byte:02x}")
    return ciphertext

def xor_decrypt(ciphertext, key_streams):
    plaintext = []
    key_streams = [bytes.fromhex(key) for key in key_streams]
    ciphertext_bytes = bytes.fromhex(ciphertext)
    for i, byte in enumerate(ciphertext_bytes):
        key_stream = key_streams[i % len(key_streams)]
        key_byte = key_stream[i % len(key_stream)]
        plaintext.append(chr(byte ^ key_byte))
    return ''.join(plaintext)

def rc4_encrypt(plaintext, key_streams):
    key = key_streams[0]
    key_bytes = bytes.fromhex(key)
    s = list(range(256))
    j = 0
    out = []

    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + s[i] + key_bytes[i % len(key_bytes)]) % 256
        s[i], s[j] = s[j], s[i]

    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out.append(f"{ord(char) ^ k:02x}")

    return out

def rc4_decrypt(ciphertext, key_streams):
    key = key_streams[0]
    key_bytes = bytes.fromhex(key)
    s = list(range(256))
    j = 0
    out = []

    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + s[i] + key_bytes[i % len(key_bytes)]) % 256
        s[i], s[j] = s[j], s[i]

    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    ciphertext_bytes = bytes.fromhex(ciphertext)
    for byte in ciphertext_bytes:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out.append(chr(byte ^ k))

    return ''.join(out)

def a5_1_encrypt(plaintext, key_streams):
    key = key_streams[0]
    key_bytes = bytes.fromhex(key)
    s = list(range(256))
    j = 0
    out = []

    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + s[i] + key_bytes[i % len(key_bytes)]) % 256
        s[i], s[j] = s[j], s[i]

    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    for char in plaintext:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out.append(f"{ord(char) ^ k:02x}")

    return out

def a5_1_decrypt(ciphertext, key_streams):
    key = key_streams[0]
    key_bytes = bytes.fromhex(key)
    s = list(range(256))
    j = 0
    out = []

    # Key-scheduling algorithm (KSA)
    for i in range(256):
        j = (j + s[i] + key_bytes[i % len(key_bytes)]) % 256
        s[i], s[j] = s[j], s[i]

    # Pseudo-random generation algorithm (PRGA)
    i = j = 0
    ciphertext_bytes = bytes.fromhex(ciphertext)
    for byte in ciphertext_bytes:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out.append(chr(byte ^ k))

    return ''.join(out)

# Main GUI Setup
root = tk.Tk()
root.title("Data Generator")
root.geometry("500x450")

bg_color = "#7e57c2"
root.configure(background=bg_color)

cipher_types = ["Stream Cipher", "Block Cipher"]
cipher_type = tk.StringVar(root)
cipher_type.set(cipher_types[0])

cipher_type_label = ttk.Label(root, text="Select Cipher Type:", background=bg_color, foreground="white",
                              font=("Helvetica", 12, "bold"))
cipher_type_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

cipher_type_menu = ttk.OptionMenu(root, cipher_type, cipher_types[0], *cipher_types, command=select_cipher_type)
cipher_type_menu.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

cipher_var = tk.StringVar(root)
cipher_var.set(list(stream_ciphers.keys())[0])

cipher_label = ttk.Label(root, text="Select Cipher:", background=bg_color, foreground="white",
                         font=("Helvetica", 12, "bold"))
cipher_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")

cipher_menu = ttk.OptionMenu(root, cipher_var, list(stream_ciphers.keys())[0], *list(stream_ciphers.keys()))
cipher_menu.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

file_size_label = ttk.Label(root, text="Enter File Size (in 10^x):", background=bg_color, foreground="white",
                            font=("Helvetica", 12, "bold"))
file_size_label.grid(row=3, column=0, padx=10, pady=10, sticky="w")

file_size_entry = ttk.Entry(root, width=20, font=("Helvetica", 12))
file_size_entry.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

result_label = ttk.Label(root, text="", background=bg_color, foreground="green", font=("Helvetica", 12))
result_label.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="w")

progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="indeterminate")
progress_bar.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

progress_bar_label = ttk.Label(root, text="", background=bg_color, foreground="white", font=("Helvetica", 12))
progress_bar_label.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="w")

start_button = ttk.Button(root, text="Start", command=start_action, style="Accent.TButton")
start_button.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

instructions_label = ttk.Label(root,
                               text="Select a cipher type, cipher, enter file size (in 10^x), and click Start to generate a random cipher CSV file.",
                               background=bg_color, foreground="white", font=("Helvetica", 10))
instructions_label.grid(row=8, column=0, columnspan=2, padx=10, pady=10, sticky="w")

description_label = ttk.Label(root, text="", background=bg_color, foreground="white", font=("Helvetica", 10))
description_label.grid(row=9, column=0, columnspan=2, padx=10, pady=10, sticky="w")

root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)

style = ttk.Style()
style.configure("Accent.TButton", foreground="black", background="#4CAF50", font=("Helvetica", 12, "bold"))

select_cipher_type(None)  # Initialize the cipher dropdown based on the default cipher type

root.mainloop()