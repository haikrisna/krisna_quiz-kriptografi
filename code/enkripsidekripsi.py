import tkinter as tk
from tkinter import filedialog, messagebox
import string
import math
import numpy as np

# Vigenère Cipher Implementation
def vigenere_encrypt(plaintext, key):
    plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
    key = ''.join(filter(str.isalpha, key.upper()))
    ciphertext = ''
    key_length = len(key)
    for i, char in enumerate(plaintext):
        shift = ord(key[i % key_length]) - ord('A')
        encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        ciphertext += encrypted_char
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    ciphertext = ''.join(filter(str.isalpha, ciphertext.upper()))
    key = ''.join(filter(str.isalpha, key.upper()))
    plaintext = ''
    key_length = len(key)
    for i, char in enumerate(ciphertext):
        shift = ord(key[i % key_length]) - ord('A')
        decrypted_char = chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
        plaintext += decrypted_char
    return plaintext

# Playfair Cipher Implementation
def playfair_create_matrix(key):
    key = ''.join(filter(str.isalpha, key.upper())).replace('J', 'I')
    seen = set()
    matrix = []
    for char in key:
        if char not in seen:
            seen.add(char)
            matrix.append(char)
    for char in string.ascii_uppercase:
        if char == 'J':
            continue
        if char not in seen:
            seen.add(char)
            matrix.append(char)
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_process_text(text, encrypt=True):
    text = ''.join(filter(str.isalpha, text.upper())).replace('J', 'I')
    processed = ''
    i = 0
    while i < len(text):
        a = text[i]
        b = ''
        if (i + 1) < len(text):
            b = text[i + 1]
            if a == b:
                b = 'X'
                i += 1
            else:
                i += 2
        else:
            b = 'X'
            i += 1
        processed += a + b
    return processed

def playfair_encrypt(plaintext, key_matrix):
    plaintext = playfair_process_text(plaintext, encrypt=True)
    ciphertext = ''
    for i in range(0, len(plaintext), 2):
        a, b = plaintext[i], plaintext[i+1]
        pos_a = next((r, c) for r in range(5) for c in range(5) if key_matrix[r][c] == a)
        pos_b = next((r, c) for r in range(5) for c in range(5) if key_matrix[r][c] == b)
        if pos_a[0] == pos_b[0]:
            ciphertext += key_matrix[pos_a[0]][(pos_a[1] + 1) % 5]
            ciphertext += key_matrix[pos_b[0]][(pos_b[1] + 1) % 5]
        elif pos_a[1] == pos_b[1]:
            ciphertext += key_matrix[(pos_a[0] + 1) % 5][pos_a[1]]
            ciphertext += key_matrix[(pos_b[0] + 1) % 5][pos_b[1]]
        else:
            ciphertext += key_matrix[pos_a[0]][pos_b[1]]
            ciphertext += key_matrix[pos_b[0]][pos_a[1]]
    return ciphertext

def playfair_decrypt(ciphertext, key_matrix):
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i+1]
        pos_a = next((r, c) for r in range(5) for c in range(5) if key_matrix[r][c] == a)
        pos_b = next((r, c) for r in range(5) for c in range(5) if key_matrix[r][c] == b)
        if pos_a[0] == pos_b[0]:
            plaintext += key_matrix[pos_a[0]][(pos_a[1] - 1) % 5]
            plaintext += key_matrix[pos_b[0]][(pos_b[1] - 1) % 5]
        elif pos_a[1] == pos_b[1]:
            plaintext += key_matrix[(pos_a[0] - 1) % 5][pos_a[1]]
            plaintext += key_matrix[(pos_b[0] - 1) % 5][pos_b[1]]
        else:
            plaintext += key_matrix[pos_a[0]][pos_b[1]]
            plaintext += key_matrix[pos_b[0]][pos_a[1]]
    return plaintext

# Hill Cipher Implementation
def hill_matrix(key, size):
    key = ''.join(filter(str.isalpha, key.upper()))
    key_numbers = [ord(char) - ord('A') for char in key]
    matrix = []
    for i in range(size):
        row = key_numbers[i*size:(i+1)*size]
        matrix.append(row)
    return np.array(matrix)

def mod_inverse(matrix, modulus):
    det = int(round(np.linalg.det(matrix))) 
    det = det % modulus
    inv_det = None
    for i in range(modulus):
        if (det * i) % modulus == 1:
            inv_det = i
            break
    if inv_det is None:
        return None
    adjugate = np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    inv_matrix = (inv_det * adjugate) % modulus
    return inv_matrix

def hill_encrypt(plaintext, key, size):
    plaintext = ''.join(filter(str.isalpha, plaintext.upper()))
    # Padding
    while len(plaintext) % size != 0:
        plaintext += 'X'
    key_matrix = hill_matrix(key, size)
    ciphertext = ''
    for i in range(0, len(plaintext), size):
        block = [ord(char) - ord('A') for char in plaintext[i:i+size]]
        cipher_block = np.dot(key_matrix, block) % 26
        ciphertext += ''.join([chr(num + ord('A')) for num in cipher_block])
    return ciphertext

def hill_decrypt(ciphertext, key, size):
    key_matrix = hill_matrix(key, size)
    inv_matrix = mod_inverse(key_matrix, 26)
    if inv_matrix is None:
        raise ValueError("Key matrix is not invertible modulo 26.")
    plaintext = ''
    for i in range(0, len(ciphertext), size):
        block = [ord(char) - ord('A') for char in ciphertext[i:i+size]]
        plain_block = np.dot(inv_matrix, block) % 26
        plaintext += ''.join([chr(int(num) + ord('A')) for num in plain_block])
    return plaintext

# GUI Implementation using Tkinter
class CipherGUI:
    def __init__(self, master):
        self.master = master
        master.title("Cipher GUI")
        master.geometry("800x600")

        # Cipher Selection
        self.cipher_label = tk.Label(master, text="Pilih Cipher:")
        self.cipher_label.pack()

        self.cipher_var = tk.StringVar(value="Vigenere")
        self.ciphers = ["Vigenere", "Playfair", "Hill"]
        self.cipher_menu = tk.OptionMenu(master, self.cipher_var, *self.ciphers)
        self.cipher_menu.pack()

        # Message Input
        self.message_label = tk.Label(master, text="Masukkan Pesan:")
        self.message_label.pack()

        self.message_text = tk.Text(master, height=10, width=80)
        self.message_text.pack()

        self.upload_button = tk.Button(master, text="Unggah File .txt", command=self.upload_file)
        self.upload_button.pack()

        # Key Input
        self.key_label = tk.Label(master, text="Masukkan Kunci (min 12 karakter):")
        self.key_label.pack()

        self.key_entry = tk.Entry(master, width=50, show='*')
        self.key_entry.pack()

        # Encrypt and Decrypt Buttons
        self.button_frame = tk.Frame(master)
        self.button_frame.pack(pady=10)

        self.encrypt_button = tk.Button(self.button_frame, text="Enkripsi", command=self.encrypt)
        self.encrypt_button.grid(row=0, column=0, padx=10)

        self.decrypt_button = tk.Button(self.button_frame, text="Dekripsi", command=self.decrypt)
        self.decrypt_button.grid(row=0, column=1, padx=10)

        # Output
        self.output_label = tk.Label(master, text="Hasil:")
        self.output_label.pack()

        self.output_text = tk.Text(master, height=10, width=80)
        self.output_text.pack()

        self.save_button = tk.Button(master, text="Simpan Hasil ke File", command=self.save_file)
        self.save_button.pack()

    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.message_text.delete(1.0, tk.END)
                    self.message_text.insert(tk.END, content)
            except Exception as e:
                messagebox.showerror("Error", f"Tidak dapat membuka file: {e}")

    def save_file(self):
        content = self.output_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning("Warning", "Tidak ada hasil untuk disimpan.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    file.write(content)
                messagebox.showinfo("Success", "Hasil berhasil disimpan.")
            except Exception as e:
                messagebox.showerror("Error", f"Tidak dapat menyimpan file: {e}")

    def validate_key(self, key, cipher):
        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal 12 karakter.")
            return False
        if cipher == "Hill":
            size = int(math.sqrt(len(key)))
            if size * size != len(key):
                messagebox.showerror("Error", "Untuk Hill Cipher, panjang kunci harus merupakan kuadrat sempurna (mis. 16 karakter untuk 4x4 matrix).")
                return False
            try:
                key_matrix = hill_matrix(key, size)
                inv_matrix = mod_inverse(key_matrix, 26)
                if inv_matrix is None:
                    messagebox.showerror("Error", "Kunci untuk Hill Cipher tidak invertibel modulo 26.")
                    return False
            except:
                messagebox.showerror("Error", "Kunci untuk Hill Cipher tidak valid.")
                return False
        return True

    def encrypt(self):
        cipher = self.cipher_var.get()
        plaintext = self.message_text.get(1.0, tk.END).strip()
        key = self.key_entry.get().strip()
        if not plaintext:
            messagebox.showerror("Error", "Pesan kosong.")
            return
        if not self.validate_key(key, cipher):
            return
        try:
            if cipher == "Vigenere":
                ciphertext = vigenere_encrypt(plaintext, key)
            elif cipher == "Playfair":
                key_matrix = playfair_create_matrix(key)
                ciphertext = playfair_encrypt(plaintext, key_matrix)
            elif cipher == "Hill":
                size = int(math.sqrt(len(key)))
                ciphertext = hill_encrypt(plaintext, key, size)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, ciphertext)
        except Exception as e:
            messagebox.showerror("Error", f"Enkripsi gagal: {e}")

    def decrypt(self):
        cipher = self.cipher_var.get()
        ciphertext = self.message_text.get(1.0, tk.END).strip()
        key = self.key_entry.get().strip()
        if not ciphertext:
            messagebox.showerror("Error", "Pesan kosong.")
            return
        if not self.validate_key(key, cipher):
            return
        try:
            if cipher == "Vigenere":
                plaintext = vigenere_decrypt(ciphertext, key)
            elif cipher == "Playfair":
                key_matrix = playfair_create_matrix(key)
                plaintext = playfair_decrypt(ciphertext, key_matrix)
            elif cipher == "Hill":
                size = int(math.sqrt(len(key)))
                plaintext = hill_decrypt(ciphertext, key, size)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, plaintext)
        except Exception as e:
            messagebox.showerror("Error", f"Dekripsi gagal: {e}")

def main():
    root = tk.Tk()
    gui = CipherGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
