import sys
from PyQt5.QtWidgets import QApplication
from ransomware_builder import RansomwareBuilder

if __name__ == '__main__':
    app = QApplication(sys.argv)
    builder = RansomwareBuilder()
    builder.show()
    sys.exit(app.exec_())
