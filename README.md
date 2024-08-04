# Ransomware Builder - Educational Use Only

<div id="header" align="center">
 <img src="https://image.noelshack.com/fichiers/2024/31/6/1722719562-screenshot-at-2024-08-03-23-10-33.png">
</div>

## Features

- **Custom Ransom Note**: Choose from predefined messages or create your own.
- **Decryption Password**: Set and confirm a decryption password.
- **Email Contact**: Add your email address for receiving decryption requests.
- **File Extensions**: Specify file types to encrypt.
- **Modern GUI**: Stylish and easy-to-use interface.
- **AES-256 Encryption**: Secure encryption of files.

## Prerequisites

- Python 3.6 or higher
- PyQt5
- PyCryptodome
- PyInstaller

## Installation

1. Clone this repository:
    ```sh
    git clone https://github.com/busirus/PyQt5-RansomwareBuilder.git
    cd PyQt5-RansomwareBuilder
    ```

2. Install the required dependencies:
    ```sh
    pip install pyqt5 pycryptodome pyinstaller
    ```

## Usage

1. Run the application:
    ```sh
    python main.py
    ```

2. Fill in the fields in the GUI:
    - **Ransom Note Message**: Choose or enter a ransom note message.
    - **Decryption Password**: Set a password for decrypting files.
    - **Confirm Decryption Password**: Confirm the decryption password.
    - **Your Email**: Enter your email address.
    - **File Extensions to Encrypt**: Specify file extensions to encrypt (e.g., `.pdf,.jpeg`).

3. Click **Build Ransomware** to create the ransomware executable.

4. The executable will be generated in the current directory. Run this executable to encrypt files and place the `INSTRUCTIONS.txt` and `RANSOM_NOTE.txt` on the desktop.

## Warnings

- **Educational Use Only**: This project is intended for educational purposes only. Do not use it for malicious purposes.
- **Security**: Test this code only in a controlled and secure environment, such as a virtual machine or isolated system.
- **Responsibility**: The author is not responsible for any misuse or illegal use of this project.

## Contribution

Contributions are welcome! If you have ideas for improvements or find any issues, feel free to submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
