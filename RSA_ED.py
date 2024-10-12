import sys
import os
import logging
from PyQt5.QtWidgets import (QApplication, QMainWindow, QAction, QMessageBox,
                             QVBoxLayout, QWidget, QTextEdit, QPushButton, QHBoxLayout, QLabel, 
                             QFileDialog, QProgressBar, QComboBox, QInputDialog)
from PyQt5.QtGui import QIcon, QPalette, QColor, QDragEnterEvent, QDropEvent
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Setup logging
logging.basicConfig(filename='rsa_app.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class RSAEncryptionGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.current_theme = 'dark'
        self.key_size = 2048
        self.generate_keys()

    def initUI(self):
        self.setStyleSheet(self.dark_theme())
        self.setWindowIcon(QIcon(resource_path('logo.png')))

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Menu bar
        menubar = self.menuBar()
        file_menu = menubar.addMenu('File')
        key_menu = menubar.addMenu('Keys')
        settings_menu = menubar.addMenu('Settings')

        # File menu actions
        open_action = QAction('Open Text', self)
        save_action = QAction('Save Text', self)
        encrypt_file_action = QAction('Encrypt File', self)
        decrypt_file_action = QAction('Decrypt File', self)
        open_action.triggered.connect(self.open_file)
        save_action.triggered.connect(self.save_file)
        encrypt_file_action.triggered.connect(self.encrypt_file)
        decrypt_file_action.triggered.connect(self.decrypt_file)
        file_menu.addAction(open_action)
        file_menu.addAction(save_action)
        file_menu.addAction(encrypt_file_action)
        file_menu.addAction(decrypt_file_action)

        # Key menu actions
        generate_keys_action = QAction('Generate New Keys', self)
        export_public_key_action = QAction('Export Public Key', self)
        import_public_key_action = QAction('Import Public Key', self)
        generate_keys_action.triggered.connect(self.generate_keys)
        export_public_key_action.triggered.connect(self.export_public_key)
        import_public_key_action.triggered.connect(self.import_public_key)
        key_menu.addAction(generate_keys_action)
        key_menu.addAction(export_public_key_action)
        key_menu.addAction(import_public_key_action)

        set_key_size_action = QAction('Set Key Size', self)
        change_theme_action = QAction('Change Theme', self)
        set_key_size_action.triggered.connect(self.set_key_size)
        change_theme_action.triggered.connect(self.change_theme)
        settings_menu.addAction(set_key_size_action)
        settings_menu.addAction(change_theme_action)

        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText("Drag and drop a file here or enter text to encrypt/decrypt")
        layout.addWidget(self.text_edit)
        
        # Settings menu actions
        btn_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("Encrypt")
        self.decrypt_btn = QPushButton("Decrypt")
        self.encrypt_btn.clicked.connect(self.encrypt_text)
        self.decrypt_btn.clicked.connect(self.decrypt_text)
        btn_layout.addWidget(self.encrypt_btn)
        btn_layout.addWidget(self.decrypt_btn)
        layout.addLayout(btn_layout)

        self.result_label = QLabel()
        layout.addWidget(self.result_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.setGeometry(200, 200, 700, 400)
        self.setWindowTitle('RSA E&D')
        self.setAcceptDrops(True)
        self.show()

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        QMessageBox.information(self, "Keys Generated", "New RSA key pair has been generated.")
        logging.info(f'New RSA key pair generated with key size {self.key_size}.')

    def set_key_size(self):
        key_sizes = [1024, 2048, 3072, 4096]
        key_size_str, ok = QInputDialog.getItem(self, "Select Key Size", "Key Size:", 
                                                [str(size) for size in key_sizes], 1, False)
        if ok and key_size_str:
            self.key_size = int(key_size_str)
            self.generate_keys()
            logging.info(f'RSA key size set to {self.key_size}.')

    def change_theme(self):
        if self.current_theme == 'dark':
            self.current_theme = 'light'
            self.setStyleSheet(self.light_theme())
        else:
            self.current_theme = 'dark'
            self.setStyleSheet(self.dark_theme())
        logging.info(f'Theme changed to {self.current_theme}.')

    def dark_theme(self):
        return """
        QMainWindow, QWidget, QMessageBox { 
            background-color: #333; 
            color: white; 
        }
        QTextEdit { 
            background-color: #444; 
            color: white; 
            border: 1px solid #555; 
        }
        QPushButton { 
            background-color: #555; 
            color: white; 
            border: 1px solid #666; 
            padding: 5px; 
        }
        QPushButton:hover { 
            background-color: #666; 
        }
        QLabel { 
            color: white; 
        }
        QMenuBar { 
            background-color: #444; 
            color: white; 
        }
        QMenuBar::item:selected { 
            background-color: #555; 
        }
        QMenu { 
            background-color: #444; 
            color: white; 
        }
        QMenu::item:selected { 
            background-color: #555; 
        }
        QMessageBox { 
            background-color: #333; 
        }
        QMessageBox QLabel { 
            color: white; 
        }
        QMessageBox QPushButton { 
            background-color: #555; 
            color: white; 
            border: 1px solid #666; 
            padding: 5px; 
            min-width: 65px; 
        }
        QMessageBox QPushButton:hover { 
            background-color: #666; 
        }
        """

    def light_theme(self):
        return """
        QMainWindow, QWidget, QMessageBox { 
            background-color: #f0f0f0; 
            color: black; 
        }
        QTextEdit { 
            background-color: #ffffff; 
            color: black; 
            border: 1px solid #ccc; 
        }
        QPushButton { 
            background-color: #e0e0e0; 
            color: black; 
            border: 1px solid #bbb; 
            padding: 5px; 
        }
        QPushButton:hover { 
            background-color: #d0d0d0; 
        }
        QLabel { 
            color: black; 
        }
        QMenuBar { 
            background-color: #e0e0e0; 
            color: black; 
        }
        QMenuBar::item:selected { 
            background-color: #d0d0d0; 
        }
        QMenu { 
            background-color: #e0e0e0; 
            color: black; 
        }
        QMenu::item:selected { 
            background-color: #d0d0d0; 
        }
        QMessageBox { 
            background-color: #f0f0f0; 
        }
        QMessageBox QLabel { 
            color: black; 
        }
        QMessageBox QPushButton { 
            background-color: #e0e0e0; 
            color: black; 
            border: 1px solid #bbb; 
            padding: 5px; 
            min-width: 65px; 
        }
        QMessageBox QPushButton:hover { 
            background-color: #d0d0d0; 
        }
        """
    
    def encrypt_text(self):
        try:
            plaintext = self.text_edit.toPlainText().encode()
            ciphertext = self.public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.text_edit.setPlainText(ciphertext.hex())
            self.result_label.setText("Text encrypted successfully!")
            logging.info('Text encrypted successfully.')
        except Exception as e:
            self.result_label.setText(f"Error: {str(e)}")
            logging.error(f"Encryption error: {str(e)}")

    def decrypt_text(self):
        try:
            ciphertext = bytes.fromhex(self.text_edit.toPlainText())
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.text_edit.setPlainText(plaintext.decode())
            self.result_label.setText("Text decrypted successfully!")
            logging.info('Text decrypted successfully.')
        except ValueError:
            self.result_label.setText("Error: Invalid ciphertext")
            logging.error("Decryption error: Invalid ciphertext")
        except Exception as e:
            self.result_label.setText(f"Error: {str(e)}")
            logging.error(f"Decryption error: {str(e)}")

    def open_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Open Text File", "", 
                                                   "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            with open(file_name, 'r') as file:
                file_content = file.read()
                self.text_edit.setPlainText(file_content)
                logging.info(f'Opened file: {file_name}')

    def save_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Text File", "", 
                                                   "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            with open(file_name, 'w') as file:
                file_content = self.text_edit.toPlainText()
                file.write(file_content)
                logging.info(f'Saved file: {file_name}')

    def encrypt_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt", "", 
                                                   "All Files (*)")
        if file_name:
            try:
                with open(file_name, 'rb') as file:
                    file_content = file.read()
                encrypted_content = self.public_key.encrypt(
                    file_content,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                save_file_name, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", "", 
                                                                "All Files (*)")
                if save_file_name:
                    with open(save_file_name, 'wb') as file:
                        file.write(encrypted_content)
                    self.result_label.setText("File encrypted and saved successfully!")
                    logging.info(f'File encrypted: {file_name} and saved as {save_file_name}')
            except Exception as e:
                self.result_label.setText(f"Error: {str(e)}")
                logging.error(f"File encryption error: {str(e)}")

    def decrypt_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt", "", 
                                                   "All Files (*)")
        if file_name:
            try:
                with open(file_name, 'rb') as file:
                    encrypted_content = file.read()
                decrypted_content = self.private_key.decrypt(
                    encrypted_content,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                save_file_name, _ = QFileDialog.getSaveFileName(self, "Save Decrypted File", "", 
                                                                "All Files (*)")
                if save_file_name:
                    with open(save_file_name, 'wb') as file:
                        file.write(decrypted_content)
                    self.result_label.setText("File decrypted and saved successfully!")
                    logging.info(f'File decrypted: {file_name} and saved as {save_file_name}')
            except ValueError:
                self.result_label.setText("Error: Invalid encrypted file")
                logging.error("File decryption error: Invalid encrypted file")
            except Exception as e:
                self.result_label.setText(f"Error: {str(e)}")
                logging.error(f"File decryption error: {str(e)}")

    def export_public_key(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Export Public Key", "", 
                                                   "Public Key Files (*.pem);;All Files (*)", options=options)
        if file_name:
            with open(file_name, 'wb') as file:
                public_key_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                file.write(public_key_pem)
            self.result_label.setText("Public key exported successfully!")
            logging.info(f'Public key exported to {file_name}')

    def import_public_key(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Import Public Key", "", 
                                                   "Public Key Files (*.pem);;All Files (*)", options=options)
        if file_name:
            with open(file_name, 'rb') as file:
                public_key_pem = file.read()
                self.public_key = serialization.load_pem_public_key(public_key_pem)
            self.result_label.setText("Public key imported successfully!")
            logging.info(f'Public key imported from {file_name}')

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                file_name = url.toLocalFile()
                if file_name:
                    with open(file_name, 'r') as file:
                        file_content = file.read()
                        self.text_edit.setPlainText(file_content)
                        logging.info(f'File dragged and dropped: {file_name}')
                        break

if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWin = RSAEncryptionGUI()
    sys.exit(app.exec_())
