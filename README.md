# RSA E&D GUI

## Description

This application provides a graphical user interface for RSA encryption and decryption operations. It allows users to encrypt and decrypt text and files using RSA public-key cryptography. The application features a customizable interface with dark and light themes, supports drag-and-drop functionality, and includes various key management options.

## Features

- Text encryption and decryption
- File encryption and decryption
- RSA key pair generation with customizable key sizes
- Public key import and export
- Dark and light theme options
- Drag and drop support for files
- Logging of operations and errors
- Customizable RSA key size (1024, 2048, 3072, 4096 bits)

## Requirements

- Python 3.6+
- PyQt5
- cryptography

## Installation

1. Clone this repository or download the source code.

2. Create a virtual environment `(venv)` e.g:

```bash
   python -m venv venv
```

3. Activate the venv before installing dependencies:

```bash
   venv\Scripts\activate 
```

4. Install the required dependencies:

```bash
   pip install -r requirements.txt
```

5. Ensure the `logo.png` file is in the same directory as `RSA_ED.py`.

6. Run the application:

```bash
   python RSA_ED.py
```

## Usage

### Text Encryption/Decryption

1. Enter or paste the text you want to encrypt/decrypt in the text area.
2. Click the "Encrypt" or "Decrypt" button as appropriate.
3. The result will be displayed in the text area.

### File Encryption/Decryption

1. Go to File -> Encrypt File or File -> Decrypt File.
2. Select the file you want to process.
3. Choose the output location for the processed file.

### Key Management

- Generate New Keys: Go to Keys -> Generate New Keys
- Export Public Key: Go to Keys -> Export Public Key
- Import Public Key: Go to Keys -> Import Public Key
- Set Key Size: Go to Settings -> Set Key Size

### Changing Themes

- Go to Settings -> Change Theme to switch between dark and light themes.

### Drag and Drop

You can drag and drop text files directly into the text area to load their content.

## Logging

The application logs operations and errors to a file named `rsa_app.log` in the same directory as the script.

## Security Considerations

- This application is for educational purposes and may not be suitable for high-security environments.
- Always keep your private key secure and never share it.
- For production use, consider using established cryptography libraries and following best practices for key management.

## Contributing

Contributions to improve the application are welcome. Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

[MIT License](https://opensource.org/licenses/MIT)

## Disclaimer

This software is provided "as is", without warranty of any kind. Use at your own risk.