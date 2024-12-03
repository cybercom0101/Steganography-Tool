# Steganography Tool

A Python-based graphical user interface (GUI) application for securely encoding and decoding messages into images using steganography techniques, with optional AES encryption for enhanced security.

---

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Screenshots](#screenshots)
5. [How It Works](#how-it-works)
6. [Security Features](#security-features)
7. [Limitations](#limitations)
8. [Contributing](#contributing)
9. [License](#license)
10. [Acknowledgments](#acknowledgments)

---

## Features

- **Encode Messages**: Hide text messages inside images using least significant bit (LSB) manipulation.
- **Decode Messages**: Extract hidden messages from encoded images.
- **Optional Encryption**: Encrypt messages using AES encryption before encoding.
- **Password Protection**: Secure encoded messages with a user-defined password.
- **User-Friendly GUI**: Intuitive graphical interface for smooth interaction.
- **Progress Indicator**: Visual feedback during encoding and decoding processes.

---

## Installation

### Prerequisites

- Python 3.8 or higher
- Libraries: `tkinter` (Standard library), `pillow`, `numpy`, `pycryptodome`

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/steganography-tool.git
   cd steganography-tool
   
2. Install the required dependencies:
   ```bash
   pip install pillow pycryptodome numpy
3. Run the application:
   ```bash
   python steganography_tool.py

##Usage

###Encoding a Message

1. Launch the application.
2. Click on Encode Message.
3. Select an image file (only PNG supported).
4. Enter the message you want to encode.
5. Choose to enable encryption (optional) and provide a password (16, 24, or 32 characters).
6. Save the encoded image to a desired location.

###Decoding a Message

1. Launch the application.
2. Click on Decode Message.
3. Select the encoded image file.
4. Indicate whether the message was encrypted and provide the correct password if applicable.
5. View the decoded message.

##How It Works

###Encoding

1. Converts the message into a binary format.
2. Optionally encrypts the message using AES encryption with a password.
3. Compresses the message using zlib to optimize size.
4. Embeds the binary message into the least significant bits (LSB) of the image pixels.

###Decoding

1. Reads the binary data from the image's least significant bits.
2. Extracts the message by identifying the delimiter.
3. Decompresses and, if applicable, decrypts the message.

##Security Features

- **AES Encryption**: Encrypts messages using AES in CBC mode.
- **Password-Based Key Derivation**: Uses PBKDF2 with a salt for secure password-to-key conversion.
- **Message Compression**: Reduces the size of the message to optimize encoding.

##Limitations

- Message size is limited by the number of pixels in the image.
- Only supports PNG images to ensure data integrity.

##License

- This project is licensed under the MIT License.

##Acknowledgments

- **PyCryptodome** for cryptographic functionalities.
- **Pillow** for image processing.
- **NumPy** for efficient numerical operations.

##Notes

1. Ensure the password for encryption is either 16, 24, or 32 characters long, as required by AES.
2. Always keep a backup of the original image for recovery in case of issues with the encoded image.

