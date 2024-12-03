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
