# NSE: Nofal's Seucre Encryption
**Developed by Bahaa Nofal | EXcellent TechStacks**

 NES is an advanced, terminal-driven steganography and cryptographic suite. It enforces the CIA triad (Confidentiality, Integrity, and Authentication) by fusing TRN entropy generation, hybrid asymmetric cryptography (RSA-2048 / AES-256-GCM), and Discrete Integer Wavelet Transforms (IWT). 

---

## Core Architecture

* **Hybrid Cryptography:** AES-256-GCM payload encryption driven by a non-linear Chaotic Logistic Map, wrapped in RSA-2048 Key Encapsulation for "Zero-Footprint" key distribution.
* **Frequency Domain Steganography:** Lossless data injection into the high-frequency ($HH$) sub-bands of carrier images using 2D Integer Wavelet Transforms.
* **Centralized PKI Directory:** A lightweight Flask/PyMySQL backend to seamlessly resolve public identities and enable offline-capable key caching.
* **TUI Interface:** A high-contrast, bootloader-style Terminal User Interface built with `prompt_toolkit` and `rich`.

---

## Prerequisites

* **Operating System:** Natively optimized for Linux Mint / Ubuntu environments.
* **Python:** Python 3.10+
* **Database:** A local MySQL server instance (for the PKI registry).

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Bahfo/EXcellentTechStacks---Nofal-s-Secure-Encryption
cd Nofal-s-Secure-Encryption
```

### 2. Install Python Dependencies
It is recommended to use a virtual environment. The framework avoids heavy data-science libraries in favor of optimized, built-in structural processing.

```bash
pip install -r requirements.txt
(Dependencies: prompt_toolkit, rich, pycryptodome, Pillow, numpy, flask, pymysql, requests)
```

# Usage Instructions

1. Boot the PKI Server
Before starting the client, initialize the Central Key Registry. This will automatically bootstrap the MySQL openbox_pki database.

Ensure your MySQL service is running, then execute:

```bash
python3 pki_server.py
```

2. Launch the TUI Environment
With your ESP32 plugged into a USB port (or active on the local Wi-Fi), launch the main interface:

```Bash
python3 interface.py
```

#### Happy Coding!