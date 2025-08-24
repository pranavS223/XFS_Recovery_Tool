# XFS Permanently Deleted File Recovery Tool

A CLI tool and web application to recover permanently deleted, non-overwritten files from XFS file systems.
Includes end-to-end AES-GCM encryption for secure upload and download of recovered files.

## Features
- **Recovery of Permanently Deleted Files –** Parses raw disk hex data to reconstruct inode structures and extract file metadata.
- **Metadata Extraction –** Retrieves file names, sizes, extents, and paths from XFS inode data.
- **Web Interface –** Flask-based UI to upload XFS images and perform recovery visually.
- **End-to-End Encryption –**
  - Client-side encryption of uploaded images via WebCrypto API & Diffie–Hellman key exchange.
  - Server-side decryption for processing and secure re-encryption of recovered files.
  - Browser-based decryption of recovered ZIP files before download.

## Technologies Used
- **Programming Languages:** C, Python, JavaScript
- **Frameworks:** Flask
- **Encryption:** AES-GCM (WebCrypto API, PyCryptodome)
- **Filesystem Tools:** XFSProgs
- **Frontend:** HTML, CSS

## Installation & Setup
**Prerequisites**
- Python 3.x
- Flask
- XFSProgs (for low-level operations)

## Steps
**1] Clone the repository:**
```bash
git clone https://github.com/yourusername/xfs-recovery.git
cd xfs-recovery
PyCryptodome (pip install pycryptodome)
```
**2] Install dependencies:**
```bash
pip install flask pycryptodome
```
**3] Run the Flask server:**
```bash
sudo python3 app.py
```
**4] Open your browser and go to:**
```bash
http://127.0.0.1:5000
```

## How It Works
**1. File Upload**
- Users upload an XFS image.
- Image is encrypted on the browser using AES-GCM before upload.

**2. File Recovery**
- CLI & backend logic parses inode hex data and maps it to file blocks.
- Reconstructs deleted, non-overwritten files using XFS metadata.

**3. Secure Download**
- Recovered files are zipped and encrypted server-side.
- Browser decrypts the ZIP before downloading.
