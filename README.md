
# Cybersecurity Mini Projects

This repository contains two simple but powerful cybersecurity tools built with Python:  
- A **Personal Firewall** that monitors and filters packets using Scapy.  
- A **Secure File Storage** system with AES encryption and a GUI.

---

## Project Structure

```
cyber-mini-projects/
├── Personal_Firewall_Code 2.py        # Packet filtering firewall using Scapy
├── Secure_File_Storage_Code.py        # GUI file encryptor/decryptor using AES
```

---

## Project 1: Personal Firewall

### Description:
A lightweight Python firewall that sniffs incoming packets and blocks traffic from blacklisted IPs.

### Features:
- Uses `scapy` to sniff live traffic.
- Filters packets based on source IP.
- Logs all blocked packets to `firewall_log.txt`.

###  Usage:
```bash
pip install scapy
python "Personal_Firewall_Code 2.py"
```

### Output:
```
Personal Firewall is running...
Allowed packet from 192.168.1.105
```

---

## Project 2: Secure File Storage with AES

### Description:
A GUI-based Python app to encrypt and decrypt files securely using AES (via `cryptography.Fernet`).

### Features:
- AES encryption and decryption with SHA256 integrity checks.
- Simple GUI using `tkinter`.
- Automatically generates a secret key (`filekey.key`).

###  Usage:
```bash
pip install cryptography
python Secure_File_Storage_Code.py
```

### GUI:
- **Encrypt File** → Select any file and encrypt it. Output will be `.enc` file.
- **Decrypt File** → Select `.enc` file and restore original with `.dec` extension.
- Shows **SHA256 hash** of content before/after.

---

## License

This project is for educational/demo purposes only.
