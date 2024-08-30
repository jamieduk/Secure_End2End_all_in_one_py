# Secure_End2End_all_in_one (c) J~Net 2024

An end-to-end encrypted chat application using public key encryption and a decentralized peer-to-peer (P2P) architecture in Python.

## Features

- **Peer-to-Peer (P2P) Communication**: Decentralized, direct communication between peers without a central server.
- **End-to-End Encryption**: Messages and files are encrypted using RSA public/private key pairs.
- **Public/Private Key Management**: Generate and share keys for secure communication.
- **Send/Receive Encrypted Files**: Securely send and receive files via encrypted channels.
- **Logging**: Toggle logging of messages and file transfers.
- **Alias/Username**: Set a custom alias for communication.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/jamieduk/Secure_End2End_all_in_one_py
   cd Secure_End2End_all_in_one_py
   pip install pygame

menu:1. %F0%9F%93%A9 Receive Messages Or File2. %E2%9C%89%EF%B8%8F Send A New Message3. %F0%9F%94%92 Send An Encrypted File4. %F0%9F%93%9D Toggle Logging5. %F0%9F%94%91 Generate A New Key-Pair6. %F0%9F%9B%A0%EF%B8%8F Load Remote Public Key7. %F0%9F%A7%91%E2%80%8D%F0%9F%92%BB Set Alias / Username8. %F0%9F%9A%AA Exit
Steps to Get Started:
Generate your RSA key pair: Choose option 5 from the menu to generate a new key pair (public/private). You will share your public key with your peer while keeping your private key secure.

Exchange Public Keys: Share your public key with your peer, and obtain their public key as well. This is essential for secure, encrypted communication.

Set Your Alias: Choose option 7 to set an alias (username or codename) that will identify you in communication.

Update Remote Peer Key: Choose option 6 to load your peer's public key from a file. This allows you to encrypt messages and files using their public key.

Send and Receive Encrypted Messages or Files:

Choose 1 to start the server and listen for incoming encrypted messages or files.
Choose 2 to send an encrypted message to your peer.
Choose 3 to send an encrypted file to your peer.
Important Notes
Port Forwarding: Ensure that the port you are using is open and correctly forwarded to your IP address in your router settings for smooth communication.
Key Sharing: You must share your public key with your peer and get their public key to enable encrypted communication. Never share your private key.
Default Settings: Some settings have default values, but it's important to configure your keys and alias properly for secure communication.
Architecture Overview
1. Peer-to-Peer (P2P) Communication
Each user acts as both a client and server, enabling direct peer-to-peer connections using the socket library for networking and threading for handling multiple peers.

2. Public/Private Key Encryption
RSA Encryption: Uses RSA for public/private key generation and encryption. Public keys are exchanged between peers for secure communication.
Key Generation: Generate your own key pair with the menu option and exchange public keys securely with your peers.
3. Message Encryption/Decryption
Messages are encrypted using the recipient's public key and decrypted with the recipient's private key.

4. Encrypted File Transfer
Secure file transfers are handled using RSA encryption, ensuring that only the intended recipient can decrypt the file.

5. Decentralization
The application is fully decentralized and peer-to-peer. There is no central server, and peers communicate directly.

Roadmap
UI Enhancements: Potential future development includes building a graphical user interface (GUI) using frameworks like Tkinter or Kivy.
Additional Security: Introducing hybrid encryption (AES + RSA) for enhanced performance and security.
Improved Network Discovery: Using advanced P2P discovery mechanisms like Distributed Hash Tables (DHT).
Reliability Enhancements: Adding features like reconnections, message acknowledgment, and data persistence.
License
This project is licensed under the terms of the (c) J~Net 2024.


This `README.md` includes instructions on how to install and run the application, an overview of its features, and additional details about its architecture and usage.
