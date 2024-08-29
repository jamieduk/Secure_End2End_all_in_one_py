#
# Secure_End2End_all_in_one (c) J~Net 2024
#https://github.com/jamieduk/Secure_End2End_all_in_one_py
#
#
# python e2e_aio.py
#
import socket
import threading
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Global variables for private key, public key, peer's public key, and username alias
port=12345
private_key=None
public_key=None
peer_public_key=None
username="Anonymous"  # Default username alias

# Generate RSA Key Pair
def generate_key_pair():
    global private_key, public_key
    private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key=private_key.public_key()

    print("New key pair generated successfully.")
    save_keys()

# Save keys to files
def save_keys():
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Keys saved to files: private_key.pem and public_key.pem")

# Load keys from files
def load_keys():
    global private_key, public_key
    try:
        with open("private_key.pem", "rb") as f:
            private_key=serialization.load_pem_private_key(f.read(), password=None)
        with open("public_key.pem", "rb") as f:
            public_key=serialization.load_pem_public_key(f.read())
        print("Keys loaded successfully.")
    except FileNotFoundError:
        print("Key files not found. Please generate new keys.")

# Encrypt a message using the recipient's public key
def encrypt_message(public_key, message):
    encrypted=public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

# Decrypt a received message using the private key
def decrypt_message(private_key, encrypted_message):
    decrypted=private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

# Handle incoming peer connections and messages
def handle_peer_connection(client_socket):
    try:
        encrypted_message=client_socket.recv(4096)
        if encrypted_message:
            message=decrypt_message(private_key, encrypted_message)
            print(f"Received: {message}")
    except Exception as e:
        print(f"Error handling message: {e}")
    finally:
        client_socket.close()

# Start the server to listen for incoming connections and wait for one message
def start_server():
    server_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", port))  # Bind to any available network interface
    server_socket.listen(5)
    
    print(f"Server listening on port {port}... Press Ctrl+C to quit.")
    
    try:
        client_socket, addr=server_socket.accept()
        print(f"Accepted connection from {addr}")
        handle_peer_connection(client_socket)
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server_socket.close()

# Connect to a peer and send an encrypted message
def connect_to_peer(peer_ip="127.0.0.1", peer_port=12345, message=""):
    if peer_public_key is None:
        print("No peer public key available. Please update the peer's public key first.")
        return

    # Prepend the username to the message
    full_message=f"{username}: {message}"

    client_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((peer_ip, peer_port))
        encrypted_message=encrypt_message(peer_public_key, full_message)
        client_socket.send(encrypted_message)
        print(f"Message sent to {peer_ip}:{peer_port}")
    except Exception as e:
        print(f"Failed to send message: {e}")
    finally:
        client_socket.close()

# Update remote peer's public key
def update_peer_public_key():
    global peer_public_key
    try:
        default_path=os.path.join(os.getcwd(), "public_key.pem")
        file_path=input(f"Enter the path of the peer's public key file (default: {default_path}): ")
        file_path=file_path.strip() or default_path

        with open(file_path, "rb") as f:
            peer_public_key=serialization.load_pem_public_key(f.read())
        print("Peer's public key updated successfully.")
    except Exception as e:
        print(f"Failed to load peer's public key: {e}")


# Set username alias
def set_username_alias():
    global username
    username=input("Enter your username alias : ").strip()
    if not username:
        username="Anonymous"
    print(f"Username alias set to: {username}")


# Menu
def menu():
    while True:
        print("\nMenu:")
        print("1. Start server to receive messages")
        print("2. Write and send a new message")
        print("3. Generate a new key pair")
        print("4. Update remote peer's public key")
        print("5. Set username alias")
        print("6. Exit")

        choice=input("Choose an option: ")

        if choice == "1":
            print("Starting server...")
            try:
                start_server()
            except Exception as e:
                print(f"Error starting server: {e}")
        elif choice == "2":
            peer_ip=input("Enter peer IP (default: 127.0.0.1): ").strip() or "127.0.0.1"
            peer_port=input(f"Enter peer port (default: {port}): ").strip() or port
            try:
                peer_port=int(peer_port)
            except ValueError:
                print("Invalid port number. Using default.")
                peer_port=12345
            message=input("Enter message: ")
            connect_to_peer(peer_ip, peer_port, message)
        elif choice == "3":
            generate_key_pair()
        elif choice == "4":
            update_peer_public_key()
        elif choice == "5":
            set_username_alias()
        elif choice == "6":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

# Main script execution
if __name__ == "__main__":
    # Load existing keys if available
    load_keys()
    
    # Run the menu
    menu()

