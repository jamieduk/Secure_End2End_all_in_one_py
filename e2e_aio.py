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
from datetime import datetime
from playsound import playsound

# Constants for text color and buffer size
GREEN_TEXT="\033[92m"
RESET_TEXT="\033[0m"
BUFFER_SIZE=4096

# Directory for storing received files
DOWNLOAD_DIR="downloads"

# Initialize default port and global variables
port=12345
private_key=None
public_key=None
peer_public_key=None
username_alias="Anonymous"
logging_enabled=False

# Create downloads folder if it doesn't exist
if not os.path.exists(DOWNLOAD_DIR):
    os.makedirs(DOWNLOAD_DIR)

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

# Set alias / username
def set_username_alias():
    global username_alias
    alias=input("Enter your alias / username: ").strip()
    if alias:
        username_alias=alias
        print(f"alias / username set to '{username_alias}'")

# Generate RSA Key Pair
def generate_key_pair():
    global private_key, public_key
    
    # Check if key files already exist
    key_files_exist=os.path.exists("private_key.pem") or os.path.exists("public_key.pem")
    
    if key_files_exist:
        # Ask for user confirmation to overwrite existing keys
        confirm=input("Key files already exist. Overwrite? (y/n): ").strip().lower()
        if confirm != 'y':
            print("Key generation cancelled.")
            return
    
    # Generate new RSA key pair
    private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key=private_key.public_key()

    print("New key pair generated successfully.")
    save_keys()


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

# Decrypt a message using the private key
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

# Encrypt file using peer's public key
def encrypt_file(file_path, public_key):
    with open(file_path, "rb") as f:
        file_data=f.read()

    encrypted_file_data=public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_file_data

# Decrypt file using private key
def decrypt_file(encrypted_file_data):
    decrypted_file_data=private_key.decrypt(
        encrypted_file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_file_data

# Sanitize filename to prevent path traversal attacks
def sanitize_filename(filename):
    return os.path.basename(filename)

# Log messages to a file
def log_message(message):
    if logging_enabled:
        with open("logfile.log", "a") as f:
            f.write(f"{datetime.now()} - {message}\n")

# Handle incoming peer connections and messages/files
def handle_peer_connection(client_socket):
    try:
        message_type=client_socket.recv(1).decode('utf-8')

        if message_type == 'M':
            encrypted_message=client_socket.recv(BUFFER_SIZE)
            if encrypted_message:
                message=decrypt_message(private_key, encrypted_message)
                print(f"{GREEN_TEXT}Received: {message}{RESET_TEXT}")
                log_message(f"Received message: {message}")
                playsound("sounds/notification_sound.wav")
                
        elif message_type == 'F':
            # First, receive the filename (unencrypted)
            filename_length=int(client_socket.recv(4).decode('utf-8'))
            filename=client_socket.recv(filename_length).decode('utf-8')
            filename=sanitize_filename(filename)

            # Receive the encrypted file data
            encrypted_file_data=client_socket.recv(BUFFER_SIZE)
            file_data=decrypt_file(encrypted_file_data)

            # Save the file to the downloads folder
            file_path=os.path.join(DOWNLOAD_DIR, filename)
            with open(file_path, "wb") as f:
                f.write(file_data)
            print(f"{GREEN_TEXT}Received encrypted file. Saved as {file_path}.{RESET_TEXT}")
            log_message(f"Received file: {filename}")

    except Exception as e:
        print(f"Error handling peer connection: {e}")
    finally:
        client_socket.close()

# Start the server to continuously listen for incoming connections
def start_server():
    global port  # Use the global port variable

    # Prompt for port input
    port_input=input(f"Enter port to listen on (default: {port}): ").strip()
    if port_input:
        try:
            port=int(port_input)
        except ValueError:
            print("Invalid port number. Using default port 12345.")
            port=12345
    else:
        print(f"Using default port: {port}")

    # Create and bind the server socket
    server_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", port))
    server_socket.listen(5)
    
    print(f"Server listening on port {port}... Press Ctrl+C to quit.")
    
    try:
        while True:
            client_socket, addr=server_socket.accept()
            print(f"Accepted connection from {addr}")
            handle_peer_connection(client_socket)
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server_socket.close()

# Send a file to a peer (encrypted)
def send_file(peer_ip="127.0.0.1", peer_port=12345, file_path=""):
    if peer_public_key is None:
        print("No peer public key available. Please update the peer's public key first.")
        return

    # Extract the filename and encrypt the file
    filename=os.path.basename(file_path)
    encrypted_file_data=encrypt_file(file_path, peer_public_key)

    client_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((peer_ip, peer_port))
        client_socket.send(b'F')  # Indicate this is a file transfer
        
        # Send the filename length, followed by the filename (in plaintext)
        client_socket.send(f"{len(filename):04}".encode('utf-8'))
        client_socket.send(filename.encode('utf-8'))
        
        # Send the encrypted file data
        client_socket.send(encrypted_file_data)
        print(f"File '{filename}' sent to {peer_ip}:{peer_port}")
        log_message(f"Sent file: {filename} to {peer_ip}:{peer_port}")
    except Exception as e:
        print(f"Failed to send file: {e}")
    finally:
        client_socket.close()

def connect_to_peer(peer_ip="127.0.0.1", peer_port=12345, message=""):
    global peer_public_key, username_alias
    
    if peer_public_key is None:
        print("No peer public key available. Please update the peer's public key first.")
        return

    if username_alias is None:
        print("No alias / username set. Please set your alias / username first.")
        return

    # Format message with alias
    formatted_message=f"{username_alias}: {message}"
    encrypted_message=encrypt_message(peer_public_key, formatted_message)

    client_socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((peer_ip, peer_port))
        client_socket.send(b'M')  # Indicate this is a message transfer
        client_socket.send(encrypted_message)
        print(f"Message sent to {peer_ip}:{peer_port}")
        log_message(f"Sent message: {formatted_message} to {peer_ip}:{peer_port}")
    except Exception as e:
        print(f"Failed to send message: {e}")
    finally:
        client_socket.close()

def toggle_logging():
    global logging_enabled
    log_file="logging.txt"
    
    # Check if logging.txt exists
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            logging_state=f.read().strip()
            if logging_state == "1":
                logging_enabled=True
                print("Logging is currently ON.")
            elif logging_state == "0":
                logging_enabled=False
                print("Logging is currently OFF.")
            else:
                print("Invalid logging state in file. Defaulting to OFF.")
                logging_enabled=False
    else:
        logging_enabled=False  # Default to logging off if file doesn't exist
    
    # Prompt user to toggle logging state
    new_state=input("Enter 1 to turn logging ON or 0 to turn logging OFF: ").strip()
    
    if new_state in ["0", "1"]:
        with open(log_file, "w") as f:
            f.write(new_state)
        logging_enabled=new_state == "1"
        if logging_enabled:
            print("Logging has been turned ON.")
        else:
            print("Logging has been turned OFF.")
    else:
        print("Invalid input. Logging state not changed.")

def menu():
    while True:
        print("\nMenu:")
        print("1. Receive Messages Or File")
        print("2. Send A New Message")
        print("3. Send An Encrypted File")
        print("4. Toggle Logging")
        print("5. Generate A New Key-Pair")
        print("6. Load Remote Public Key")
        print("7. Set Alias / Username")
        print("8. Exit")

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
            peer_ip=input("Enter peer IP (default: 127.0.0.1): ").strip() or "127.0.0.1"
            peer_port=input(f"Enter peer port (default: {port}): ").strip() or port
            try:
                peer_port=int(peer_port)
            except ValueError:
                print("Invalid port number. Using default.")
                peer_port=12345
            file_path=input("Enter the path of the file to send: ").strip()
            send_file(peer_ip, peer_port, file_path)
        elif choice == "4":
            toggle_logging()
        elif choice == "5":
            generate_key_pair()
        elif choice == "6":
            update_peer_public_key()
        elif choice == "7":
            set_username_alias()
        elif choice == "8":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

# Main script execution
if __name__ == "__main__":
    load_keys()
    menu()

