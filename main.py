import socket
import threading
from cryptography.fernet import Fernet

# Generate a key for encryption and decryption
# Make sure to share this key securely among all participants
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

# Server configuration
HOST = "0.0.0.0"
PORT = 5555

# Store clients and messages
clients = []
messages = [] 

# Server's own username
SERVER_USERNAME = "Server"

def broadcast_message(message, sender):
    """Send a message to all connected clients except the sender."""
    for client in clients:
        if client[1] != sender:
            client[0].send(message)

def handle_client(client_socket, address):
    """Handle communication with a connected client."""
    try:
        # Ask for username
        client_socket.send(cipher.encrypt(b"Enter your name: "))
        username_encrypted = client_socket.recv(1024)
        username = cipher.decrypt(username_encrypted).decode("utf-8")

        # Notify everyone about the new connection
        join_message = f"{username} has joined the chat.".encode("utf-8")
        encrypted_join_message = cipher.encrypt(join_message)
        broadcast_message(encrypted_join_message, address)
        print(f"{username} connected from {address}")

        # Send stored messages to the new user
        for user, msg in messages:
            client_socket.send(cipher.encrypt(f"{user}: {msg}".encode("utf-8")))

        # Add the client to the list
        clients.append((client_socket, address, username))

        # Handle incoming messages
        while True:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                break

            # Decrypt the message
            message = cipher.decrypt(encrypted_message).decode("utf-8")
            messages.append((username, message))  # Store the message

            # Broadcast the message to others
            broadcast_message(cipher.encrypt(f"{username}: {message}".encode("utf-8")), address)

    except Exception as e:
        print(f"Error handling client {address}: {e}")

    finally:
        # Remove the client on disconnect
        for client in clients:
            if client[1] == address:
                clients.remove(client)
                break

        # Notify others about the disconnection
        leave_message = f"{username} has left the chat.".encode("utf-8")
        encrypted_leave_message = cipher.encrypt(leave_message)
        broadcast_message(encrypted_leave_message, address)
        print(f"{username} disconnected from {address}")

        client_socket.close()

def send_server_message():
    """Allow the server itself to send messages to all clients."""
    while True:
        message = input()
        messages.append((SERVER_USERNAME, message))
        encrypted_message = cipher.encrypt(f"{SERVER_USERNAME}: {message}".encode("utf-8"))
        broadcast_message(encrypted_message, None)

def start_server():
    """Start the chat server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    # Start a thread for the server to send messages
    threading.Thread(target=send_server_message, daemon=True).start()

    while True:
        client_socket, address = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket, address))
        client_thread.start()

if __name__ == "__main__":
    start_server()
