import socket


# Server configuration
HOST = '192.168.226.2'
PORT = 1337


def connect_to_server():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    
    while True:
        try:
            data = client.recv(1024)
            if not data:
                command = data.decode()
                print(f"Received command: {command}")
                
            # Execute the command and send the result back to the server
            result = execute_command(command)
            client.send(result.encode())
        except:
            break
            client.close()
            
            
def execute_command(command: str) -> str:
    # Implement your command execution logic here
    # For example, if command == "scan", run the scan and return the results
    return "Command executed: " + command
    

if "__name__" == "__main__":
    connect_to_server()