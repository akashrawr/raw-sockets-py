from reliable_raw_socket import ReliableRawSocket

SERVER_IP = "192.168.56.1"
SERVER_PORT = 9000
CLIENT_IP = "192.168.56.1"
CLIENT_PORT = 9001

def main():
    client = ReliableRawSocket(local_ip=CLIENT_IP, local_port=CLIENT_PORT)
    if client.connect(SERVER_IP, SERVER_PORT):
        print(f"Connected to server at {SERVER_IP}:{SERVER_PORT}")
        auth_data = "user_id=admin1;password=admin123"
        if client.send_reliable(SERVER_IP, SERVER_PORT, auth_data):
            print("Sent authentication data.")
            data, src_ip, src_port = client.receive_reliable(timeout=10)
            if data:
                print(f"Server replied: {data.decode('utf-8')}")
            else:
                print("No reply from server.")
        else:
            print("Failed to send authentication data.")
        client.close_connection(SERVER_IP, SERVER_PORT)
    else:
        print("Could not connect to server.")

if __name__ == "__main__":
    main()