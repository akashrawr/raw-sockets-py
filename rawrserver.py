from reliable_raw_socket import ReliableRawSocket

SERVER_IP = "192.168.56.1"  # Listen on all interfaces
SERVER_PORT = 9000

def main():
    server = ReliableRawSocket(local_ip=SERVER_IP, local_port=SERVER_PORT)
    server.listen()
    print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        client_ip, client_port = server.accept(timeout=30)
        if client_ip:
            print(f"Accepted connection from {client_ip}:{client_port}")

            # Wait for the VERIFY message to confirm handshake
            verified = False
            for _ in range(10):
                data, src_ip, src_port = server.receive_reliable(timeout=2)
                if data:
                    try:
                        if data.decode('utf-8') == "VERIFY":
                            print(f"Handshake verified with {src_ip}:{src_port}")
                            verified = True
                            break
                    except Exception:
                        pass  # Not a VERIFY message, keep waiting

            if not verified:
                print("Handshake not verified, skipping client.")
                continue

            # Now receive the actual authentication data
            data, src_ip, src_port = server.receive_reliable(timeout=10)
            if data:
                try:
                    print(f"Received from {src_ip}:{src_port}: {data.decode('utf-8')}")
                except Exception:
                    print(f"Received binary data from {src_ip}:{src_port}")
                # Always ACK the received data packet
                server._send_ack(src_ip, src_port, server.expected_seq_num - 1)
                # Echo or process authentication here
                server.send_reliable(src_ip, src_port, b"AUTH_OK")
            else:
                print("No data received from client.")
        else:
            print("No incoming connection. Waiting...")

if __name__ == "__main__":
    main()