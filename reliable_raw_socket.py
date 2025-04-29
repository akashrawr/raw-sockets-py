import socket
import struct
import time
import os
import threading
import queue
from enum import Enum
from raw_socket import RawSocket

class PacketType(Enum):
    DATA = 1
    ACK = 2
    SYN = 3
    SYN_ACK = 4
    FIN = 5
    FIN_ACK = 6

class ConnectionState(Enum):
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT = 5
    CLOSING = 6
    TIME_WAIT = 7

class ReliableRawSocket(RawSocket):
    """
    Extends the RawSocket class to add reliability features:
    - Sequence numbers
    - Acknowledgments
    - Retransmission of lost packets
    - Connection management
    """
    
    def __init__(self, local_ip=None, local_port=0, protocol_id=200, 
                 retransmit_timeout=2.0, max_retries=10):  # Increased timeout and retries
        super().__init__(local_ip, local_port, protocol_id)
        
        # Reliability parameters
        self.retransmit_timeout = retransmit_timeout  # Seconds to wait before retransmitting
        self.max_retries = max_retries                # Maximum retransmission attempts
        
        # Sequence tracking
        self.next_seq_num = 0           # Next sequence number to use
        self.expected_seq_num = 0       # Next expected sequence number
        
        # Connection state
        self.state = ConnectionState.CLOSED
        self.connections = {}  # (ip, port) -> ConnectionState
        
        # Storage for sent packets waiting for ACK
        self.unacked_packets = {}       # seq_num -> (packet_data, attempts, timestamp)
        
        # Start background thread for retransmission and packet handling
        self.running = True
        self.ack_queue = queue.Queue()  # Queue for received ACKs
        self.event_queue = queue.Queue()  # Queue for connection events
        self.retransmit_thread = threading.Thread(target=self._retransmission_handler)
        self.retransmit_thread.daemon = True
        self.retransmit_thread.start()
    
    def create_reliable_packet(self, dst_ip, dst_port, data, packet_type=PacketType.DATA, seq_num=None):
        """
        Create a packet with reliability header information
        """
        # Use provided sequence number or get next available
        if seq_num is None and packet_type == PacketType.DATA:
            seq_num = self.next_seq_num
            self.next_seq_num += 1
        elif seq_num is None:
            seq_num = 0  # For non-data packets like ACK
        
        # Create reliability header (8 bytes):
        # - packet_type (1 byte)
        # - sequence number (4 bytes)
        # - reserved (3 bytes, for future extensions)
        reliability_header = struct.pack('!BI3s', 
            packet_type.value,                 # B: Packet type (1 byte enum)
            seq_num,                           # I: Sequence number (4 bytes)
            b'\x00\x00\x00'                    # 3s: Reserved (3 bytes)
        )
        
        # Let the parent class create the basic packet with our enhanced data
        return super().create_ip_packet(dst_ip, dst_port, reliability_header + data)
    
    def extract_reliable_header(self, packet):
        """
        Extract reliability information from a packet
        """
        # First get the basic header info
        header_info = self.extract_ip_header(packet)
        
        # Now extract our reliability header (8 bytes after the IP+port headers)
        reliability_offset = header_info['header_length']
        reliability_header = packet[reliability_offset:reliability_offset+8]
        
        if len(reliability_header) == 8:
            packet_type_val, seq_num, _ = struct.unpack('!BI3s', reliability_header)
            try:
                packet_type = PacketType(packet_type_val)
            except ValueError:
                packet_type = None
                
            # Update header info with reliability fields
            header_info.update({
                'packet_type': packet_type,
                'seq_num': seq_num,
                'data_offset': reliability_offset + 8  # Start of actual data
            })
            
        return header_info

    def connect(self, dst_ip, dst_port, timeout=10.0):
        """
        Establish a connection with the remote host using a three-way handshake
        """
        # Initialize connection state
        conn_id = (dst_ip, dst_port)
        self.connections[conn_id] = ConnectionState.SYN_SENT
        
        # Step 1: Send SYN packet
        initial_seq = self.next_seq_num
        self.next_seq_num += 1
        syn_packet = self.create_reliable_packet(
            dst_ip, dst_port, b'', 
            packet_type=PacketType.SYN, 
            seq_num=initial_seq
        )
        
        # Store SYN packet for potential retransmission
        self.unacked_packets[initial_seq] = (syn_packet, 0, time.time())
        
        # Send the SYN packet
        self.send_socket.sendto(syn_packet, (dst_ip, 0))
        
        print(f"Sent SYN to {dst_ip}:{dst_port} with seq={initial_seq}")
        
        # Step 2: Wait for SYN-ACK
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Check for direct packets too, not just events
                packet, addr = self.recv_socket.recvfrom(65565)
                header_info = self.extract_reliable_header(packet)
                
                if (header_info['packet_type'] == PacketType.SYN_ACK and 
                    header_info['source_addr'] == dst_ip and 
                    header_info['source_port'] == dst_port):
                    
                    # Got SYN-ACK directly
                    print(f"Received SYN-ACK directly from {dst_ip}:{dst_port}")
                    self.expected_seq_num = header_info['seq_num'] + 1
                    
                    # Step 3: Send ACK
                    ack_packet = self.create_reliable_packet(
                        dst_ip, dst_port, b'',
                        packet_type=PacketType.ACK,
                        seq_num=self.next_seq_num
                    )
                    self.next_seq_num += 1
                    self.send_socket.sendto(ack_packet, (dst_ip, 0))
                    # Send 3 ACKs to increase chances of delivery
                    time.sleep(0.1)
                    self.send_socket.sendto(ack_packet, (dst_ip, 0))
                    time.sleep(0.1)
                    self.send_socket.sendto(ack_packet, (dst_ip, 0))
                    
                    # Add verification that connection is truly established
                    verification_packet = self.create_reliable_packet(
                        dst_ip, dst_port, b'VERIFY', 
                        packet_type=PacketType.DATA,
                        seq_num=self.next_seq_num
                    )
                    self.next_seq_num += 1
                    self.send_socket.sendto(verification_packet, (dst_ip, 0))
                    print(f"Verifying connection to {dst_ip}:{dst_port}")

                    # Connection established
                    self.connections[conn_id] = ConnectionState.ESTABLISHED
                    print(f"Connection established to {dst_ip}:{dst_port}")
                    return True
                    
            except socket.timeout:
                pass
            except Exception as e:
                print(f"Error while waiting for SYN-ACK: {e}")
                
            # Also check the event queue as before
            try:
                event, data = self.event_queue.get(timeout=0.1)
                if event == "SYN_ACK" and data['source_addr'] == dst_ip and data['source_port'] == dst_port:
                    # Got SYN-ACK
                    print(f"Received SYN-ACK from {dst_ip}:{dst_port}")
                    self.expected_seq_num = data['seq_num'] + 1
                    
                    # Step 3: Send ACK
                    ack_packet = self.create_reliable_packet(
                        dst_ip, dst_port, b'',
                        packet_type=PacketType.ACK,
                        seq_num=self.next_seq_num
                    )
                    self.next_seq_num += 1
                    self.send_socket.sendto(ack_packet, (dst_ip, 0))
                    
                    # Connection established
                    self.connections[conn_id] = ConnectionState.ESTABLISHED
                    print(f"Connection established to {dst_ip}:{dst_port}")
                    return True
            except queue.Empty:
                pass
        
        # Timeout waiting for SYN-ACK
        print(f"Connection timeout to {dst_ip}:{dst_port}")
        self.connections[conn_id] = ConnectionState.CLOSED
        return False

    def listen(self):
        """
        Start listening for incoming connections
        """
        self.state = ConnectionState.LISTEN
        print(f"Listening for connections on {self.local_ip}:{self.local_port}")
    
    def accept(self, timeout=None):
        """
        Accept an incoming connection - IMPROVED VERSION
        """
        start_time = time.time()
        while timeout is None or time.time() - start_time < timeout:
            try:
                event, data = self.event_queue.get(timeout=0.1)
                if event == "SYN":
                    # Got SYN packet
                    client_ip = data['source_addr']
                    client_port = data['source_port']
                    conn_id = (client_ip, client_port)
                    
                    print(f"Received connection request from {client_ip}:{client_port}")
                    
                    # Store connection state
                    self.connections[conn_id] = ConnectionState.SYN_RECEIVED
                    
                    # Send SYN-ACK - SEND MULTIPLE TIMES to improve delivery chances
                    syn_ack = self.create_reliable_packet(
                        client_ip, client_port, b'',
                        packet_type=PacketType.SYN_ACK,
                        seq_num=self.next_seq_num
                    )
                    self.next_seq_num += 1
                    
                    # Store for retransmission and send multiple times
                    self.unacked_packets[self.next_seq_num - 1] = (syn_ack, 0, time.time())
                    self.send_socket.sendto(syn_ack, (client_ip, 0))
                    time.sleep(0.1)
                    self.send_socket.sendto(syn_ack, (client_ip, 0))  # Send twice
                    
                    print(f"Sent SYN-ACK to {client_ip}:{client_port}")
                    
                    # Wait for final ACK - IMPROVED DETECTION
                    ack_wait_start = time.time()
                    ack_received = False
                    
                    # Wait longer - 8 seconds instead of 5
                    while time.time() - ack_wait_start < 8.0 and not ack_received:
                        try:
                            # Try to get ACK from event queue
                            event, ack_data = self.event_queue.get(timeout=0.1)
                            if (event == "ACK" and ack_data['source_addr'] == client_ip):
                                # Allow any port from this IP - more flexible
                                ack_received = True
                                from_port = ack_data['source_port']
                                
                                # Record all possible connection IDs
                                alt_conn_id = (client_ip, from_port)
                                self.connections[alt_conn_id] = ConnectionState.ESTABLISHED
                                self.connections[conn_id] = ConnectionState.ESTABLISHED
                                
                                # Reset sequence numbers for new connection
                                self.expected_seq_num = 1
                                print(f"Connection accepted from {client_ip} (ports {client_port},{from_port})")
                                return client_ip, client_port
                            
                        except queue.Empty:
                            # Also check directly for packets - more aggressive ACK detection
                            try:
                                self.recv_socket.settimeout(0.1)
                                packet, addr = self.recv_socket.recvfrom(65565)
                                header_info = self.extract_reliable_header(packet)
                                
                                if (header_info['packet_type'] == PacketType.ACK and 
                                    header_info['source_addr'] == client_ip):
                                    # Got ACK directly
                                    ack_received = True
                                    from_port = header_info['source_port']
                                    
                                    # Record all possible connection IDs
                                    alt_conn_id = (client_ip, from_port)
                                    self.connections[alt_conn_id] = ConnectionState.ESTABLISHED
                                    self.connections[conn_id] = ConnectionState.ESTABLISHED
                                    
                                    # Reset sequence numbers for new connection
                                    self.expected_seq_num = 1
                                    print(f"Connection accepted (direct ACK) from {client_ip} (ports {client_port},{from_port})")
                                    return client_ip, client_port
                                    
                            except socket.timeout:
                                pass
                            except Exception as e:
                                print(f"Error checking for direct ACK: {e}")
                    
                    # ACK timeout
                    if not ack_received:
                        print(f"Client {client_ip}:{client_port} didn't complete handshake")
                        # Don't immediately close - give client a chance
                        # Just leave in SYN_RECEIVED state
                    else:
                        # We should never reach here due to returns above
                        return client_ip, client_port
            
            except queue.Empty:
                # Also check directly for SYN packets
                try:
                    self.recv_socket.settimeout(0.1)
                    packet, addr = self.recv_socket.recvfrom(65565)
                    header_info = self.extract_reliable_header(packet)
                    
                    if (header_info['packet_type'] == PacketType.SYN):
                        # Got SYN directly - add to event queue
                        self.event_queue.put(("SYN", header_info))
                        
                except socket.timeout:
                    pass
                except Exception as e:
                    pass
        
        return None, None
    
    def close_connection(self, dst_ip, dst_port, timeout=5.0):
        """
        Close connection with graceful FIN handshake
        """
        conn_id = (dst_ip, dst_port)
        if conn_id not in self.connections or self.connections[conn_id] != ConnectionState.ESTABLISHED:
            return False
        
        # Send FIN
        self.connections[conn_id] = ConnectionState.FIN_WAIT
        fin_packet = self.create_reliable_packet(
            dst_ip, dst_port, b'',
            packet_type=PacketType.FIN,
            seq_num=self.next_seq_num
        )
        self.next_seq_num += 1
        
        self.unacked_packets[self.next_seq_num - 1] = (fin_packet, 0, time.time())
        self.send_socket.sendto(fin_packet, (dst_ip, 0))
        
        print(f"Sent FIN to {dst_ip}:{dst_port}")
        
        # Wait for FIN-ACK
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                event, data = self.event_queue.get(timeout=0.1)
                if (event == "FIN_ACK" and data['source_addr'] == dst_ip and 
                    data['source_port'] == dst_port):
                    # Connection closed
                    self.connections[conn_id] = ConnectionState.CLOSED
                    
                    # Send final ACK
                    ack_packet = self.create_reliable_packet(
                        dst_ip, dst_port, b'',
                        packet_type=PacketType.ACK,
                        seq_num=self.next_seq_num
                    )
                    self.next_seq_num += 1
                    self.send_socket.sendto(ack_packet, (dst_ip, 0))
                    
                    print(f"Connection to {dst_ip}:{dst_port} closed")
                    return True
            except queue.Empty:
                pass
        
        # Timeout
        print(f"Timeout closing connection to {dst_ip}:{dst_port}")
        self.connections[conn_id] = ConnectionState.CLOSED
        return False
    
    def send_reliable(self, dst_ip, dst_port, data, timeout=10.0):
        """
        Send data with reliability guarantees
        """
        conn_id = (dst_ip, dst_port)
        
        # Check if connection is established
        if conn_id not in self.connections or self.connections[conn_id] != ConnectionState.ESTABLISHED:
            print(f"Not connected to {dst_ip}:{dst_port}, attempting to connect...")
            # Auto-connect if not connected
            if not self.connect(dst_ip, dst_port, timeout):
                return False
        
        try:
            # Convert string to bytes if needed
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Create packet with reliability header
            packet = self.create_reliable_packet(dst_ip, dst_port, data)
            seq_num = self.next_seq_num - 1  # The sequence number we just used
            
            # Store packet for potential retransmission
            self.unacked_packets[seq_num] = (packet, 0, time.time())
            
            # Send the packet
            self.send_socket.sendto(packet, (dst_ip, 0))
            
            # Wait for acknowledgment
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    ack_seq = self.ack_queue.get(timeout=0.1)
                    if ack_seq == seq_num:
                        # Got ACK for our packet
                        if seq_num in self.unacked_packets:
                            del self.unacked_packets[seq_num]
                        return True
                except queue.Empty:
                    # No ACK yet, continue waiting
                    pass
                    
            return False  # Timeout waiting for ACK
        except Exception as e:
            print(f"Error sending reliable data: {e}")
            return False
    
    def receive_reliable(self, timeout=5.0, filter_addr=None, filter_port=None):
        """
        Receive data with reliability guarantees - IMPROVED VERSION
        """
        try:
            self.recv_socket.settimeout(timeout)
            
            while True:
                # Receive a packet
                packet, addr = self.recv_socket.recvfrom(65565)
                
                # Extract header including reliability info
                header_info = self.extract_reliable_header(packet)
                
                # Check filters
                if filter_addr and header_info['source_addr'] != filter_addr:
                    continue
                if filter_port and header_info['source_port'] != filter_port:
                    continue
                
                src_ip = header_info['source_addr']
                src_port = header_info['source_port']
                conn_id = (src_ip, src_port)
                
                # Process based on packet type
                if header_info['packet_type'] == PacketType.DATA:
                    # IMPROVED CONNECTION CHECKING - Check for any connection from this IP
                    is_established = False
                    established_port = None
                    
                    # Direct check first
                    if conn_id in self.connections and self.connections[conn_id] == ConnectionState.ESTABLISHED:
                        is_established = True
                        established_port = src_port
                    
                    # Check all connections from this IP
                    if not is_established:
                        for (ip, port), state in self.connections.items():
                            if ip == src_ip and state == ConnectionState.ESTABLISHED:
                                is_established = True
                                established_port = port
                                # Record this new port combination
                                self.connections[conn_id] = ConnectionState.ESTABLISHED
                                print(f"Updated connection ID from {ip}:{port} to {src_ip}:{src_port}")
                                break
                    
                    # Also check SYN_RECEIVED state - might be waiting for ACK
                    if not is_established:
                        for (ip, port), state in self.connections.items():
                            if ip == src_ip and state == ConnectionState.SYN_RECEIVED:
                                # If we have a SYN_RECEIVED, auto-promote to ESTABLISHED
                                is_established = True
                                established_port = port
                                # Update both port combinations to ESTABLISHED
                                self.connections[(ip, port)] = ConnectionState.ESTABLISHED
                                self.connections[conn_id] = ConnectionState.ESTABLISHED
                                print(f"Auto-promoted connection from SYN_RECEIVED to ESTABLISHED: {src_ip}:{src_port}")
                                break
                    
                    # Special handling for "VERIFY" message - always ACK this
                    data = packet[header_info['data_offset']:]
                    try:
                        if data.decode('utf-8') == "VERIFY":
                            print(f"Received verification message from {src_ip}:{src_port}")
                            # Always ACK verification messages
                            self._send_ack(src_ip, src_port, header_info['seq_num'])
                            # If in listening state, auto-establish connection
                            if self.state == ConnectionState.LISTEN and not is_established:
                                self.connections[conn_id] = ConnectionState.ESTABLISHED
                                print(f"Auto-establishing connection from VERIFY: {src_ip}:{src_port}")
                                is_established = True
                            return data, src_ip, src_port
                    except:
                        pass  # Not a VERIFY message, continue normal processing
                    
                    if not is_established:
                        print(f"Received data from non-established connection: {src_ip}:{src_port}")
                        # Try to auto-establish if possible
                        if self.state == ConnectionState.LISTEN:
                            print(f"Auto-establishing connection with {src_ip}:{src_port}")
                            self.connections[conn_id] = ConnectionState.ESTABLISHED
                            is_established = True
                        else:
                            # Send ACK anyway to avoid retransmissions
                            self._send_ack(src_ip, src_port, header_info['seq_num'])
                            continue
                    
                    # Always ACK the packet to prevent excessive retransmissions
                    self._send_ack(src_ip, src_port, header_info['seq_num'])
                    # Send multiple ACKs to improve delivery chances
                    time.sleep(0.05)
                    self._send_ack(src_ip, src_port, header_info['seq_num'])
                    
                    # Update expected sequence if higher
                    if header_info['seq_num'] >= self.expected_seq_num:
                        self.expected_seq_num = header_info['seq_num'] + 1
                    
                    # Return the data
                    return data, src_ip, src_port
                
                elif header_info['packet_type'] == PacketType.ACK:
                    # Put ACK in queue for send_reliable to process
                    self.ack_queue.put(header_info['seq_num'])
                    
                    # Also check if this is an ACK for connection establishment
                    # More flexible connection handling - check any connection from this IP
                    found = False
                    for (ip, port), state in list(self.connections.items()):
                        if ip == src_ip and state == ConnectionState.SYN_RECEIVED:
                            # Found a matching connection in SYN_RECEIVED state
                            self.event_queue.put(("ACK", header_info))
                            self.connections[(ip, port)] = ConnectionState.ESTABLISHED
                            # Also register this specific port
                            self.connections[conn_id] = ConnectionState.ESTABLISHED
                            print(f"Received final handshake ACK from {src_ip}:{src_port}")
                            found = True
                            break
                    
                    if not found and conn_id in self.connections and self.connections[conn_id] == ConnectionState.SYN_RECEIVED:
                        # Direct check
                        self.event_queue.put(("ACK", header_info))
                        self.connections[conn_id] = ConnectionState.ESTABLISHED
                        print(f"Received final handshake ACK from {src_ip}:{src_port}")
                
                elif header_info['packet_type'] == PacketType.SYN:
                    # Connection request
                    if self.state == ConnectionState.LISTEN:
                        # Add to event queue for accept() to process
                        self.event_queue.put(("SYN", header_info))
                    
                elif header_info['packet_type'] == PacketType.SYN_ACK:
                    # SYN-ACK response during connection
                    self.event_queue.put(("SYN_ACK", header_info))
                
                elif header_info['packet_type'] == PacketType.FIN:
                    # More flexible FIN handling - check any connection from this IP
                    conn_found = False
                    
                    # Check all connections from this IP
                    for (ip, port), state in list(self.connections.items()):
                        if ip == src_ip and state != ConnectionState.CLOSED:
                            # Send FIN-ACK
                            fin_ack = self.create_reliable_packet(
                                src_ip, src_port, b'',
                                packet_type=PacketType.FIN_ACK,
                                seq_num=self.next_seq_num
                            )
                            self.next_seq_num += 1
                            self.send_socket.sendto(fin_ack, (src_ip, 0))
                            # Send twice to improve delivery chances
                            time.sleep(0.1)
                            self.send_socket.sendto(fin_ack, (src_ip, 0))
                            
                            self.connections[(ip, port)] = ConnectionState.CLOSED
                            print(f"Received FIN from {src_ip}:{src_port}, connection closed")
                            conn_found = True
                    
                    if not conn_found and conn_id in self.connections:
                        # Direct check as fallback
                        fin_ack = self.create_reliable_packet(
                            src_ip, src_port, b'',
                            packet_type=PacketType.FIN_ACK,
                            seq_num=self.next_seq_num
                        )
                        self.next_seq_num += 1
                        self.send_socket.sendto(fin_ack, (src_ip, 0))
                        self.connections[conn_id] = ConnectionState.CLOSED
                        print(f"Received FIN from {src_ip}:{src_port}, connection closed")
                    
                elif header_info['packet_type'] == PacketType.FIN_ACK:
                    # FIN acknowledged
                    self.event_queue.put(("FIN_ACK", header_info))
                    
        except socket.timeout:
            return None, None, None
        except Exception as e:
            print(f"Error receiving reliable data: {e}")
            return None, None, None
    
    def _send_ack(self, dst_ip, dst_port, seq_num):
        """
        Send an acknowledgment packet
        """
        # ACK packets have no data, just headers
        ack_packet = self.create_reliable_packet(
            dst_ip, dst_port, b'', 
            packet_type=PacketType.ACK, seq_num=seq_num
        )
        self.send_socket.sendto(ack_packet, (dst_ip, 0))
    
    def _retransmission_handler(self):
        """
        Background thread that retransmits unacknowledged packets
        """
        while self.running:
            current_time = time.time()
            
            # Check all unacknowledged packets
            for seq_num, (packet, attempts, timestamp) in list(self.unacked_packets.items()):
                # If packet has been waiting longer than timeout
                if current_time - timestamp > self.retransmit_timeout:
                    if attempts < self.max_retries:
                        # Retransmit
                        try:
                            # Extract destination IP from packet
                            header_info = self.extract_ip_header(packet)
                            dst_ip = header_info['dest_addr']
                            
                            # Resend the packet
                            self.send_socket.sendto(packet, (dst_ip, 0))
                            
                            # Update attempts and timestamp
                            self.unacked_packets[seq_num] = (
                                packet, attempts + 1, current_time
                            )
                        except Exception as e:
                            print(f"Error retransmitting packet {seq_num}: {e}")
                    else:
                        # Max retries reached, consider packet lost
                        print(f"Packet {seq_num} lost after {attempts} attempts")
                        
                        # Check if this was a connection packet
                        try:
                            header_info = self.extract_reliable_header(packet)
                            if header_info['packet_type'] in [PacketType.SYN, PacketType.SYN_ACK, PacketType.FIN]:
                                dst_ip = header_info['dest_addr']
                                dst_port = header_info['dest_port']
                                conn_id = (dst_ip, dst_port)
                                if conn_id in self.connections:
                                    self.connections[conn_id] = ConnectionState.CLOSED
                                    print(f"Connection to {dst_ip}:{dst_port} failed due to packet loss")
                        except:
                            pass
                            
                        del self.unacked_packets[seq_num]
            
            # Sleep to avoid consuming too much CPU
            time.sleep(0.1)
    
    def close(self):
        """
        Close the reliable socket, stopping background threads
        """
        # Close all active connections
        for (dst_ip, dst_port), state in list(self.connections.items()):
            if state == ConnectionState.ESTABLISHED:
                try:
                    self.close_connection(dst_ip, dst_port)
                except:
                    pass
        
        self.running = False
        if hasattr(self, 'retransmit_thread') and self.retransmit_thread.is_alive():
            self.retransmit_thread.join(2.0)  # Wait up to 2 seconds
        
        try:
            # Check if sockets are still valid before closing
            if hasattr(self, 'send_socket') and self.send_socket:
                self.send_socket.close()
            if hasattr(self, 'recv_socket') and self.recv_socket:
                self.recv_socket.close()
        except Exception as e:
            print(f"Error during socket close: {e}")