import socket  # Provides low-level networking interface
import struct  # Handles binary data conversion
import time    # For timestamp generation
import os      # For OS-related operations
import sys     # For system-specific parameters
import ctypes  # For accessing system functions like checking admin privileges

class RawSocket:
    """
    A class to simplify working with raw sockets for network communication.
    
    WHAT ARE RAW SOCKETS?
    ---------------------
    Raw sockets give direct access to the network protocol layer, bypassing the 
    normal TCP/UDP socket interface. This allows creating custom packet structures,
    implementing custom protocols, and having more control over networking.
    
    This implementation adds port support on top of raw IP packets, which usually
    don't have port concepts (ports normally come from TCP/UDP).
    """
    
    def __init__(self, local_ip=None, local_port=0, protocol_id=200):
        """
        Initialize a raw socket connection.
        
        Parameters:
        - local_ip: The IP address of this machine (None to auto-detect)
          When None, it automatically detects your machine's IP address
        - local_port: The local port to use (default: 0)
          This is our custom port concept, not a standard OS port
        - protocol_id: The custom protocol ID to use (default: 200)
          IP protocol numbers are 8-bit values identifying the next level protocol
          Values below 143 are assigned to standard protocols (TCP=6, UDP=17)
          We use 200 as an unassigned protocol number for our custom protocol
        """
        # Check for admin privileges first - raw sockets require admin/root access
        # for security reasons (they could be used for network attacks)
        self._check_admin_privileges()
        
        # Store configuration for later use
        self.protocol_id = protocol_id
        # If no IP specified, get the local machine's IP address
        self.local_ip = local_ip or socket.gethostbyname(socket.gethostname())
        self.local_port = local_port
        
        # These socket objects will be created in _create_sockets method:
        # - send_socket: for sending custom packets
        # - recv_socket: for receiving packets with our protocol ID
        self.send_socket = None
        self.recv_socket = None
        self._create_sockets()
        
        print(f"Raw socket initialized at {self.local_ip}:{self.local_port}")
    
    def _check_admin_privileges(self):
        """
        Check if the script is running with admin/root privileges.
        
        Raw sockets require elevated privileges because they allow for:
        1. Packet sniffing (security risk)
        2. IP spoofing (pretending to be another machine)
        3. Other potentially dangerous network operations
        
        Different checks are needed for Windows vs. Unix systems.
        """
        if os.name == 'nt':  # Windows
            # On Windows, IsUserAnAdmin() returns True if running as administrator
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError("Raw sockets require administrator privileges")
        else:  # Unix/Linux
            # On Unix systems, root has user ID 0
            if os.geteuid() != 0:
                raise PermissionError("Raw sockets require root privileges")
    
    def _create_sockets(self):
        """
        Create two different socket objects for sending and receiving.
        
        1. SEND SOCKET:
           - Uses SOCK_RAW + IPPROTO_RAW to allow complete control over IP header
           - IP_HDRINCL flag tells the kernel we're providing our own IP headers
        
        2. RECEIVE SOCKET:
           - Uses SOCK_RAW + our custom protocol_id to receive packets
           - Bound to our local IP to only receive packets intended for us
        """
        try:
            # Create a socket for sending data:
            # - AF_INET: IPv4 address family
            # - SOCK_RAW: Raw packet access
            # - IPPROTO_RAW: We'll provide complete packet including IP header
            self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # IP_HDRINCL tells the kernel we'll include our own IP headers
            # Without this, the kernel would add its own IP header
            self.send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Create a socket for receiving data:
            # - This time we use our protocol_id to only receive packets with that protocol
            self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.protocol_id)
            # Bind to our local IP so we only get packets sent to us
            # Port 0 means the OS can choose any port for the underlying socket
            # (but we track our custom ports separately in the packet payload)
            self.recv_socket.bind((self.local_ip, 0))
        except socket.error as e:
            # If socket creation fails, ensure we clean up any sockets
            # that were successfully created
            self.close()
            raise RuntimeError(f"Socket creation failed: {e}")
    
    def create_ip_packet(self, dst_ip, dst_port, data):
        """
        Create a complete IP packet with embedded port information.
        
        PACKET STRUCTURE:
        ----------------
        | IP Header (20 bytes) | Port Header (4 bytes) | Data (variable) |
        
        IP HEADER FIELDS:
        - ip_ver: IP version (4 for IPv4)
        - ip_ihl: Internet Header Length (5 words = 20 bytes for basic header)
        - ip_tos: Type of Service (priority)
        - ip_tot_len: Total packet length
        - ip_id: Identification field (helps with fragmentation)
        - ip_frag_off: Fragment offset (for reassembly)
        - ip_ttl: Time to Live (prevents infinite routing loops)
        - ip_proto: Protocol number (identifies what follows the IP header)
        - ip_check: Header checksum (we set to 0, kernel will calculate)
        - ip_saddr: Source IP address
        - ip_daddr: Destination IP address
        
        PORT HEADER (our custom addition):
        - 2 bytes for source port
        - 2 bytes for destination port
        """
        # IP header fields
        ip_ver = 4  # IPv4
        ip_ihl = 5  # Header length in 32-bit words (5 × 4 = 20 bytes)
        ip_tos = 0  # Type of service (0 is normal)
        ip_tot_len = 20 + 4 + len(data)  # IP header + port header + data
        ip_id = int(time.time()) & 0xFFFF  # Packet ID (using timestamp)
        ip_frag_off = 0  # No fragmentation
        ip_ttl = 64  # Time to live in seconds/hops
        ip_proto = self.protocol_id  # Our custom protocol number
        ip_check = 0  # Checksum (let kernel fill this)
        ip_saddr = socket.inet_aton(self.local_ip)  # Convert IP string to binary
        ip_daddr = socket.inet_aton(dst_ip)  # Convert destination IP to binary
        
        # First byte combines version and header length
        # Example: Version 4 (0100) and IHL 5 (0101) becomes 01000101 = 69 decimal
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        # Pack the IP header using struct.pack
        # '!' means network byte order (big-endian)
        # B = unsigned char (1 byte), H = unsigned short (2 bytes), 4s = 4-byte string
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ihl_ver,   # B: Version + Header Length
            ip_tos,       # B: Type of Service
            ip_tot_len,   # H: Total Length
            ip_id,        # H: Identification
            ip_frag_off,  # H: Flags + Fragment Offset
            ip_ttl,       # B: Time to Live
            ip_proto,     # B: Protocol
            ip_check,     # H: Header Checksum
            ip_saddr,     # 4s: Source Address
            ip_daddr)     # 4s: Destination Address
        
        # Add port information (source and destination ports)
        # '!' means network byte order
        # H = unsigned short (2 bytes) for each port
        port_header = struct.pack('!HH', self.local_port, dst_port)
        
        # Return the complete packet: IP header + port header + data
        return ip_header + port_header + data
    
    def extract_ip_header(self, packet):
        """
        Extract and decode the IP header and our custom port header from a received packet.
        
        This method unpacks the binary data back into readable values.
        
        Parameters:
        - packet: Raw binary packet data as received
        
        Returns:
        - Dictionary with decoded header information
        """
        # First 20 bytes are the IP header
        ip_header = packet[0:20]
        
        # Unpack the header using the same format as when we created it
        # Returns a tuple of values in the same order as packed
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # First byte contains both version and header length
        version_ihl = iph[0]
        version = version_ihl >> 4  # Right-shift by 4 bits to get version
        ihl = version_ihl & 0xF     # Bitwise AND with 0xF to get header length
        
        # IHL is in 32-bit words, so multiply by 4 to get bytes
        iph_length = ihl * 4
        
        # Extract other IP header fields
        protocol = iph[6]  # Protocol number
        # Convert binary IPs back to string format (like "192.168.1.1")
        s_addr = socket.inet_ntoa(iph[8])  # Source IP
        d_addr = socket.inet_ntoa(iph[9])  # Destination IP
        
        # Extract our custom port header (after the IP header)
        port_header = packet[iph_length:iph_length+4]
        if len(port_header) == 4:
            # Unpack 2 unsigned shorts (source and destination ports)
            source_port, dest_port = struct.unpack('!HH', port_header)
        else:
            # If port header missing or incomplete, use default values
            source_port, dest_port = 0, 0
        
        # Return all extracted information as a dictionary
        return {
            'version': version,
            'ihl': ihl,
            'protocol': protocol,
            'source_addr': s_addr,
            'dest_addr': d_addr,
            'source_port': source_port,
            'dest_port': dest_port,
            'header_length': iph_length + 4  # Total header length (IP + port)
        }
    
    def send(self, dst_ip, dst_port, data):
        """
        Send data to the specified destination IP and port.
        
        This method:
        1. Converts string data to bytes if needed
        2. Creates a complete packet with headers and data
        3. Sends the packet to the destination IP
        
        Note: The port is handled within our custom packet structure,
        not by the operating system's network stack.
        
        Parameters:
        - dst_ip: Destination IP address (string like "192.168.1.1")
        - dst_port: Destination port number
        - data: Data to send (string or bytes)
        
        Returns:
        - True if successfully sent, False if an error occurred
        """
        try:
            # Convert string to bytes if needed
            # Bytes are the raw binary format needed for network transmission
            if isinstance(data, str):
                data = data.encode('utf-8')
                
            # Create the complete packet with headers and data
            packet = self.create_ip_packet(dst_ip, dst_port, data)
            
            # Send the packet to the destination IP
            # The (dst_ip, 0) tuple is required by the sendto method,
            # but the port value (0) is ignored because we're using raw sockets
            # and including our own port in the packet
            self.send_socket.sendto(packet, (dst_ip, 0))
            return True
        except Exception as e:
            print(f"Error sending data: {e}")
            return False
    
    def receive(self, timeout=5.0, filter_addr=None, filter_port=None):
        """
        Receive data from the network.
        
        This method:
        1. Waits for a packet with our protocol ID
        2. Extracts header information
        3. Filters packets based on source IP/port if specified
        4. Returns the data portion of the packet
        
        Parameters:
        - timeout: How long to wait for data in seconds
        - filter_addr: Only accept packets from this source IP (optional)
        - filter_port: Only accept packets from this source port (optional)
        
        Returns:
        - A tuple of (data, source_ip, source_port) if successful
        - (None, None, None) if timeout or error occurs
        """
        try:
            # Set timeout for receiving to avoid blocking forever
            self.recv_socket.settimeout(timeout)
            
            # Keep trying until we get a matching packet or timeout
            while True:
                # Receive a packet (65565 is max possible IP packet size)
                packet, addr = self.recv_socket.recvfrom(65565)
                
                # Extract and decode the headers
                header_info = self.extract_ip_header(packet)
                
                # FILTERING:
                # If filters are specified, check if this packet matches
                
                # Check source address if filter is set
                if filter_addr and header_info['source_addr'] != filter_addr:
                    continue  # Skip this packet, try for another one
                
                # Check source port if filter is set
                if filter_port and header_info['source_port'] != filter_port:
                    continue  # Skip this packet, try for another one
                
                # Extract just the data part of the packet
                # (everything after our headers)
                data = packet[header_info['header_length']:]
                
                # Return the data along with source information
                return data, header_info['source_addr'], header_info['source_port']
                
        except socket.timeout:
            # If we timed out waiting for data
            return None, None, None
        except Exception as e:
            # If any other error occurred
            print(f"Error receiving data: {e}")
            return None, None, None
    
    def close(self):
        """
        Close the socket connections.
        
        It's important to properly close sockets when done to:
        1. Free up system resources
        2. Release bound ports
        3. Avoid socket-related memory leaks
        """
        # Close the send socket if it exists
        if self.send_socket:
            self.send_socket.close()
            self.send_socket = None
            
        # Close the receive socket if it exists
        if self.recv_socket:
            self.recv_socket.close()
            self.recv_socket = None
    
    def __del__(self):
        """
        Destructor method called when object is garbage collected.
        
        This ensures sockets are closed even if the user forgets
        to call the close() method explicitly.
        """
        self.close()


# Example usage
if __name__ == "__main__":
    """
    This section runs only when the script is executed directly.
    It demonstrates how to use the RawSocket class for basic communication.
    
    WHAT HAPPENS DURING THIS TEST:
    -----------------------------
    1. Create a raw socket
    2. Send a test message to our own machine
    3. Wait to receive the message back
    4. Display the received data
    
    This works because we're sending to our own IP address, and our
    receive socket is bound to the same IP, so we receive our own packet.
    """
    # Test the raw socket implementation
    print("Testing raw socket implementation...")
    
    # Create a raw socket instance
    raw_socket = RawSocket()
    
    # Define test parameters
    test_msg = "Hello, Raw Socket!"
    dest_ip = raw_socket.local_ip  # Send to ourselves for testing
    dest_port = 12345  # Example destination port
    
    # Send a test message
    print(f"Sending test message to {dest_ip}:{dest_port}...")
    raw_socket.send(dest_ip, dest_port, test_msg)
    
    # Try to receive the message (with 3 second timeout)
    print("Waiting for response...")
    data, src_ip, src_port = raw_socket.receive(timeout=3.0)
    
    # Process and display the received data
    if data:
        try:
            # Try to decode the received data as UTF-8 text
            decoded = data.decode('utf-8')
            print(f"Received from {src_ip}:{src_port}: {decoded}")
        except UnicodeDecodeError:
            # If it's not valid UTF-8 text, treat as binary data
            print(f"Received {len(data)} bytes of binary data from {src_ip}:{src_port}")
    else:
        print("No data received")
    
    # Clean up by closing the socket
    raw_socket.close()