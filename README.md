# Network Scanner

A lightweight network scanning utility that uses ICMP echo requests (ping) to check the availability of network endpoints. This tool sends raw ICMP packets to determine if a target host is reachable on the network.

## Features

- Send ICMP echo requests to check host availability
- Configurable target IP address and port
- Raw socket implementation with custom IP and ICMP header construction
- Automatic detection of local IPv4 address
- Success rate statistics
- Detailed packet information reporting

## Requirements

- Linux operating system (Ubuntu 24 or similar)
- Root/sudo privileges (required for raw socket operations)
- GCC compiler
- Standard C libraries

## Building

Compile the program using GCC:

```bash
gcc -o scan network_scanner_documented.c -Wall
```

## Usage

The program requires root privileges to create raw sockets:

```bash
sudo ./scan [OPTIONS]
```

### Command-Line Options

| Option | Long Option | Description | Default |
|--------|-------------|-------------|---------|
| `-p` | `--port` | Target port number | 8080 |
| `-h` | `--target_ip` | Target IPv4 address | localhost |

### Examples

Scan localhost on default port (8080):
```bash
sudo ./scan
```

Scan a specific IP address:
```bash
sudo ./scan -h 192.168.1.100
```

Scan a specific IP and port:
```bash
sudo ./scan -h 192.168.1.100 -p 80
```

Using long options:
```bash
sudo ./scan --target_ip 192.168.1.100 --port 443
```

## How It Works

1. **Initialization**: The program validates root privileges and parses command-line arguments
2. **Local IP Detection**: Automatically detects the local machine's IPv4 address from wireless interfaces (wl*)
3. **Socket Creation**: Creates raw sockets for sending and receiving ICMP packets
4. **Packet Construction**: Builds custom IP and ICMP headers with proper checksums
5. **Packet Transmission**: Sends 30 ICMP echo request packets to the target
6. **Reply Processing**: Listens for ICMP echo replies with a 5-second timeout per packet
7. **Statistics**: Reports the success rate and detailed information about each packet

## Technical Details

### ICMP Packet Structure

The program constructs raw ICMP packets with:
- **IP Header**: Version 4, TTL 64, Protocol ICMP
- **ICMP Header**: Type ECHO (8), Code 0
- **Data Payload**: 32 bytes of 'A' characters

### Checksum Calculation

Uses the standard Internet checksum algorithm (RFC 1071) for both IP and ICMP headers.

### Configuration Constants

- `ICMP_PACKET_CNT`: Number of packets to send (30)
- `ICMP_PACKET_DATA`: Size of ICMP data payload (32 bytes)
- Receive timeout: 5 seconds per packet

## Output

The program provides detailed output including:
- Local IPv4 address detection
- Bytes sent per packet
- Received packet information (source IP, TTL, sequence number, ICMP type)
- Echo reply confirmations
- Final success statistics with percentage

Example output:
```
Getting current IPv4 address ...
Current ipv4 address of the machine: 192.168.1.50
Starting network scan...
Sending ICMP to the ipv4 adress: 192.168.1.100
Sent 84 bytes ...
Received 84 byte packets from=192.168.1.100   ip_ttl=64   icmp_seq=0   icmp_type=8 ( Received ECHO REPLY from 192.168.1.100)
...
Ping test completed ! 28/30 (93.3333%) transmitted successfully
```

## Error Handling

The program handles various error conditions:
- Insufficient privileges (non-root execution)
- Socket creation failures
- Memory allocation failures
- Packet send/receive failures
- Timeout conditions (no response)
- Invalid ICMP packet formats

## Network Interface Detection

The program automatically detects the local IPv4 address by:
1. Enumerating all network interfaces
2. Filtering for IPv4 addresses (AF_INET)
3. Selecting wireless interfaces (names starting with "wl")

If no suitable interface is found, the program returns an error.

## Limitations

- Only supports IPv4 addresses
- Requires wireless interface (wl*) for automatic IP detection
- Requires root privileges for raw socket operations
- Fixed packet count (30 packets)
- Fixed timeout (5 seconds per packet)
- Does not support IPv6

## Security Considerations

⚠️ **Warning**: This tool requires root privileges and uses raw sockets. Use responsibly and only on networks you own or have permission to scan.

- Raw socket access can be a security risk
- Ensure proper network permissions before scanning
- May trigger intrusion detection systems
- Some networks block ICMP packets

## Troubleshooting

### "This program requires root privileges to run"
Run the program with `sudo`:
```bash
sudo ./scan
```

### "No TCP interface found"
The program cannot detect a wireless interface. Possible solutions:
- Ensure you have a wireless adapter connected
- Modify the `checkIfName()` function to match your interface naming (e.g., "eth", "en")

### "Failed to create a new socket"
- Verify root privileges
- Check if raw socket support is enabled in your kernel
- Ensure no firewall is blocking raw socket operations

### Timeouts
If you experience many timeouts:
- Verify the target IP is correct and reachable
- Check firewall rules on both source and destination
- Verify the target host responds to ICMP requests
- Some hosts may have ICMP disabled

## Code Structure

```
network_scanner_documented.c
├── Data Structures
│   └── NetworkEndpoint
├── Utility Functions
│   ├── csum() - Checksum calculation
│   ├── ConvertStrToInt() - String to integer conversion
│   ├── checkIfName() - Interface name validation
│   └── getCurrentIpv4Addr() - Local IP detection
├── Core Functions
│   ├── InitEndpoint() - Endpoint initialization
│   └── ScanNetworkEndpoint() - Main scanning logic
└── main() - Entry point and argument parsing
```

## Contributing

Contributions are welcome! Areas for improvement:
- IPv6 support
- Configurable packet count and timeout
- Support for additional network interface types
- TCP/UDP scanning capabilities
- Enhanced error reporting
- Configuration file support

## License

This is educational/demonstration code. Use at your own risk and ensure compliance with local laws and network policies.

## Disclaimer

This tool is provided for educational and network administration purposes only. Always obtain proper authorization before scanning networks. Unauthorized network scanning may be illegal in your jurisdiction.

## Author

Network Scanner - ICMP Ping Implementation

## Version

1.0.0
