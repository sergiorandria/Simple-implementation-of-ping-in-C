/*Copyright (c) 2025 Sergio Randriamihoatra.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <asm-generic/socket.h>
#include <bits/getopt_core.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define ICMP_PACKET_CNT 30
#define ICMP_PACKET_DATA 32

/**
 * @struct NetworkEndpoint
 * @brief Represents a network endpoint with address, port, and status
 * information
 *
 * This structure contains all the necessary information about a network
 * endpoint including its socket address, netmask, broadcast address, ports, and
 * alive status.
 */
typedef struct {
  struct sockaddr_in sockaddr;
  struct sockaddr *endpointNetmask;
  struct sockaddr *broadAddr;

  int src_port;
  int dst_port;

  _Bool isAlive;
} NetworkEndpoint;

bool ip_address_given;
bool port_given;

static int ConvertStrToInt(const char *str_ipaddr);
static void InitEndpoint(char *ip_addr, int port, NetworkEndpoint *endpoint);
static char *getCurrentIpv4Addr();
static _Bool checkIfName(char *ifname);

/**
 * @brief Calculate the Internet checksum of a packet
 *
 * Calculates the checksum used in IP and ICMP headers using the standard
 * Internet checksum algorithm (RFC 1071). The checksum is computed by
 * summing 16-bit words and folding the carry bits.
 *
 * @param addr Pointer to the data buffer (struct icmp or struct ip)
 * @param len Size of the data buffer in bytes
 * @return The calculated checksum as an unsigned short, or -1 if addr is NULL
 */
unsigned short csum(unsigned short *addr, int len) {
  int sum = 0;

  if (addr == NULL) {
    fprintf(stderr, "ADDR is NULLL!\n");
    return -1;
  }

  while (len > 1) {
    sum += *addr++;
    len -= 2;
  }

  if (len == 1) {
    sum += *(unsigned char *)addr;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  return (unsigned short)(~sum);
}

/**
 * @brief Alternative checksum calculation using hypercube algorithm
 *
 * This is a placeholder for an alternative checksum implementation
 * using the hypercube algorithm. Currently not implemented.
 *
 * @param addr Pointer to the data buffer
 * @param len Size of the data buffer in bytes
 * @return The calculated checksum as an unsigned short
 */
__attribute_maybe_unused__ unsigned short csum2(unsigned short *addr, int len) {

}

/**
 * @brief Initialize a NetworkEndpoint structure with IP address and port
 *
 * Sets up a NetworkEndpoint structure with the provided IP address and port.
 * Initializes the socket address family to AF_INET and sets the isAlive flag to
 * false.
 *
 * @param ip_addr String representation of the IPv4 address
 * @param port Port number for the endpoint
 * @param endpoint Pointer to the NetworkEndpoint structure to initialize
 */
static void InitEndpoint(char *ip_addr, int port, NetworkEndpoint *endpoint) {
  // Should be set to true after scanning
  endpoint->sockaddr.sin_family = AF_INET;
  endpoint->sockaddr.sin_addr.s_addr = inet_addr(ip_addr);
  endpoint->sockaddr.sin_port = htons(port);

  endpoint->isAlive = false;
}

/**
 * @brief Convert a string to an integer
 *
 * Parses a numeric string and converts it to an integer value.
 * Stops parsing at the first non-digit character.
 *
 * @param str_ipaddr String containing numeric characters
 * @return The parsed integer value
 */
static int ConvertStrToInt(const char *str_ipaddr) {
  int res = 0;
  size_t len = strlen(str_ipaddr);

  for (int i = 0; i < len && isdigit(str_ipaddr[i]); ++i) {
    res = 10 * res + (str_ipaddr[i] - '0');
  }

  return res;
}

/**
 * @brief Get the current machine's IPv4 address
 *
 * Queries all network interfaces on the system and returns the IPv4 address
 * of the first interface matching the criteria (typically wireless interfaces
 * starting with "wl"). The returned string must be freed by the caller.
 *
 * @return Pointer to a dynamically allocated string containing the IPv4
 * address, or NULL if no suitable interface is found
 */
static char *getCurrentIpv4Addr() {
  fprintf(stdout, "Getting current IPv4 address ...\n");

  struct ifaddrs *addrs;

  getifaddrs(&addrs);
  struct ifaddrs *tmp = addrs;

  while (tmp != NULL) {
    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
      if (checkIfName(tmp->ifa_name)) {
        struct sockaddr_in *eAddr = (struct sockaddr_in *)tmp->ifa_addr;
        char *result = malloc(INET_ADDRSTRLEN);

        strncpy(result, inet_ntoa(eAddr->sin_addr), INET_ADDRSTRLEN);
        fprintf(stdout, "Current ipv4 address of the machine: %s\n", result);
        fflush(stdout);

        // freeifaddrs(tmp);
        freeifaddrs(addrs);
        return result;
      }
    }
    tmp = tmp->ifa_next;
  }

  fprintf(stderr, "No TCP interface found, return NULL\n");
  freeifaddrs(tmp);
  freeifaddrs(addrs);
  return NULL;
}

/**
 * @brief Check if an interface name matches the expected pattern
 *
 * Determines if the given interface name is a wireless interface by checking
 * if it starts with "wl".
 *
 * @param ifname The interface name to check
 * @return true if the interface name starts with "wl", false otherwise
 */
static _Bool checkIfName(char *ifname) { return !strncmp(ifname, "wl", 2); }

/**
 * @brief Scan a network endpoint using ICMP echo requests
 *
 * Sends multiple ICMP echo request packets to the specified endpoint to
 * determine if it is alive and reachable. Creates raw sockets for sending and
 * receiving ICMP packets, constructs IP and ICMP headers, and processes echo
 * replies.
 *
 * The function sends ICMP_PACKET_CNT packets and waits for replies with a
 * 5-second timeout. It reports the success rate and detailed information about
 * each packet.
 *
 * @param endpoint Pointer to the NetworkEndpoint to scan. If NULL, defaults to
 * localhost
 * @return EXIT_SUCCESS on successful completion, EXIT_FAILURE or -1 on error
 */
int ScanNetworkEndpoint(NetworkEndpoint *endpoint) {
  char *current_ipv4;
  current_ipv4 = getCurrentIpv4Addr();
  if (!current_ipv4) {
    return -1;
  }

  fprintf(stdout, "Starting network scan...\n");
  NetworkEndpoint local;
  if (endpoint == NULL) {
    endpoint = &local;
    fprintf(stderr, "Got null endpoint, will fallback to localhost\n");
    NetworkEndpoint *hostEndpoint;
    hostEndpoint = malloc(sizeof(NetworkEndpoint));
    if (!hostEndpoint)
      return -1;

    hostEndpoint->isAlive = true;
    hostEndpoint->sockaddr.sin_family = AF_INET;
    hostEndpoint->sockaddr.sin_port = htons(8080);
    hostEndpoint->sockaddr.sin_addr.s_addr = inet_addr(current_ipv4);
    fflush(stderr);
    fflush(stdout);

    memcpy(endpoint, hostEndpoint, sizeof(NetworkEndpoint));
    free(hostEndpoint);
  }

  struct in_addr target_ipaddr;
  struct in_addr host_ipaddr;
  target_ipaddr.s_addr = endpoint->sockaddr.sin_addr.s_addr;
  host_ipaddr.s_addr = inet_addr(current_ipv4);

  // Preparing to send ICMP packets to the endpoint;
  fprintf(stdout, "Sending ICMP to the ipv4 adress: %s\n",
          inet_ntoa(target_ipaddr));
  fflush(stdout);

  int packet_size = sizeof(struct ip) + sizeof(struct icmp) + ICMP_PACKET_DATA;
  char *send_buf = malloc(packet_size);
  char *recv_buf = malloc(packet_size + sizeof(struct ip));

  if (!send_buf || !recv_buf) {
    fprintf(stderr, "Failed to allocate buffers: %s", strerror(errno));
    free(send_buf);
    free(recv_buf);
    free(current_ipv4);
    return -1;
  }

  memset(send_buf, 0, packet_size);
  memset(recv_buf, 0, packet_size + sizeof(struct ip));

  struct ip *ip = (struct ip *)send_buf;
  struct icmp *host_icmp_proto = (struct icmp *)(send_buf + sizeof(struct ip));

  char *icmp_buf = (char *)(host_icmp_proto + 1);
  memset(icmp_buf, 'A', ICMP_PACKET_DATA);

  int opt = 1;
  int send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  int recv_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

  if (send_fd < 0 || recv_fd < 0) {
    fprintf(stderr, "Failed to create a new socket: %s\n", strerror(errno));
    free(send_buf);
    free(recv_buf);
    free(current_ipv4);
    return EXIT_FAILURE;
  }

  if (setsockopt(send_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
    fprintf(stderr, "Failed to create Raw socket: %s\n", strerror(errno));
    close(send_fd);
    close(recv_fd);
    free(current_ipv4);
    return EXIT_FAILURE;
  }

  ip->ip_v = 4;
  ip->ip_hl = 5;
  ip->ip_tos = 0;
  ip->ip_len =
      htons(sizeof(struct ip) + sizeof(struct icmp) + ICMP_PACKET_DATA);
  ip->ip_id = htons(getpid());
  ip->ip_off = htons(0);
  ip->ip_ttl = 64;
  ip->ip_p = IPPROTO_ICMP;
  ip->ip_sum = 0;
  ip->ip_src = host_ipaddr;
  ip->ip_dst = target_ipaddr;

  host_icmp_proto->icmp_type = ICMP_ECHO;
  host_icmp_proto->icmp_code = 0;
  host_icmp_proto->icmp_id = getpid() & 0xffff;
  host_icmp_proto->icmp_seq = 0;
  host_icmp_proto->icmp_cksum = 0;

  struct timeval tv;

  // Listen 5 seconds
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  if (setsockopt(recv_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    fprintf(stderr, "Failed to assign socket options SO_RCVTIMEO: %s",
            strerror(errno));
    free(current_ipv4);
    close(send_fd);
    close(recv_fd);
    return -1;
  }

  int success_count = 0;
  for (int i = 0; i < ICMP_PACKET_CNT; ++i) {
    ip->ip_sum = 0;
    ip->ip_sum = csum((unsigned short *)send_buf, sizeof(struct ip));
    host_icmp_proto->icmp_cksum = 0;
    host_icmp_proto->icmp_cksum = csum((unsigned short *)host_icmp_proto,
                                       sizeof(struct icmp) + ICMP_PACKET_DATA);

    socklen_t dst_addr_len = sizeof(endpoint->sockaddr);

    int bytes_sent, bytes_received;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = endpoint->sockaddr.sin_addr;
    dest_addr.sin_port = 0;

    if ((bytes_sent =
             sendto(send_fd, send_buf, packet_size, 0,
                    (struct sockaddr *)&dest_addr, sizeof(dest_addr))) < 0) {
      fprintf(stderr, "Cannot send ICMP packets to %s: %s\n",
              inet_ntoa(dest_addr.sin_addr), strerror(errno));
      close(send_fd);
      close(recv_fd);
      free(current_ipv4);
      return EXIT_FAILURE;
    }
    fprintf(stdout, "Sent %d bytes ...\n", bytes_sent);
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);

    if ((bytes_received =
             recvfrom(recv_fd, recv_buf, packet_size + sizeof(struct ip), 0,
                      (struct sockaddr *)&src_addr, &src_addr_len)) < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        fprintf(stdout, "Timeout (no response): %s\n", strerror(errno));
        fflush(stdout);
        continue;
      } else {
        fprintf(stderr, "Failed reading reply packet: %s\n", strerror(errno));
        fflush(stderr);
        close(send_fd);
        close(recv_fd);
        free(current_ipv4);
        return EXIT_FAILURE;
      }
    }

    fprintf(stdout, "Received %d byte packets ", bytes_received);
    fprintf(stdout, "from=%s   ip_ttl=%d   icmp_seq=%d   icmp_type=%d ",
            inet_ntoa(target_ipaddr), ip->ip_ttl, host_icmp_proto->icmp_seq,
            host_icmp_proto->icmp_type);

    struct icmp *recv_icmp = NULL;

    // Try to parse as IP + ICMP
    if (bytes_received >= sizeof(struct ip) + sizeof(struct icmp)) {
      struct ip *recv_ip = (struct ip *)recv_buf;

      if (recv_ip->ip_v == 4 && recv_ip->ip_p == IPPROTO_ICMP) {
        int ip_hdr_len = recv_ip->ip_hl << 2;
        if (ip_hdr_len >= 20 &&
            ip_hdr_len <= bytes_received - sizeof(struct icmp)) {
          recv_icmp = (struct icmp *)(recv_buf + ip_hdr_len);
        }
      }

      // Try to parse as ICMP only (if IP+ICMP didn't work)
      if (!recv_icmp && bytes_received >= sizeof(struct icmp)) {
        recv_icmp = (struct icmp *)recv_buf;
      }

      // Validate the ICMP packet
      if (recv_icmp && recv_icmp->icmp_type == ICMP_ECHOREPLY) {
        fprintf(stdout, "( Received ECHO REPLY from %s)\n",
                inet_ntoa(src_addr.sin_addr));
        success_count++;
      } else if (recv_icmp) {
        fprintf(stdout, "( Got ICMP type %d (not ECHOREPLY) )\n",
                recv_icmp->icmp_type);
      } else {
        fprintf(stdout, "[%d] Failed to parse ICMP packet\n", i + 1);
      }
    }

    host_icmp_proto->icmp_seq++;
  }

  float percentage = 100 * ((float)success_count / (float)ICMP_PACKET_CNT);
  fprintf(stdout,
          "Ping test completed ! %d/%d (%g\%) transmitted successfully\n",
          success_count, ICMP_PACKET_CNT, percentage);
cleanup:
  free(send_buf);
  free(recv_buf);
  free(current_ipv4);

  close(send_fd);
  close(recv_fd);
  return EXIT_SUCCESS;
}

/**
 * @brief Main entry point for the network scanner application
 *
 * Parses command-line arguments for target IP address and port, validates
 * root privileges, and initiates a network scan on the specified endpoint.
 *
 * Command-line options:
 * - -p, --port <port>: Specify the target port (default: 8080)
 * - -h, --target_ip <ip>: Specify the target IP address (optional, defaults to
 * localhost)
 *
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return EXIT_SUCCESS on successful execution, EXIT_FAILURE on error
 */
int main(int argc, char *argv[]) {
  int port, c;
  char *target_ipaddr;
  int scanFinished = false;

  if (getuid() != 0) {
    fprintf(stderr,
            "This program requires root privileges to run, try with sudo.\n");
    return (EXIT_FAILURE);
  }

  ip_address_given = port_given = false;
  while (1) {
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    static struct option long_opts[] = {
        {"port", required_argument, 0, 'p'},
        {"target_ip", required_argument, 0, 'h'},
        {NULL, 0, NULL, 0}};

    c = getopt_long(argc, argv, "p:h:", long_opts, &option_index);
    if (c == -1) {
      break;
    }

    switch (c) {
    case 'p':
      port_given = true;
      port = ConvertStrToInt(optarg);
      break;

    case 'h':
      ip_address_given = true;
      target_ipaddr = optarg;
      break;

    case '?':
      break;

    default:
      fprintf(stderr, "Usage: ./scan -p [port] -h [ip :Optional]");
      return EXIT_FAILURE;
      break;
    }
  }

  if (!port_given)
    port = 8080;

  if (!ip_address_given)
    target_ipaddr = NULL;

  NetworkEndpoint *endpoint = malloc(sizeof(NetworkEndpoint));

  memset(endpoint, 0, sizeof(NetworkEndpoint));
  InitEndpoint(target_ipaddr, port, endpoint);

  if (ScanNetworkEndpoint(endpoint) != 0) {
    fprintf(stderr, "Failed to scan the given endpoint\n");
  }
  free(endpoint);
  return EXIT_SUCCESS;
}
