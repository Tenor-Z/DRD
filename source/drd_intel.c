/* 
'########::'########::'########::
 ##.... ##: ##.... ##: ##.... ##:
 ##:::: ##: ##:::: ##: ##:::: ##:
 ##:::: ##: ########:: ##:::: ##:
 ##:::: ##: ##.. ##::: ##:::: ##:
 ##:::: ##: ##::. ##:: ##:::: ##:
 ########:: ##:::. ##: ########::
........:::..:::::..::........:::
-------------------------------------------
 * DRD v2.0 - Advanced Network Scanner
 * Discover | Report | Document
 * Developed by Tenor-Z
 * 
 * Current Capabilities:
 * - TCP/UDP port scanning
 * - IPv4 / Limited IPv6 support
 * - CIDR expansion for IPv4 ranges
 * - Banner grabbing & version detection for common TCP services
 * - OS guesses
 * - Top ports mode
 * - HTML report generation
 * - Partial verbose output levels

 * Planned:
 * - Rate limiting
 * - SOCKS5 proxy support
 * - True SYN stealth scanning
 * - Stronger footprinting
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdint.h>

/* Ensure C99 functions are available on older MinGW 
   This shouldn't be an issue if kept up-to-date but just in case... */
#ifdef _WIN32
    #ifndef snprintf
        #define snprintf _snprintf
    #endif
    #ifndef strdup
        #define strdup _strdup
    #endif
#endif

/* Different header setups and definitions for both types of 
compilers.*/

#ifdef _WIN32
    /* Windows headers MUST be in this exact order 
    It won't work otherwise */
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <iphlpapi.h>
    #include <icmpapi.h>
    
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
    
    #define CLOSE_SOCKET(s) closesocket(s)
    #define SLEEP(ms) Sleep(ms)
    typedef int socklen_t;
    typedef ULONG IPAddr;
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <sys/types.h>
    #include <sys/select.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <pthread.h>
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define SOCKET int
    #define CLOSE_SOCKET(s) close(s)
    #define SLEEP(ms) usleep((ms) * 1000)
    typedef struct { int dummy; } WSADATA;
#endif

#define VERSION "2.0"   // A simpler way of maintaining version no.
#define MAX_PORTS 65535
#define MAX_TARGETS 256
#define MAX_BANNER_LEN 512
#define MAX_VERSION_LEN 128

// Top 100 most common ports
static const int TOP_100_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    1, 7, 9, 13, 17, 19, 26, 37, 49, 79,
    81, 82, 83, 84, 85, 88, 89, 90, 99, 100,
    106, 109, 113, 119, 125, 144, 146, 161, 163, 179,
    199, 211, 212, 222, 254, 255, 256, 259, 264, 280,
    301, 306, 311, 340, 366, 389, 406, 407, 416, 417,
    425, 427, 444, 458, 464, 465, 481, 497, 500, 512,
    513, 514, 515, 524, 541, 543, 544, 545, 548, 554,
    555, 563, 587, 593, 616, 617, 625, 631, 636, 646
};

// Top 20
static const int TOP_20_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
    445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888
};

// Service signatures for version detection
// Special thanks to https://regex101.com/ for building regex codes
// Still working on regex stuff
typedef struct {
    const char* pattern;
    const char* service;
    const char* version_regex;
} ServiceSignature;

static const ServiceSignature SERVICE_SIGNATURES[] = {
    {"SSH-", "SSH", "SSH-([0-9.]+)"},
    {"220", "FTP", "220[- ]([^\r\n]+)"},
    {"HTTP/1", "HTTP", "Server: ([^\r\n]+)"},
    {"+OK", "POP3", "\\+OK ([^\r\n]+)"},
    {"* OK", "IMAP", "\\* OK ([^\r\n]+)"},
    {"220 ", "SMTP", "220 ([^\r\n]+)"},
    {"MySQL", "MySQL", "([0-9.]+)"},
    {"PostgreSQL", "PostgreSQL", "([0-9.]+)"},
    {"redis_version", "Redis", "redis_version:([0-9.]+)"},
    {"MongoDB", "MongoDB", NULL},
    {NULL, NULL, NULL}
};

typedef struct {
    int port;
    const char* service;
    const char* protocol;
} PortService;

// In the future, I might add specific ports used by backdoors and malware, but as of right now,
// Metasploit can be detected by the program. This obviously won't replace the necessity of antimalware software
// but it would provide insight on malicious services running on a given device
static const PortService KNOWN_SERVICES[] = {
    {20, "FTP-DATA", "tcp"}, {21, "FTP", "tcp"}, {22, "SSH", "tcp"},
    {23, "Telnet", "tcp"}, {25, "SMTP", "tcp"}, {53, "DNS", "tcp/udp"},
    {67, "DHCP", "udp"}, {68, "DHCP", "udp"}, {69, "TFTP", "udp"},
    {80, "HTTP", "tcp"}, {110, "POP3", "tcp"}, {111, "RPC", "tcp"},
    {119, "NNTP", "tcp"}, {123, "NTP", "udp"}, {135, "MSRPC", "tcp"},
    {137, "NetBIOS-NS", "udp"}, {138, "NetBIOS-DGM", "udp"},
    {139, "NetBIOS-SSN", "tcp"}, {143, "IMAP", "tcp"}, {161, "SNMP", "udp"},
    {162, "SNMP-Trap", "udp"}, {179, "BGP", "tcp"}, {389, "LDAP", "tcp"},
    {443, "HTTPS", "tcp"}, {445, "SMB", "tcp"}, {465, "SMTPS", "tcp"},
    {500, "IKE", "udp"}, {514, "Syslog", "udp"}, {515, "LPD", "tcp"},
    {520, "RIP", "udp"}, {523, "IBM-DB2", "tcp"}, {543, "Klogin", "tcp"},
    {544, "Kshell", "tcp"}, {548, "AFP", "tcp"}, {554, "RTSP", "tcp"},
    {587, "Submission", "tcp"}, {631, "IPP", "tcp"}, {636, "LDAPS", "tcp"},
    {873, "rsync", "tcp"}, {902, "VMware", "tcp"}, {993, "IMAPS", "tcp"},
    {995, "POP3S", "tcp"}, {1080, "SOCKS", "tcp"}, {1194, "OpenVPN", "udp"},
    {1433, "MSSQL", "tcp"}, {1434, "MSSQL-UDP", "udp"}, {1521, "Oracle", "tcp"},
    {1701, "L2TP", "udp"}, {1723, "PPTP", "tcp"}, {1883, "MQTT", "tcp"},
    {2049, "NFS", "tcp"}, {2082, "cPanel", "tcp"}, {2083, "cPanel-SSL", "tcp"},
    {2181, "ZooKeeper", "tcp"}, {2222, "SSH-Alt", "tcp"}, {2375, "Docker", "tcp"},
    {2376, "Docker-SSL", "tcp"}, {3000, "Node.js", "tcp"}, {3128, "Squid", "tcp"},
    {3268, "LDAP-GC", "tcp"}, {3306, "MySQL", "tcp"}, {3389, "RDP", "tcp"},
    {3690, "SVN", "tcp"}, {4333, "mSQL", "tcp"}, {4443, "Pharos", "tcp"},
    {4444, "Metasploit", "tcp"}, {4505, "SaltStack", "tcp"},
    {4506, "SaltStack", "tcp"}, {5000, "UPnP", "tcp"}, {5432, "PostgreSQL", "tcp"},
    {5433, "PostgreSQL", "tcp"}, {5500, "VNC-HTTP", "tcp"}, {5601, "Kibana", "tcp"},
    {5672, "RabbitMQ", "tcp"}, {5900, "VNC", "tcp"}, {5984, "CouchDB", "tcp"},
    {6000, "X11", "tcp"}, {6379, "Redis", "tcp"}, {6443, "Kubernetes", "tcp"},
    {6666, "IRC", "tcp"}, {6667, "IRC", "tcp"}, {7001, "WebLogic", "tcp"},
    {7002, "WebLogic-SSL", "tcp"}, {8000, "HTTP-Alt", "tcp"},
    {8008, "HTTP-Alt", "tcp"}, {8080, "HTTP-Proxy", "tcp"},
    {8081, "HTTP-Alt", "tcp"}, {8443, "HTTPS-Alt", "tcp"},
    {8888, "HTTP-Alt", "tcp"}, {9000, "PHP-FPM", "tcp"},
    {9090, "Prometheus", "tcp"}, {9092, "Kafka", "tcp"},
    {9200, "Elasticsearch", "tcp"}, {9300, "Elasticsearch", "tcp"},
    {9418, "Git", "tcp"}, {10000, "Webmin", "tcp"}, {11211, "Memcached", "tcp"},
    {27017, "MongoDB", "tcp"}, {27018, "MongoDB", "tcp"},
    {28017, "MongoDB-Web", "tcp"}, {50000, "SAP", "tcp"},
    {50070, "Hadoop", "tcp"}, {50090, "Hadoop", "tcp"},
    {0, NULL, NULL}
};

// Verbose levels
typedef enum {
    VERBOSE_QUIET = -1,
    VERBOSE_NORMAL = 0,
    VERBOSE_V = 1,
    VERBOSE_VV = 2,
    VERBOSE_VVV = 3
} VerboseLevel;

typedef struct {
    char target[256];
    char targets[MAX_TARGETS][256];
    int target_count;
    int port_start;
    int port_end;
    int* custom_ports;
    int custom_port_count;
    int timeout_ms;
    int udp_scan;
    int banner_grab;
    int version_detect;
    int syn_scan;
    int rate_limit;
    VerboseLevel verbose;
    int use_ipv6;
    int top_ports;
    char proxy_host[256];
    int proxy_port;
    char output_file[256];
} ScanOptions;

typedef struct {
    int port;
    int is_open;
    int is_tcp;
    char service[64];
    char banner[MAX_BANNER_LEN];
    char version[MAX_VERSION_LEN];
} PortResult;

typedef struct {
    char target[256];
    int is_ipv6;
    PortResult* ports;
    int port_count;
    int open_count;
    char os_guess[64];
    time_t scan_start;
    time_t scan_end;
} ScanResults;

void print_banner(void);
void print_usage(const char* prog_name);
const char* get_service_name(int port);
int check_port_tcp(const char* host, int port, int timeout_ms, int use_ipv6);
int check_port_tcp_v6(const char* host, int port, int timeout_ms);
int check_port_udp(const char* host, int port, int timeout_ms, int use_ipv6);
int grab_banner(const char* host, int port, char* banner, int banner_len, int use_ipv6);
void detect_version(const char* banner, char* version, int version_len);
int ping_host(const char* host, int use_ipv6);
void guess_os(ScanResults* results);
void generate_html_report(ScanResults* results, const char* filename);
int parse_cidr(const char* cidr, char targets[][256], int max_targets);
int is_ipv6_address(const char* addr);
void print_verbose(VerboseLevel level, VerboseLevel current, const char* fmt, ...);

void print_banner(void) {
    printf("\n");
    printf("  I=======================================================I\n");
    printf("  |                                                       |\n");
    printf("  |             /$$$$$$$  /$$$$$$$  /$$$$$$$              |\n");
    printf("  |            | $$__  $$| $$__  $$| $$__  $$             |\n");
    printf("  |            | $$  | $$| $$  | $$| $$  | $$             |\n");
    printf("  |            | $$  | $$| $$$$$$$/| $$  | $$             |\n");
    printf("  |            | $$  | $$| $$__  $$| $$  | $$             |\n");
    printf("  |            | $$  | $$| $$  | $$| $$  | $$             |\n");
    printf("  |            | $$$$$$$/| $$  | $$| $$$$$$$/             |\n");
    printf("  |            |_______/ |__/  |__/|_______/              |\n");
    printf("  |                                                       |\n");
    printf("  |            Discover | Report | Document  v%s          |\n", VERSION);
    printf("  |                                                       |\n");
    printf("  I=======================================================I\n");
    printf("               Created and developed by Tenor-Z            \n");
    printf("-----------------------------------------------------------\n");
    printf("\n");
}

void print_usage(const char* prog_name) {
    print_banner();
    printf("  Usage: %s <target> [options]\n\n", prog_name);
    printf("  Target:\n");
    printf("    hostname           Domain name (e.g., example.com)\n");
    printf("    IPv4 address       e.g., 192.168.1.1\n");
    printf("    IPv6 address       e.g., ::1 or 2001:db8::1\n");
    printf("    CIDR notation      e.g., 192.168.1.0/24\n\n");
    printf("  Scan Options:\n");
    printf("    -p <range>         Port range (default: 1-1024)\n");
    printf("                       Examples: -p 80, -p 1-1000, -p 22,80,443\n");
    printf("    -top <n>           Scan top N common ports (20 or 100)\n");
    printf("    -t <ms>            Timeout per port in ms (default: 1000)\n");
    printf("    -u                 Enable UDP scanning\n");
    printf("    -6                 Force IPv6 scanning (EXPERIMENTAL)\n\n");
    printf("  Detection Options:\n");
    printf("    -b                 Grab service banners\n");
    printf("    -sV                Version detection (includes banner grab) (EXPERIMENTAL)\n");
    printf("  Output Options:\n");
    printf("    -v                 Verbose output (show scan progress)\n");
    printf("    -vv                More verbose (show closed ports)\n");
    printf("    -vvv               Maximum verbosity (debug info)\n");
    printf("    -q                 Quiet mode (only show open ports)\n");
    printf("    -o <file>          Export HTML report\n\n");
    printf("  Other:\n");
    printf("    -h, --help         Show this help message\n\n");
    printf("  Examples:\n");
    printf("    %s example.com\n", prog_name);
    printf("    %s 192.168.1.1 -p 1-65535 -sV -o report.html\n", prog_name);
    printf("    %s 192.168.1.0/24 -top 100 -v\n", prog_name);
    printf("    %s ::1 -6 -p 22,80,443 -b\n", prog_name);
    printf("    %s 10.0.0.1 -p 80-443 100 -vv\n\n", prog_name);
}

// Very helpful (but barebones) verbose level system
// Built solely on if statements and does exactly what it says on the tin
void print_verbose(VerboseLevel level, VerboseLevel current, const char* fmt, ...) {
    if (current >= level) {
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
        fflush(stdout);
    }
}

int is_ipv6_address(const char* addr) {
    return strchr(addr, ':') != NULL;
}

// This gets the service name
const char* get_service_name(int port) {
    for (int i = 0; KNOWN_SERVICES[i].service != NULL; i++) {
        if (KNOWN_SERVICES[i].port == port) {
            return KNOWN_SERVICES[i].service;
        }
    }
    return "Unknown";
}

// This is a matter of parsing the CIDR (Classless Inter-Domain Routing) details in a way that can be processed
// by the program. By default, there are two parts of a CIDR address; the IP address itself and the CIDR prefix.
// the prefix details the subnet mask that the IP address will be affiliated with.

int parse_cidr(const char* cidr, char targets[][256], int max_targets) {
    char ip_str[64];
    int prefix_len;
    
    // Essentially, we take the CIDR input from the user, look for specific strings or sets of integers often
    // associated with them, and add them to a new set of information which can then be used to obtain the network
    // and broadcast address of the network.
    
    const char* slash = strchr(cidr, '/');
    if (!slash) {
        strncpy(targets[0], cidr, 255);
        return 1;
    }
    
    // Parse IP and prefix
    size_t ip_len = slash - cidr;
    if (ip_len >= sizeof(ip_str)) {
        return 0;
    }
    strncpy(ip_str, cidr, ip_len);
    ip_str[ip_len] = '\0';
    prefix_len = atoi(slash + 1);
    
    if (prefix_len < 0 || prefix_len > 32) {
        printf("Error: Invalid CIDR prefix length (must be 0-32)\n");
        return 0;
    }
    
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        printf("Error: Invalid IP address in CIDR notation\n");
        return 0;
    }
    
    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;
    
    int count = 0;
    for (uint32_t host = network + 1; host < broadcast && count < max_targets; host++) {
        struct in_addr host_addr;
        host_addr.s_addr = htonl(host);
        inet_ntop(AF_INET, &host_addr, targets[count], 256);
        count++;
    }
    
    return count;
}

// To clarify (though it is apparent within the first few lines of this function), this checks selected TCP ports
// on IPv4 addresses only. All ports on IPv6 ports are checked on the check_port_tcp_v6 function since they both use
// different architectures. I plan on updating this so that both IPv4 and IPv6 TCP ports can be scanned under one function
// using 'getaddrinfo' rather than 'gethostbyname'

int check_port_tcp(const char* host, int port, int timeout_ms, int use_ipv6) {
    if (use_ipv6) {
        return check_port_tcp_v6(host, port, timeout_ms);
    }
    
    struct sockaddr_in addr;
    struct hostent* host_info;
    SOCKET sock;
    int result;
    fd_set fdset;
    struct timeval tv;
    
    host_info = gethostbyname(host);
    if (!host_info) {
        return -1;
    }
    
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }
    
    // Set non-blocking mode
    // Just so that it works with the timeout parameter
    #ifdef _WIN32
        unsigned long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
    #else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    #endif
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = *((struct in_addr*)host_info->h_addr);
    
    result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    if (result == 0) {
        CLOSE_SOCKET(sock);
        return 0;
    }
    
    // Making this as cross-platform as possible. 
    // Will be prioritized in future updates
    #ifdef _WIN32
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            CLOSE_SOCKET(sock);
            return -1;
        }
    #else
        if (errno != EINPROGRESS) {
            CLOSE_SOCKET(sock);
            return -1;
        }
    #endif
    
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    result = select((int)sock + 1, NULL, &fdset, NULL, &tv);
    
    if (result <= 0) {
        CLOSE_SOCKET(sock);
        return -1;
    }
    
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
    
    CLOSE_SOCKET(sock);
    
    return (so_error == 0) ? 0 : -1;
}

// This function will be removed and combined with the above function in a future update.
// In retrospective, there is a much more organized way of doing this that I completely overlooked
int check_port_tcp_v6(const char* host, int port, int timeout_ms) {
    struct addrinfo hints, *res, *p;
    SOCKET sock = INVALID_SOCKET;
    int result;
    fd_set fdset;
    struct timeval tv;
    char port_str[16];
    
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        // Try with unspecified family
        hints.ai_family = AF_UNSPEC;
        if (getaddrinfo(host, port_str, &hints, &res) != 0) {
            return -1;
        }
    }
    
    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == INVALID_SOCKET) {
            continue;
        }
        
        // Set non-blocking
        #ifdef _WIN32
            unsigned long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
        #else
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        #endif
        
        result = connect(sock, p->ai_addr, (int)p->ai_addrlen);
        
        if (result == 0) {
            freeaddrinfo(res);
            CLOSE_SOCKET(sock);
            return 0;
        }
        
        #ifdef _WIN32
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                CLOSE_SOCKET(sock);
                continue;
            }
        #else
            if (errno != EINPROGRESS) {
                CLOSE_SOCKET(sock);
                continue;
            }
        #endif
        
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        
        result = select((int)sock + 1, NULL, &fdset, NULL, &tv);
        
        if (result > 0) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
            CLOSE_SOCKET(sock);
            freeaddrinfo(res);
            return (so_error == 0) ? 0 : -1;
        }
        
        CLOSE_SOCKET(sock);
    }
    
    freeaddrinfo(res);
    return -1;
}

// UDP ports can be checked on both IPv4 and IPv6 IP addresses as well. Basically,
// it sends an empty packet out and waits for a response to determine if the port is
// open or not. Returns 0 if a response has been received (open) or is set to open|filtered
// if no response is received (rough estimation)

int check_port_udp(const char* host, int port, int timeout_ms, int use_ipv6) {
    struct addrinfo hints, *res;
    SOCKET sock;
    char port_str[16];
    fd_set fdset;
    struct timeval tv;
    char buf[1024];
    
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = use_ipv6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }
    
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return -1;
    }
    
    #ifdef _WIN32
        unsigned long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
    #else
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    #endif
    
    sendto(sock, "", 0, 0, res->ai_addr, (int)res->ai_addrlen);
    
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    int result = select((int)sock + 1, &fdset, NULL, NULL, &tv);
    
    if (result > 0) {
        int recv_result = recv(sock, buf, sizeof(buf), 0);
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        return (recv_result >= 0) ? 0 : -1;
    }
    
    CLOSE_SOCKET(sock);
    freeaddrinfo(res);
    
    // UDP is "open|filtered" if no response
    return 0;
}

// Used to obtain banner grabs on specified ports. It initiates a TCP connection, and sends a 
// HTTP Head request to trigger a response (for web applications) and displays the cleaned up version of the banner
// in the script output

int grab_banner(const char* host, int port, char* banner, int banner_len, int use_ipv6) {
    struct addrinfo hints, *res;
    SOCKET sock;
    char port_str[16];
    fd_set fdset;
    struct timeval tv;
    
    snprintf(port_str, sizeof(port_str), "%d", port);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = use_ipv6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }
    
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res);
        return -1;
    }
    
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));
    
    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) < 0) {
        CLOSE_SOCKET(sock);
        freeaddrinfo(res);
        return -1;
    }
    
    // For HTTP, send a request
    if (port == 80 || port == 8080 || port == 8000 || port == 8888 || port == 443 || port == 8443) {
        const char* http_req = "HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n";
        send(sock, http_req, (int)strlen(http_req), 0);
    }
    
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    
    if (select((int)sock + 1, &fdset, NULL, NULL, &tv) > 0) {
        int bytes = recv(sock, banner, banner_len - 1, 0);
        if (bytes > 0) {
            banner[bytes] = '\0';
            // Clean up non-printable characters
            for (int i = 0; i < bytes; i++) {
                if (banner[i] < 32 && banner[i] != '\n' && banner[i] != '\r' && banner[i] != '\t') {
                    banner[i] = '.';
                }
            }
            CLOSE_SOCKET(sock);
            freeaddrinfo(res);
            return 0;
        }
    }
    
    CLOSE_SOCKET(sock);
    freeaddrinfo(res);
    return -1;
}

// As of right now, version detection is only limited to pattern recognition using similar tactics
// to banner grabbing to gather information about a service's version based on specific strings. If
// nothing of use can be found from the banner (or nothing at all), the function will just fall back
// on the first line of the banner message and clean it up a bit

void detect_version(const char* banner, char* version, int version_len) {
    version[0] = '\0';
    
    if (!banner || strlen(banner) == 0) {
        return;
    }
    
    // Check for common version patterns
    for (int i = 0; SERVICE_SIGNATURES[i].pattern != NULL; i++) {
        if (strstr(banner, SERVICE_SIGNATURES[i].pattern)) {
            const char* ver_start = NULL;
            
            // Look for version number patterns
            if (strstr(banner, "SSH-")) {
                ver_start = banner;
                const char* end = strchr(banner, '\n');
                if (end) {
                    int len = (end - banner < version_len - 1) ? (int)(end - banner) : version_len - 1;
                    strncpy(version, banner, len);
                    version[len] = '\0';
                }
                return;
            }
            
            if ((ver_start = strstr(banner, "Server:")) != NULL) {
                ver_start += 7;
                while (*ver_start == ' ') ver_start++;
                const char* end = strchr(ver_start, '\r');
                if (!end) end = strchr(ver_start, '\n');
                if (end) {
                    int len = (end - ver_start < version_len - 1) ? (int)(end - ver_start) : version_len - 1;
                    strncpy(version, ver_start, len);
                    version[len] = '\0';
                }
                return;
            }
            
            const char* end = strchr(banner, '\n');
            if (end) {
                int len = (end - banner < version_len - 1) ? (int)(end - banner) : version_len - 1;
                strncpy(version, banner, len);
                version[len] = '\0';
            } else {
                strncpy(version, banner, version_len - 1);
                version[version_len - 1] = '\0';
            }
            return;
        }
    }
    
    // Fallback: just get first line of banner
    const char* end = strchr(banner, '\n');
    if (end) {
        int len = (end - banner < version_len - 1) ? (int)(end - banner) : version_len - 1;
        strncpy(version, banner, len);
        version[len] = '\0';
    }
}

// A function to ping hosts and determine their reachability. It traditionally only works with
// IPv4 since that is what was more straightforward to include at first. IPv6 support will be 
// properly implemented with this function in future updates

int ping_host(const char* host, int use_ipv6) {
    #ifdef _WIN32
        if (use_ipv6) {
            // IPv6 ping on Windows - use TCP connect fallback
            return check_port_tcp_v6(host, 80, 1000);
        }
        
        HANDLE hIcmpFile;
        IPAddr ipaddr;
        DWORD dwRetVal;
        char SendData[32] = "DRD-Intel Ping";
        LPVOID ReplyBuffer;
        DWORD ReplySize;
        struct hostent* host_info;
        
        host_info = gethostbyname(host);
        if (!host_info) {
            return -1;
        }
        
        ipaddr = inet_addr(inet_ntoa(*(struct in_addr*)host_info->h_addr));
        
        hIcmpFile = IcmpCreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE) {
            return -1;
        }
        
        ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
        ReplyBuffer = (VOID*)malloc(ReplySize);
        if (ReplyBuffer == NULL) {
            IcmpCloseHandle(hIcmpFile);
            return -1;
        }
        
        dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, SendData, sizeof(SendData),
                                NULL, ReplyBuffer, ReplySize, 1000);
        
        free(ReplyBuffer);
        IcmpCloseHandle(hIcmpFile);
        
        return (dwRetVal != 0) ? 0 : -1;
    #else
        return check_port_tcp(host, 80, 1000, use_ipv6);
    #endif
}

// OS detection at the moment is very barebones and not as in-depth
// as Nmap or similar tools. It looks for ports commonly affiliated with
// specific operating systems and makes its decision based on what is open
// For example, if port TCP 3389 is open, it assumes the host is a Windows
// device because RDP is a Windows service.

void guess_os(ScanResults* results) {
    int has_22 = 0, has_135 = 0, has_139 = 0, has_445 = 0;
    int has_3389 = 0, has_111 = 0, has_2049 = 0;
    
    for (int i = 0; i < results->port_count; i++) {
        if (!results->ports[i].is_open) continue;
        
        switch (results->ports[i].port) {
            case 22: has_22 = 1; break;
            case 135: has_135 = 1; break;
            case 139: has_139 = 1; break;
            case 445: has_445 = 1; break;
            case 3389: has_3389 = 1; break;
            case 111: has_111 = 1; break;
            case 2049: has_2049 = 1; break;
        }
    }
    
    if (has_135 && has_139 && has_445) {
        if (has_3389) {
            strcpy(results->os_guess, "Windows (RDP enabled)");
        } else {
            strcpy(results->os_guess, "Windows");
        }
    } else if (has_22 && (has_111 || has_2049)) {
        strcpy(results->os_guess, "Linux/Unix (NFS enabled)");
    } else if (has_22) {
        strcpy(results->os_guess, "Linux/Unix/macOS");
    } else if (has_445 || has_139) {
        strcpy(results->os_guess, "Windows/Samba");
    } else {
        strcpy(results->os_guess, "Unknown");
    }
}

// Generates a HTML report of scan results
// spent way too long styling this instead of fixing the scanner lol shhhhh

void generate_html_report(ScanResults* results, const char* filename) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        printf("  [!] Error: Could not create report file: %s\n", filename);
        return;
    }
    
    char time_str[64];
    struct tm* tm_info = localtime(&results->scan_start);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(fp, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    fprintf(fp, "  <meta charset=\"UTF-8\">\n");
    fprintf(fp, "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    fprintf(fp, "  <title>DRD Scan Report - %s</title>\n", results->target);
    fprintf(fp, "  <style>\n");
    fprintf(fp, "    :root { --bg: #0a0a0f; --card: #12121a; --border: #1e1e2e; ");
    fprintf(fp, "--text: #e0e0e0; --muted: #888; --accent: #00d4aa; --danger: #ff4757; }\n");
    fprintf(fp, "    * { margin: 0; padding: 0; box-sizing: border-box; }\n");
    fprintf(fp, "    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); ");
    fprintf(fp, "color: var(--text); line-height: 1.6; padding: 2rem; }\n");
    fprintf(fp, "    .container { max-width: 1200px; margin: 0 auto; }\n");
    fprintf(fp, "    header { text-align: center; margin-bottom: 2rem; padding: 2rem; ");
    fprintf(fp, "background: var(--card); border-radius: 12px; border: 1px solid var(--border); }\n");
    fprintf(fp, "    h1 { font-size: 2.5rem; background: linear-gradient(135deg, var(--accent), #00a896); ");
    fprintf(fp, "-webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 0.5rem; }\n");
    fprintf(fp, "    .subtitle { color: var(--muted); font-size: 0.9rem; }\n");
    fprintf(fp, "    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); ");
    fprintf(fp, "gap: 1rem; margin-bottom: 2rem; }\n");
    fprintf(fp, "    .stat-card { background: var(--card); padding: 1.5rem; border-radius: 8px; ");
    fprintf(fp, "border: 1px solid var(--border); text-align: center; }\n");
    fprintf(fp, "    .stat-value { font-size: 2rem; font-weight: bold; color: var(--accent); }\n");
    fprintf(fp, "    .stat-label { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }\n");
    fprintf(fp, "    table { width: 100%%; border-collapse: collapse; background: var(--card); ");
    fprintf(fp, "border-radius: 8px; overflow: hidden; }\n");
    fprintf(fp, "    th, td { padding: 1rem; text-align: left; border-bottom: 1px solid var(--border); }\n");
    fprintf(fp, "    th { background: #1a1a2e; color: var(--accent); font-weight: 600; text-transform: uppercase; font-size: 0.8rem; }\n");
    fprintf(fp, "    tr:hover { background: #1a1a2e; }\n");
    fprintf(fp, "    .port { font-family: 'Fira Code', monospace; font-weight: bold; }\n");
    fprintf(fp, "    .open { color: #00d4aa; }\n");
    fprintf(fp, "    .service { color: #ffa502; }\n");
    fprintf(fp, "    .version { color: var(--muted); font-size: 0.85rem; max-width: 300px; ");
    fprintf(fp, "overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }\n");
    fprintf(fp, "    footer { text-align: center; margin-top: 2rem; padding: 1rem; color: var(--muted); font-size: 0.8rem; }\n");
    fprintf(fp, "  </style>\n</head>\n<body>\n");
    fprintf(fp, "  <div class=\"container\">\n");
    fprintf(fp, "    <header>\n");
    fprintf(fp, "      <h1>DRD</h1>\n");
    fprintf(fp, "      <p class=\"subtitle\">Discover | Report | Document</p>\n");
    fprintf(fp, "    </header>\n\n");
    
    fprintf(fp, "    <div class=\"stats\">\n");
    fprintf(fp, "      <div class=\"stat-card\">\n");
    fprintf(fp, "        <div class=\"stat-value\">%s</div>\n", results->target);
    fprintf(fp, "        <div class=\"stat-label\">Target%s</div>\n", results->is_ipv6 ? " (IPv6)" : "");
    fprintf(fp, "      </div>\n");
    fprintf(fp, "      <div class=\"stat-card\">\n");
    fprintf(fp, "        <div class=\"stat-value\">%d</div>\n", results->open_count);
    fprintf(fp, "        <div class=\"stat-label\">Open Ports</div>\n");
    fprintf(fp, "      </div>\n");
    fprintf(fp, "      <div class=\"stat-card\">\n");
    fprintf(fp, "        <div class=\"stat-value\">%d</div>\n", results->port_count);
    fprintf(fp, "        <div class=\"stat-label\">Ports Scanned</div>\n");
    fprintf(fp, "      </div>\n");
    fprintf(fp, "      <div class=\"stat-card\">\n");
    fprintf(fp, "        <div class=\"stat-value\">%ds</div>\n", (int)(results->scan_end - results->scan_start));
    fprintf(fp, "        <div class=\"stat-label\">Scan Duration</div>\n");
    fprintf(fp, "      </div>\n");
    fprintf(fp, "    </div>\n\n");
    
    fprintf(fp, "    <div class=\"stat-card\" style=\"margin-bottom: 2rem;\">\n");
    fprintf(fp, "      <p><strong>Scan Time:</strong> %s</p>\n", time_str);
    fprintf(fp, "      <p><strong>OS Guess:</strong> %s</p>\n", results->os_guess);
    fprintf(fp, "    </div>\n\n");
    
    fprintf(fp, "    <table>\n");
    fprintf(fp, "      <thead>\n");
    fprintf(fp, "        <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr>\n");
    fprintf(fp, "      </thead>\n");
    fprintf(fp, "      <tbody>\n");
    
    for (int i = 0; i < results->port_count; i++) {
        if (results->ports[i].is_open) {
            fprintf(fp, "        <tr>\n");
            fprintf(fp, "          <td class=\"port\">%d</td>\n", results->ports[i].port);
            fprintf(fp, "          <td>%s</td>\n", results->ports[i].is_tcp ? "TCP" : "UDP");
            fprintf(fp, "          <td class=\"open\">open</td>\n");
            fprintf(fp, "          <td class=\"service\">%s</td>\n", results->ports[i].service);
            fprintf(fp, "          <td class=\"version\" title=\"%s\">%s</td>\n", 
                    results->ports[i].version[0] ? results->ports[i].version : "-",
                    results->ports[i].version[0] ? results->ports[i].version : "-");
            fprintf(fp, "        </tr>\n");
        }
    }
    
    fprintf(fp, "      </tbody>\n");
    fprintf(fp, "    </table>\n\n");
    
    fprintf(fp, "    <footer>\n");
    fprintf(fp, "      <p>Generated by DRD v%s | Discover | Report | Document</p>\n", VERSION);
    fprintf(fp, "    </footer>\n");
    fprintf(fp, "  </div>\n</body>\n</html>\n");
    
    fclose(fp);
    printf("  [+] HTML report saved: %s\n", filename);
}


int main(int argc, char* argv[]) {
    ScanOptions opts = {0};
    ScanResults results = {0};
    
    opts.port_start = 1;
    opts.port_end = 1024;
    opts.timeout_ms = 1000;
    opts.verbose = VERBOSE_NORMAL;
    
    #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            printf("Error: WSAStartup failed\n");
            return 1;
        }
    #endif
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Check for help flag first above all
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    if (argv[1][0] == '-') {
        printf("Error: No target specified.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Check for CIDR or IPv6
    if (strchr(argv[1], '/')) {
        opts.target_count = parse_cidr(argv[1], opts.targets, MAX_TARGETS);
        if (opts.target_count == 0) {
            return 1;
        }
    } else {
        strncpy(opts.targets[0], argv[1], 255);
        opts.target_count = 1;
        opts.use_ipv6 = is_ipv6_address(argv[1]);
    }
    
    strncpy(opts.target, argv[1], sizeof(opts.target) - 1);
    
    // Parse arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            i++;
            // Check for comma-separated ports
            if (strchr(argv[i], ',')) {
                char* ports_str = strdup(argv[i]);
                char* token = strtok(ports_str, ",");
                opts.custom_ports = malloc(sizeof(int) * 1000);
                opts.custom_port_count = 0;
                while (token && opts.custom_port_count < 1000) {
                    opts.custom_ports[opts.custom_port_count++] = atoi(token);
                    token = strtok(NULL, ",");
                }
                free(ports_str);
            } else {
                sscanf(argv[i], "%d-%d", &opts.port_start, &opts.port_end);
                if (opts.port_end == 0) opts.port_end = opts.port_start;
            }
        } else if (strcmp(argv[i], "-top") == 0 && i + 1 < argc) {
            opts.top_ports = atoi(argv[++i]);
            if (opts.top_ports != 20 && opts.top_ports != 100) {
                printf("Warning: -top only supports 20 or 100, using 100\n");
                opts.top_ports = 100;
            }
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            opts.timeout_ms = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-u") == 0) {
            opts.udp_scan = 1;
        } else if (strcmp(argv[i], "-b") == 0) {
            opts.banner_grab = 1;
        } else if (strcmp(argv[i], "-sV") == 0) {
            opts.banner_grab = 1;
            opts.version_detect = 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            opts.syn_scan = 1;
        } else if (strcmp(argv[i], "-q") == 0) {
            opts.verbose = VERBOSE_QUIET;
        } else if (strcmp(argv[i], "-vvv") == 0) {
            opts.verbose = VERBOSE_VVV;
        } else if (strcmp(argv[i], "-vv") == 0) {
            opts.verbose = VERBOSE_VV;
        } else if (strcmp(argv[i], "-v") == 0) {
            opts.verbose = VERBOSE_V;
        } else if (strcmp(argv[i], "-6") == 0) {
            opts.use_ipv6 = 1;
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            opts.rate_limit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-px") == 0 && i + 1 < argc) {
            i++;
            sscanf(argv[i], "%255[^:]:%d", opts.proxy_host, &opts.proxy_port);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(opts.output_file, argv[++i], sizeof(opts.output_file) - 1);
        }
    }
    
    int* ports_to_scan;
    int num_ports;
    
    if (opts.top_ports > 0) {
        if (opts.top_ports == 20) {
            ports_to_scan = (int*)TOP_20_PORTS;
            num_ports = 20;
        } else {
            ports_to_scan = (int*)TOP_100_PORTS;
            num_ports = 100;
        }
    } else if (opts.custom_port_count > 0) {
        ports_to_scan = opts.custom_ports;
        num_ports = opts.custom_port_count;
    } else {
        num_ports = opts.port_end - opts.port_start + 1;
        ports_to_scan = malloc(sizeof(int) * num_ports);
        for (int i = 0; i < num_ports; i++) {
            ports_to_scan[i] = opts.port_start + i;
        }
    }
    
    if (opts.verbose >= VERBOSE_NORMAL) {
        print_banner();
    }
    
    // Scan each target
    for (int t = 0; t < opts.target_count; t++) {
        char* current_target = opts.targets[t];
        int is_ipv6 = opts.use_ipv6 || is_ipv6_address(current_target);
        
        if (opts.verbose >= VERBOSE_NORMAL) {
            printf("  [*] Scanning: %s%s\n", current_target, is_ipv6 ? " (IPv6)" : "");
            printf("  [*] Ports: ");
            if (opts.top_ports > 0) {
                printf("Top %d\n", opts.top_ports);
            } else if (opts.custom_port_count > 0) {
                printf("%d custom ports\n", opts.custom_port_count);
            } else {
                printf("%d-%d\n", opts.port_start, opts.port_end);
            }
            printf("  [*] Timeout: %dms\n", opts.timeout_ms);
            if (opts.udp_scan) printf("  [*] UDP scanning enabled\n");
            if (opts.banner_grab) printf("  [*] Banner grabbing enabled\n");
            if (opts.version_detect) printf("  [*] Version detection enabled\n");
            printf("\n");
        }
        
        // Ping sweep
        if (opts.verbose >= VERBOSE_V) {
            printf("  [*] Checking host availability...\n");
        }
        
        if (ping_host(current_target, is_ipv6) != 0) {
            if (opts.verbose >= VERBOSE_NORMAL) {
                printf("  [!] Host appears to be down or blocking ping\n");
                printf("  [*] Continuing scan anyway...\n\n");
            }
        } else if (opts.verbose >= VERBOSE_V) {
            printf("  [+] Host is up\n\n");
        }
        
        // Initialize results
        strncpy(results.target, current_target, sizeof(results.target) - 1);
        results.is_ipv6 = is_ipv6;
        results.ports = malloc(sizeof(PortResult) * num_ports * 2); // *2 for UDP
        results.port_count = 0;
        results.open_count = 0;
        results.scan_start = time(NULL);
        
        if (opts.verbose >= VERBOSE_NORMAL) {
            printf("  [*] Scanning ports...\n\n");
        }
        
        int rate_delay = opts.rate_limit > 0 ? (1000 / opts.rate_limit) : 0;        // Just unused
        
        for (int i = 0; i < num_ports; i++) {
            int port = ports_to_scan[i];
            
            if (opts.verbose >= VERBOSE_VVV) {
                printf("  [DBG] Testing TCP port %d\n", port);
            }
            
            // TCP scan
            PortResult* pr = &results.ports[results.port_count];
            pr->port = port;
            pr->is_tcp = 1;
            strncpy(pr->service, get_service_name(port), sizeof(pr->service) - 1);
            pr->banner[0] = '\0';
            pr->version[0] = '\0';
            
            if (check_port_tcp(current_target, port, opts.timeout_ms, is_ipv6) == 0) {
                pr->is_open = 1;
                results.open_count++;
                
                if (opts.verbose >= VERBOSE_NORMAL) {
                    printf("  [+] %d/tcp open - %s", port, pr->service);
                }
                
                // Banner grabbing
                if (opts.banner_grab) {
                    if (grab_banner(current_target, port, pr->banner, sizeof(pr->banner), is_ipv6) == 0) {
                        if (opts.version_detect) {
                            detect_version(pr->banner, pr->version, sizeof(pr->version));
                        }
                        if (opts.verbose >= VERBOSE_NORMAL && pr->version[0]) {
                            printf(" [%s]", pr->version);
                        }
                    }
                }
                
                if (opts.verbose >= VERBOSE_NORMAL) {
                    printf("\n");
                }
            } else {
                pr->is_open = 0;
                if (opts.verbose >= VERBOSE_VV) {
                    printf("  [-] %d/tcp closed\n", port);
                }
            }
            
            results.port_count++;
            
            // UDP scan
            if (opts.udp_scan) {
                if (opts.verbose >= VERBOSE_VVV) {
                    printf("  [DBG] Testing UDP port %d\n", port);
                }
                
                pr = &results.ports[results.port_count];
                pr->port = port;
                pr->is_tcp = 0;
                strncpy(pr->service, get_service_name(port), sizeof(pr->service) - 1);
                pr->banner[0] = '\0';
                pr->version[0] = '\0';
                
                if (check_port_udp(current_target, port, opts.timeout_ms, is_ipv6) == 0) {
                    pr->is_open = 1;
                    results.open_count++;
                    
                    if (opts.verbose >= VERBOSE_NORMAL) {
                        printf("  [+] %d/udp open|filtered - %s\n", port, pr->service);
                    }
                } else {
                    pr->is_open = 0;
                }
                
                results.port_count++;
            }
            
            // Rate limiting
            // This is unused since rate limiting is not an acceptable parameter (YET)
            if (rate_delay > 0) {
                SLEEP(rate_delay);
            }
            
            // Progress indicator
            if (opts.verbose == VERBOSE_V && (i + 1) % 100 == 0) {
                printf("  [*] Progress: %d/%d ports scanned\n", i + 1, num_ports);
            }
        }
        
        results.scan_end = time(NULL);
        
        guess_os(&results);
        
        // Print summary
        if (opts.verbose >= VERBOSE_NORMAL) {
            printf("\n============================================================\n");
            printf("                   Scan Summary for %s\n", current_target);
            printf("  ============================================================\n");
            printf("  Open ports: %d\n", results.open_count);
            printf("  Ports scanned: %d\n", results.port_count);
            printf("  OS guess: %s\n", results.os_guess);
            printf("  Duration: %d seconds\n", (int)(results.scan_end - results.scan_start));
            printf("  ============================================================\n\n");
        }
        
        // Generate HTML report
        if (opts.output_file[0]) {
            generate_html_report(&results, opts.output_file);
        }
        
        free(results.ports);
    }
    
    // Cleanup
    if (opts.custom_port_count > 0) {
        free(opts.custom_ports);
    } else if (opts.top_ports == 0) {
        free(ports_to_scan);
    }
    
    #ifdef _WIN32
        WSACleanup();
    #endif
    
    return 0;
}
