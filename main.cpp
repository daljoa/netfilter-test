#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

namespace {

volatile sig_atomic_t g_running = 1;
std::string g_blocked_host;

void usage() {
    std::printf("syntax : netfilter-test <host>\n");
    std::printf("sample : netfilter-test test.gilgil.net\n");
}

void on_signal(int) {
    g_running = 0;
}

std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string trim(const std::string& s) {
    size_t begin = 0;
    while (begin < s.size() && (s[begin] == ' ' || s[begin] == '\t')) begin++;

    size_t end = s.size();
    while (end > begin &&
           (s[end - 1] == ' ' || s[end - 1] == '\t' || s[end - 1] == '\r' || s[end - 1] == '\n')) {
        end--;
    }

    return s.substr(begin, end - begin);
}

bool starts_with(const std::string& s, const char* prefix) {
    const size_t len = std::strlen(prefix);
    return s.size() >= len && std::memcmp(s.data(), prefix, len) == 0;
}

bool is_http_request(const std::string& payload) {
    return starts_with(payload, "GET ") ||
           starts_with(payload, "POST ") ||
           starts_with(payload, "HEAD ") ||
           starts_with(payload, "PUT ") ||
           starts_with(payload, "DELETE ") ||
           starts_with(payload, "OPTIONS ") ||
           starts_with(payload, "PATCH ") ||
           starts_with(payload, "CONNECT ") ||
           starts_with(payload, "TRACE ");
}

std::string strip_port(const std::string& host) {
    if (host.empty() || host[0] == '[') return host;

    size_t colon = host.rfind(':');
    if (colon == std::string::npos) return host;

    for (size_t i = colon + 1; i < host.size(); i++) {
        if (host[i] < '0' || host[i] > '9') return host;
    }

    return host.substr(0, colon);
}

bool same_host(const std::string& lhs, const std::string& rhs) {
    std::string left = lower_copy(trim(lhs));
    std::string right = lower_copy(trim(rhs));

    if (left == right) return true;

    left = strip_port(left);
    right = strip_port(right);
    return left == right;
}

bool extract_http_host(const uint8_t* data, size_t len, std::string& host) {
    std::string payload(reinterpret_cast<const char*>(data), len);
    if (!is_http_request(payload)) return false;

    size_t header_end = payload.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        header_end = payload.find("\n\n");
        if (header_end == std::string::npos) header_end = payload.size();
    }

    size_t line_begin = 0;
    while (line_begin < header_end) {
        size_t line_end = payload.find('\n', line_begin);
        if (line_end == std::string::npos || line_end > header_end) line_end = header_end;

        std::string line = payload.substr(line_begin, line_end - line_begin);
        if (!line.empty() && line.back() == '\r') line.pop_back();

        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = lower_copy(trim(line.substr(0, colon)));
            if (name == "host") {
                host = trim(line.substr(colon + 1));
                return !host.empty();
            }
        }

        line_begin = line_end + 1;
    }

    return false;
}

void print_packet_info(const iphdr* ip, const tcphdr* tcp, const char* verdict, const std::string& host) {
    char src_ip[INET_ADDRSTRLEN] = {};
    char dst_ip[INET_ADDRSTRLEN] = {};

    in_addr src {};
    in_addr dst {};
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst, dst_ip, sizeof(dst_ip));

    std::printf("[%s] %s:%u -> %s:%u Host: %s\n",
                verdict,
                src_ip,
                ntohs(tcp->source),
                dst_ip,
                ntohs(tcp->dest),
                host.c_str());
}

bool should_drop_http_host(const uint8_t* packet, int packet_len, std::string& host) {
    if (packet_len < static_cast<int>(sizeof(iphdr))) return false;

    const iphdr* ip = reinterpret_cast<const iphdr*>(packet);
    if (ip->version != 4 || ip->protocol != IPPROTO_TCP) return false;

    const int ip_header_len = ip->ihl * 4;
    if (ip_header_len < static_cast<int>(sizeof(iphdr))) return false;
    if (packet_len < ip_header_len + static_cast<int>(sizeof(tcphdr))) return false;

    const uint16_t total_len = ntohs(ip->tot_len);
    if (total_len < ip_header_len + static_cast<int>(sizeof(tcphdr))) return false;

    const int available_len = std::min(packet_len, static_cast<int>(total_len));
    const tcphdr* tcp = reinterpret_cast<const tcphdr*>(packet + ip_header_len);
    const int tcp_header_len = tcp->doff * 4;
    if (tcp_header_len < static_cast<int>(sizeof(tcphdr))) return false;
    if (available_len < ip_header_len + tcp_header_len) return false;

    const uint8_t* tcp_payload = packet + ip_header_len + tcp_header_len;
    const int tcp_payload_len = available_len - ip_header_len - tcp_header_len;
    if (tcp_payload_len <= 0) return false;

    if (!extract_http_host(tcp_payload, static_cast<size_t>(tcp_payload_len), host)) return false;
    if (!same_host(host, g_blocked_host)) {
        print_packet_info(ip, tcp, "ACCEPT", host);
        return false;
    }

    print_packet_info(ip, tcp, "DROP", host);
    return true;
}

uint32_t packet_id(struct nfq_data* nfad) {
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(nfad);
    if (ph == nullptr) return 0;
    return ntohl(ph->packet_id);
}

int on_packet(struct nfq_q_handle* qh, struct nfgenmsg*, struct nfq_data* nfad, void*) {
    uint32_t id = packet_id(nfad);

    unsigned char* packet = nullptr;
    int packet_len = nfq_get_payload(nfad, &packet);
    if (packet_len < 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
    }

    std::string host;
    if (should_drop_http_host(packet, packet_len, host)) {
        return nfq_set_verdict(qh, id, NF_DROP, 0, nullptr);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, nullptr);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return EXIT_FAILURE;
    }

    g_blocked_host = argv[1];

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    struct nfq_handle* handle = nfq_open();
    if (handle == nullptr) {
        std::fprintf(stderr, "nfq_open failed\n");
        return EXIT_FAILURE;
    }

    if (nfq_unbind_pf(handle, AF_INET) < 0) {
        std::fprintf(stderr, "nfq_unbind_pf failed\n");
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    if (nfq_bind_pf(handle, AF_INET) < 0) {
        std::fprintf(stderr, "nfq_bind_pf failed\n");
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    struct nfq_q_handle* queue = nfq_create_queue(handle, 0, &on_packet, nullptr);
    if (queue == nullptr) {
        std::fprintf(stderr, "nfq_create_queue failed\n");
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::fprintf(stderr, "nfq_set_mode failed\n");
        nfq_destroy_queue(queue);
        nfq_close(handle);
        return EXIT_FAILURE;
    }

    std::printf("blocking HTTP Host: %s\n", g_blocked_host.c_str());
    std::printf("queue-num: 0\n");

    int fd = nfq_fd(handle);
    char buf[4096] __attribute__((aligned));

    while (g_running) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(handle, buf, rv);
            continue;
        }

        if (errno == EINTR) continue;
        if (errno == ENOBUFS) {
            std::fprintf(stderr, "warning: packet loss in nfqueue\n");
            continue;
        }

        perror("recv");
        break;
    }

    nfq_destroy_queue(queue);
    nfq_close(handle);

    return EXIT_SUCCESS;
}
