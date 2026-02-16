#include <iomanip>
#include <iostream>
#include <chrono>
#include <ctime>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <objbase.h>
#include <algorithm>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")

using namespace std;
using namespace std::chrono;

SOCKET sock = INVALID_SOCKET;

int socket_flag;
int recv_flag;
int select_flag;

const int SEND_INTERVAL_MS = 1000;
const int RESPONSE_TIMEOUT_MS = 4000;
const char* sin_addr = "8.8.8.8";

constexpr size_t ICMP_HDR_MIN = 8;
constexpr size_t IP_HDR_MIN = 20;

const int GUID_LEN = 16;

bool all_responses_received;

// структура статусов и типов
enum class PacketStatus {
    NSEND,
    SENT,
    RESP_RECVD,
    TIMED_OUT,
    RESP_ERROR
};
enum class TypeRequest{
    NONE,
    TYPE3=3,
    TYPE11=11,
    TYPE12=12,
    TYPE5=5
};
enum class TypeCodes{
    NONE,
    CODE0,
    CODE1,
    CODE3=3
};

#pragma pack(push,1)
struct PacketData {
    int id{-1};
    PacketStatus status = PacketStatus::NSEND;
    chrono::steady_clock::time_point send_timestamp;
    chrono::steady_clock::time_point receive_timestamp;
    uint8_t guid[GUID_LEN];
};
#pragma pack(pop)

#pragma pack(push,1)
struct IPHdr {
    u_char      ip_v_ihl;   // Version (4 bits) and Header Length (4 bits)
    u_char      ip_tos;     // Type of Service
    u_short     ip_len;     // Total Length
    u_short     ip_id;      // Identification
    u_short     ip_off;     // Fragment Offset field
    u_char      ip_ttl;     // Time to Live
    u_char      ip_p;       // Protocol
    u_short     ip_sum;     // Checksum
    struct in_addr ip_src;  // Source Address
    struct in_addr ip_dst;  // Destination Address
};
#pragma pack(pop)

#pragma pack(push,1)
struct ICMPhdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
    uint8_t data[16];
};
#pragma pack(pop)

// вспомогательные
pair <TypeRequest, string> status_of_err(TypeRequest type, TypeCodes code) {
    switch (type) {
    case TypeRequest::TYPE3: {
        switch (code) {
        case TypeCodes::CODE0:  return make_pair(TypeRequest::TYPE3, "Destination Unreachable. The network is unreachable.");
        case TypeCodes::CODE1:  return make_pair(TypeRequest::TYPE3, "Destination Unreachable. The host is unreachable.");
        case TypeCodes::CODE3:  return make_pair(TypeRequest::TYPE3, "Destination Unreachable. The port is unreachable.");
        default: return make_pair(TypeRequest::TYPE3, "UNKNOWN CODE for TYPE3");
        }
    }
    case TypeRequest::TYPE11: {
        switch (code) {
        case TypeCodes::CODE0:  return make_pair(TypeRequest::TYPE11, "Time Exceeded. Transit lifetime exceeded.");
        case TypeCodes::CODE1:  return make_pair(TypeRequest::TYPE11, "Time Exceeded. Time exceeded while assembling fragments.");
        default: return make_pair(TypeRequest::TYPE11, "UNKNOWN CODE for TYPE11");
        }
    }
    case TypeRequest::TYPE12: {
        switch (code){
        case TypeCodes::CODE0:  return make_pair(TypeRequest::TYPE12, "Parameter Problem. The pointer points to an error.");
        default: return make_pair(TypeRequest::TYPE12, "UNKNOWN CODE for TYPE12");
        }
    }
    case TypeRequest::TYPE5: {
        switch (code){
    case TypeCodes::CODE0:  return make_pair(TypeRequest::TYPE5, "Redirect. Redirect for the network.");case TypeCodes::CODE1:  return make_pair(TypeRequest::TYPE5, "Redirect. Redirect for the host.");
        default: return make_pair(TypeRequest::TYPE5, "UNKNOWN CODE for TYPE5");}
    }
    default:
        return make_pair(TypeRequest::NONE, "UNKNOWN TYPE");
    }
}
bool is_error (TypeRequest type){
    return (type == TypeRequest::TYPE3 ||
            type == TypeRequest::TYPE11 ||
            type == TypeRequest::TYPE12 ||
            type == TypeRequest::TYPE5);
}

uint16_t icmp_checksum(const void *data, size_t len) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    while (len > 1) {
        sum += (static_cast<uint16_t>(bytes[0]) << 8) | bytes[1];
        bytes += 2;
        len -= 2;
    }

    if (len) {
        sum += static_cast<uint16_t>(bytes[0]) << 8;
    }

    // fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return static_cast<uint16_t>(~sum);
}
void print_hex(const char* data, int len, int countBytes)
{
    if (countBytes) cout << "size: " << countBytes << " bytes" << endl;
    cout << hex << uppercase << setfill('0');
    size_t to_show = min(static_cast<size_t>(len), static_cast<size_t>(60));
    for (size_t i = 0; i < to_show; ++i){
        cout << setw(2) << (static_cast<unsigned int>(static_cast<unsigned char>(data[i]))) << ' ';
        if (i == 19) cout << "     ";
    }
    cout << dec << endl;
}
void print_bytes_hex(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        cout << "(empty)\n";
        return;
    }
    ios oldState(nullptr);
    oldState.copyfmt(cout);
    for (size_t i = 0; i < len; ++i) {
        unsigned int b = static_cast<unsigned char>(data[i]);
        cout << hex << uppercase << setw(2) << setfill('0') << b;
        if (i + 1 < len) std::cout << ' ';
    }
    cout << dec << '\n';
    cout.copyfmt(oldState);}
void print_data_cout(const std::vector<char>& v) {
    if (v.empty()) {
        std::cout << "(empty)\n";
        return;
    }
    std::cout << "v.size=" << v.size() << '\n';
    print_bytes_hex(reinterpret_cast<const uint8_t*>(v.data()), v.size());
}

void print_data_cout(const uint8_t data[16]) {
    if (!data) {
        std::cout << "(null)\n";
        return;
    }
    print_bytes_hex(data, 16);
}

vector<char> packetForm(int currP){
    ICMPhdr icmphdr;
    GUID guid;
    HRESULT hr = CoCreateGuid(&guid);
    if (FAILED(hr)) {
        cerr << "CoCreateGuid failed" << std::endl;
        return {};
    }
    memcpy(icmphdr.data, &guid, sizeof(guid));

    icmphdr.type = 8;
    icmphdr.code = 0;
    icmphdr.identifier = htons(static_cast<uint16_t>(GetCurrentProcessId() & 0xFFFF));
    icmphdr.sequence = htons(static_cast<uint16_t>(currP));
    icmphdr.checksum = 0;
    icmphdr.checksum = htons(icmp_checksum(&icmphdr, sizeof(ICMPhdr)));

    const size_t header_size = sizeof(icmphdr.type) + sizeof(icmphdr.code) + sizeof(icmphdr.checksum);
    const size_t payload_size = sizeof(icmphdr.data);
    const size_t total_size = header_size + payload_size;
    cout << "total_size: " << total_size << endl;

    vector<char> sendBuffer(sizeof(ICMPhdr));
    memcpy(sendBuffer.data(), &icmphdr, sizeof(ICMPhdr));


    cout << "\n=== ICMP Packet #" << currP << " ===\n";
    cout << "type=" << dec << (int)icmphdr.type
         << " code=" << (int)icmphdr.code
         << " id=" << ntohs(icmphdr.identifier)
         << " seq=" << ntohs(icmphdr.sequence) << endl;
    printf("checksum=0x%04X\n", ntohs(icmphdr.checksum));

    cout << "payload (GUID) = ";
    print_data_cout(icmphdr.data);
    cout << "sizeof(ICMPhdr) = " << sizeof(ICMPhdr) << " bytes\n";
    cout << "--------------------------\n";

    return sendBuffer;
}

string status_to_string(PacketStatus s) {
    switch (s) {
    case PacketStatus::NSEND:      return "NSEND";
    case PacketStatus::SENT:       return "SENT";
    case PacketStatus::RESP_RECVD: return "RESP_RECVD";
    case PacketStatus::TIMED_OUT:  return "TIMED_OUT";
    case PacketStatus::RESP_ERROR: return "RESP_ERROR";
    }
    return "UNKNOWN";
}    void print_packet(const PacketData& p) {
    cout << "Packet id: " << p.id << "\n";
    cout << "  status: " << status_to_string(p.status) << "\n";
    if (p.status == PacketStatus::RESP_RECVD || p.status == PacketStatus::RESP_ERROR) {
        auto durr = chrono::duration_cast<chrono::milliseconds>(p.receive_timestamp - p.send_timestamp).count();
        cout << "  duration_time: " << dec << durr  << " ms\n";
    } else {
        cout << "  duration_time: --\n";
    }
    cout << "  guid: ";
    for (auto b : p.guid) printf("%02X ", (unsigned) b);
    cout << endl;
}

int init_socket(SOCKET &s){
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        int error_code = WSAGetLastError();
        cerr << "WSAStartup failed with error: " << error_code << endl;
        return -1;
    }

    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        cout << "Could not find a usable version of Winsock.dll" << endl;
        WSACleanup();
        return -1;
    } else {
        cout << "The Winsock 2.2 dll was found okay\n" << endl;
    }

    s = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, 0, 0);
    if (s == INVALID_SOCKET) {
        int error_code = WSAGetLastError();
        cerr << "create socket failed with error: " << error_code << endl;
        WSACleanup();
        return -1;
    }

    DWORD nonBlocking = 1;
    if ( ioctlsocket( s, FIONBIO, &nonBlocking ) != 0 ) {
        int error_code = WSAGetLastError();
        cerr << "nonblocking socket failed with error: " << error_code << endl;
        closesocket(s);
        WSACleanup();
        return -1;
    }

    int ttl_value = 120;
    if ( setsockopt( s, IPPROTO_IP, IP_TTL, (const char*)&ttl_value,  sizeof(ttl_value)) != 0 ) {
        int error_code = WSAGetLastError();
        cerr << "setsockopt TTL failed with error: " << error_code << endl;
        closesocket(s);
        WSACleanup();
        return -1;
    }

    return 0;
}

bool send_packets(SOCKET &s,
                  sockaddr_in const& dest_addr,
                  vector<char>& sendBuffer,
                  int& currPacket,
                  int countPacket,
                  chrono::steady_clock::time_point& next_send,
                  vector<PacketData>& packets)
{
    auto now = chrono::steady_clock::now();
    if (currPacket <= countPacket - 1 && now >= next_send) {
        sendBuffer = packetForm(currPacket);
        int sent_bytes = sendto(s,
                                sendBuffer.data(),
                                static_cast<int>(sendBuffer.size()),
                                0,
                                (struct sockaddr*)&dest_addr,
                                sizeof(dest_addr));
        cout << "elements in sendBuffer: " << sendBuffer.size() << " byte" <<  endl;
        if (sent_bytes == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            cerr << "sendto failed with error: " << error_code << endl;
            return true;
        } else {
            PacketData packetData{};
            packetData.id = currPacket;
            packetData.status = PacketStatus::SENT;
            packetData.send_timestamp = chrono::steady_clock::now();

            size_t data_off = offsetof(ICMPhdr, data);
            if (sendBuffer.size() >= data_off + GUID_LEN) {
                memcpy(packetData.guid, sendBuffer.data() + data_off, sizeof(packetData.guid));
                cout << "packetData.guid: " ;
                print_data_cout(packetData.guid);
            } else {
                memset(packetData.guid, 0, sizeof(packetData.guid));
            }

            cout << "send Hex: ";
            if (sent_bytes > 0 && static_cast<size_t>(sent_bytes) <= sendBuffer.size()) {
                print_hex(sendBuffer.data(), static_cast<int>(sendBuffer.size()), sent_bytes);
            }

            packets.push_back(packetData);
            ++currPacket;
            next_send = now + chrono::milliseconds(SEND_INTERVAL_MS);
        }
    }
    return false;
}

void check_timeout(vector<PacketData>& packets,const int RESPONSE_TIMEOUT_MS)
{
    auto now = chrono::steady_clock::now();
    for (auto& pkt : packets) {
        if (pkt.status == PacketStatus::SENT) {
            if (chrono::duration_cast<chrono::milliseconds>(now - pkt.send_timestamp).count() > RESPONSE_TIMEOUT_MS) {
                cout << "Packet with id " << pkt.id << " timed out. Lost package with time: " << chrono::duration_cast<chrono::milliseconds>(now - pkt.send_timestamp).count() << endl;
                pkt.status = PacketStatus::TIMED_OUT;
            }
        }
    }
    all_responses_received = true;
    for (const auto& pkt : packets) {
        if (pkt.status == PacketStatus::SENT) {
            all_responses_received = false;
            break;
        }
    }
}

void read_socket(SOCKET &s,
                 vector<char>& recvBuffer,
                 vector<PacketData>& packets,
                 int& currPacket)
{
    while (true) {
        sockaddr_in sender_addr;
        int sender_addr_len = sizeof(sender_addr);    int recv_len = recvfrom(s, recvBuffer.data(), static_cast<int>(recvBuffer.size()), 0,
                                (struct sockaddr*)&sender_addr, &sender_addr_len);

        if (recv_len == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            if (error_code == WSAEWOULDBLOCK) {
                break;
            } else {
                cerr << "recvfrom failed with error: " << error_code << endl;
                break;
            }
        }
        if (recv_len <= 0) continue;
        if (recv_len < (int)sizeof(IPHdr)) continue;

        cout << "Get raw packet size=" << recv_len << endl;

        IPHdr* ip = reinterpret_cast<IPHdr*>(recvBuffer.data());
        if (ip->ip_p != IPPROTO_ICMP) {
            // не ICMP
            continue;
        }

        size_t ip_header_len = (static_cast<uint8_t>(recvBuffer[0]) & 0x0F) * 4;
        if (ip_header_len < IP_HDR_MIN || static_cast<size_t>(recv_len) < ip_header_len + ICMP_HDR_MIN) {
            // не хватает данных
            continue;
        }

        const uint8_t* icmp_start = reinterpret_cast<const uint8_t*>(recvBuffer.data()) + ip_header_len;
        size_t total_icmp_len = static_cast<size_t>(recv_len) - ip_header_len;
        cout << "res total_icmp_len: " << total_icmp_len << endl;

        ICMPhdr l_icmp;
        size_t copy_len = min(sizeof(ICMPhdr), total_icmp_len);
        memset(&l_icmp, 0, sizeof(l_icmp));
        memcpy(&l_icmp, icmp_start, copy_len);
        uint8_t type = l_icmp.type;
        uint8_t code = l_icmp.code;

        cout << "External ICMP type=" << int(type) << " code=" << int(code) << " from " << inet_ntoa(sender_addr.sin_addr) << endl;

        bool matched_any = false;

        if (type == 0) {
            uint16_t r_id = ntohs(l_icmp.identifier);
            uint16_t r_seq = ntohs(l_icmp.sequence);

            size_t data_off = offsetof(ICMPhdr, data);
            if (total_icmp_len >= data_off + GUID_LEN) {
                const uint8_t* payload_guid = icmp_start + data_off;
                for (auto &pkt : packets) {
                    if (pkt.status == PacketStatus::SENT && pkt.id == (int)r_seq) {
                        if (memcmp(pkt.guid, payload_guid, GUID_LEN) == 0 && (int)r_id == (GetCurrentProcessId() & 0xFFFF)) {
                            pkt.status = PacketStatus::RESP_RECVD;
                            pkt.receive_timestamp = chrono::steady_clock::now();
                            matched_any = true;
                            break;
                        }
                    }
                }
            } else {
                // недостаточно данных
            }
        } else if (is_error(static_cast<TypeRequest>(type))) {
            const uint8_t* outer_payload = icmp_start + offsetof(ICMPhdr, data);
            size_t outer_payload_len = (total_icmp_len > offsetof(ICMPhdr, data)) ? (total_icmp_len - offsetof(ICMPhdr, data)) : 0;        if (outer_payload_len >= IP_HDR_MIN + ICMP_HDR_MIN) {
                // внутренний IP
                const uint8_t* inner_ip = outer_payload;
                size_t inner_ip_hlen = (static_cast<size_t>(inner_ip[0]) & 0x0F) * 4;
                if (inner_ip_hlen < IP_HDR_MIN) continue;

                if (outer_payload_len < inner_ip_hlen + ICMP_HDR_MIN) continue;

                const uint8_t* inner_icmp = inner_ip + inner_ip_hlen;
                size_t inner_icmp_len = outer_payload_len - inner_ip_hlen;

                ICMPhdr inner;
                memset(&inner, 0, sizeof(inner));
                size_t to_copy_inner = min(sizeof(inner), inner_icmp_len);
                memcpy(&inner, inner_icmp, to_copy_inner);

                uint16_t inner_seq = ntohs(inner.sequence);
                uint16_t inner_id = ntohs(inner.identifier);

                size_t inner_data_off = offsetof(ICMPhdr, data);
                if (inner_icmp_len >= inner_data_off + GUID_LEN) {
                    const uint8_t* inner_guid = inner_icmp + inner_data_off;
                    // Ищем пакет с таким seq и guid
                    for (auto &pkt : packets) {
                        if (pkt.status == PacketStatus::SENT && pkt.id == (int)inner_seq) {
                            if (memcmp(pkt.guid, inner_guid, GUID_LEN) == 0 && (int)inner_id == (GetCurrentProcessId() & 0xFFFF)) {
                                pkt.status = PacketStatus::RESP_ERROR; // это ошибка (destination unreachable / ttl exceeded)
                                pkt.receive_timestamp = chrono::steady_clock::now();
                                auto p = status_of_err(static_cast<TypeRequest>(type), static_cast<TypeCodes>(code));
                                cout << "ICMP Error for seq=" << inner_seq << ": " << p.second << endl;
                                matched_any = true;
                                break;
                            }
                        }
                    }
                } else {
                    // недостаточно данных во вложенном ICMP, но можно проверить seq/id если доступны
                    for (auto &pkt : packets) {
                        if (pkt.status == PacketStatus::SENT && pkt.id == (int)inner_seq) {
                            pkt.status = PacketStatus::RESP_ERROR;
                            pkt.receive_timestamp = chrono::steady_clock::now();
                            matched_any = true;
                            break;
                        }
                    }
                }
            } else {
                // payload слишком мал
            }
        } else {
            cout << "Unhandled ICMP type: " << int(type) << endl;
        }

        if (!matched_any) {
            cout << "No matching sent packet found for this reply.\n";
        }

        cout << "response in Hex (first " << recv_len << " bytes): ";
        print_hex(recvBuffer.data(), recv_len, recv_len);
        cout << endl;
    }
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);if (init_socket(sock) != 0) {
        cerr << "socket init failed\n";
        return 1;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(sin_addr);

    fd_set readfs;

    vector<char> recvBuffer(4096);
    vector<char> sendBuffer;
    vector<PacketData> packets;
    auto next_send = chrono::steady_clock::now();
    int countPacket = 4;
    int currPacket = 0;

    while (true) {
        if (send_packets(sock, dest_addr, sendBuffer, currPacket, countPacket, next_send, packets)) {
            break;
        }

        check_timeout(packets, RESPONSE_TIMEOUT_MS);

        if (currPacket > countPacket - 1 && all_responses_received) {
            cout << "Все пакеты отправлены." << endl;
            break;
        }

        FD_ZERO(&readfs);
        FD_SET(sock, &readfs);
        timeval select_timeout{0, 100000}; // 100ms
        int sel = select(0, &readfs, NULL, NULL, &select_timeout);
        if (sel == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            cerr << "select failed with error: " << error_code << endl;
            break;
        }
        if (FD_ISSET(sock, &readfs)) {
            cout << "socket is ready!" << endl;
            read_socket(sock, recvBuffer, packets, currPacket);
        } else {
            //cout << "socket is not ready!" << endl;
        }

        Sleep(1);
    }

    for (const auto& pkt : packets) {
        print_packet(pkt);
        cout << "-----------------\n";
    }

    closesocket(sock);
    WSACleanup();
    cout << "Нажмите любую клавишу для выхода...";
    cin.get();
    return 0;
}
