#include <iomanip>
#include <iostream>
#include <chrono>
#include <ctime>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/time.h>
#include <unistd.h>
#include <objbase.h>
#include <algorithm>
#include <cstdint>

//namespaces
using namespace std;
using namespace std::chrono;
//variables
SOCKET sock = INVALID_SOCKET;

int socket_flag;
int recv_flag;
int select_flag;

//constans
const int SEND_INTERVAL_MS = 1000;
const int RESPONSE_TIMEOUT_MS = 4000;
const char* sin_addr = "8.8.8.8";

constexpr size_t ICMP_HDR_MIN = 8;
constexpr size_t IP_HDR_MIN = 20;
//structurs
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
    int id{-1}; //для сравнения с кол-вом пакетов
    PacketStatus status = PacketStatus::NSEND;
    chrono::steady_clock::time_point send_timestamp;
    chrono::steady_clock::time_point receive_timestamp;
    vector<uint8_t> guid;
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
#pragma pack(push,1) //выравнивание
struct ICMPhdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t data;
};
#pragma pack(pop)

//methods
pair <TypeRequest, string> status_of_err(TypeRequest type, TypeCodes code) {
    switch (type) {
    case TypeRequest::TYPE3: {
        switch (code) {
        case TypeCodes::CODE0:  return make_pair(TypeRequest::TYPE3, "Destination Unreachable. The network is unreachable.") ;
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
        case TypeCodes::CODE0:  return make_pair(TypeRequest::TYPE5, "Redirect. Redirect for the network.");
        case TypeCodes::CODE1:  return make_pair(TypeRequest::TYPE5, "Redirect. Redirect for the host.");
        default: return make_pair(TypeRequest::TYPE5, "UNKNOWN CODE for TYPE5");
        }
    }
    default:
        return make_pair(TypeRequest::NONE, "UNKNOWN TYPE");
    }
}
bool is_error (TypeRequest type){
    if (type == TypeRequest::TYPE3      ||
        type == TypeRequest::TYPE11     ||
        type == TypeRequest::TYPE12     ||
        type == TypeRequest::TYPE5){
        return true;
    } else return false;
}
uint16_t icmp_checksum(const void *data, size_t len) {
    const uint8_t *bytes = reinterpret_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    size_t i = 0;
    while (len > 1) {
        uint16_t word = (uint16_t(bytes[i]) << 8) | uint16_t(bytes[i + 1]);
        sum += word;
        i += 2;
        len -= 2;
        if (sum & 0xFFFF0000) sum = (sum & 0xFFFF) + (sum >> 16);
    }

    if (len == 1) {
        uint16_t word = uint16_t(bytes[i]) << 8;
        sum += word;
    }

    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    return static_cast<uint16_t>(~sum);
}
unsigned long create_guid_part() {
    GUID g;
    if (CoCreateGuid(&g) == S_OK) {
        // 32 бита
        return g.Data1;
    }
    return 0;
}
vector<char> packetForm(){
    ICMPhdr icmphdr;
    auto resultGuid = create_guid_part();

    icmphdr.type = 8;
    icmphdr.code = 0;
    icmphdr.data = htonl(resultGuid);
    icmphdr.checksum = 0;

    //копирование структуры в буфер
    vector<char> sendBuffer(sizeof(ICMPhdr));
    memcpy(sendBuffer.data(), &icmphdr, sizeof(icmphdr));
    //дополнительная ф-я что значение crc в структуре 0
    size_t cs_off = offsetof(ICMPhdr, checksum);
    memset(sendBuffer.data() + cs_off, 0, sizeof(uint16_t));
    //вычисление crc
    uint16_t cs = icmp_checksum(sendBuffer.data(), sendBuffer.size());
    //перевод в сетевой код и запись в буфер
    uint16_t cs_net = htons(cs);
    memcpy(sendBuffer.data() + cs_off, &cs_net, sizeof(cs_net));

    cout << "--------------------------" << endl;
    cout << "Packet: " << endl;
    printf("type=%02X code=%02X ", icmphdr.type, icmphdr.code);
    printf("checksum=%04X ", cs_net);
    printf("payload=%08X ", icmphdr.data);
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
}
void print_packet(const PacketData& p) {
    cout << "Packet id: " << p.id << "\n";
    cout << "  status: " << status_to_string(p.status) << "\n";
    if (p.status == PacketStatus::RESP_RECVD) {
        auto durr = chrono::duration_cast<chrono::milliseconds>(p.receive_timestamp - p.send_timestamp).count();
        cout << "  duration_time: "
             <<dec<< durr  << " ms\n";
    } else {
        cout << "  duration_time: --\n";
    }
    cout << "  guid: ";
    for (auto b : p.guid) printf("%02X ", (unsigned) b);
    cout << endl;
}
uint32_t bytes_to_uint32(const std::vector<uint8_t>& buffer, size_t offset) {
    if (offset + 4 > buffer.size()) {
        return 0;
    }
    uint32_t value;
    memcpy(&value, buffer.data() + offset, sizeof(uint32_t));
    return value;
}
int init_socket(SOCKET &s){
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    wVersionRequested = MAKEWORD(2, 2); //задаёт версию библ winsock
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
    }
    else
        cout << "The Winsock 2.2 dll was found okay\n" << endl;

    //INIT SOCKET
    s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) {
        int error_code = WSAGetLastError();
        cerr << "create socket failed with error: " << error_code << endl;
        WSACleanup();
        return -1;
    }

    DWORD nonBlocking = 1;
    if ( ioctlsocket( s, FIONBIO, &nonBlocking ) != 0 )
    {
        int error_code = WSAGetLastError();
        cerr << "nonblocking socket failed with error: " << error_code << endl;
        closesocket(s);
        WSACleanup();
        return -1;
    }
    return 0;
}
void print_hex(const char* data, int len, int countBytes)
{

    if (countBytes) cout << "size: " << countBytes << " bytes" << endl;
    cout << hex << uppercase << setfill('0');
    size_t to_show = std::min(static_cast<size_t>(len), static_cast<size_t>(50));
    for (size_t i = 0; i < to_show; ++i){
        cout << setw(2) << (static_cast<unsigned int>(static_cast<unsigned char>(data[i]))) << ' ';//сначала перевод в символ для преобразования от 0-255, затем в int чтобы перевести в число
        if (i == 19) cout << "     ";
        if (i == 27) cout << "     ";
    }
    cout << dec << endl;
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
        sendBuffer = packetForm();
        int send_flag = sendto(s,
                               sendBuffer.data(),
                               static_cast<int>(sendBuffer.size()),
                               0,
                               (struct sockaddr*)&dest_addr,
                               sizeof(dest_addr));
        cout << "send buffer size: " << sendBuffer.size() << " byte" << endl;

        if (send_flag == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            cerr << "sendto failed with error: " << error_code << endl;
            return true; // сигнализируем об ошибке чтобы выйти из цикла
        } else {
            PacketData packetData;
            packetData.id = currPacket;
            packetData.status = PacketStatus::SENT;
            packetData.send_timestamp = chrono::steady_clock::now();
            size_t data_off = offsetof(ICMPhdr, data);
            if (sendBuffer.size() >= data_off + sizeof(uint32_t)) {
                packetData.guid.assign(sendBuffer.begin() + data_off,
                                       sendBuffer.begin() + data_off + sizeof(uint32_t));
            }

            cout << "send Hex: ";
            if (send_flag > 0 && static_cast<size_t>(send_flag) <= sendBuffer.size()) {
                print_hex(reinterpret_cast<const char*>(sendBuffer.data()), (int)sendBuffer.size(), send_flag);
            }

            packets.push_back(packetData);
            ++currPacket;
            next_send = now + chrono::milliseconds(SEND_INTERVAL_MS);
        }
    }
    return false;
}
void check_timeout(vector<PacketData>& packets, int RESPONSE_TIMEOUT_MS)
{
    auto now = chrono::steady_clock::now();
    for (auto& pkt : packets) {
        if (pkt.status == PacketStatus::SENT) {
            if (chrono::duration_cast<chrono::milliseconds>(now - pkt.send_timestamp).count() > RESPONSE_TIMEOUT_MS) {
                cout << "Packet with id " << pkt.id << " timed out. Lost package." << endl;
                pkt.status = PacketStatus::TIMED_OUT;
            }
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
        int sender_addr_len = sizeof(sender_addr);
        int recv_flag = recvfrom(s, recvBuffer.data(), static_cast<int>(recvBuffer.size()), 0,
                                 (struct sockaddr*)&sender_addr, &sender_addr_len);
        if (recv_flag == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            if (error_code == WSAEWOULDBLOCK) {
                // нечего читать
                break;
            } else {
                cerr << "recvfrom failed with error: " << error_code << endl;
                break;
            }
        }
        cout << "Get packet № " << currPacket << endl;

        int recv_len = recv_flag;
        if (recv_len <= 0) continue;
        size_t ip_header_len = (static_cast<uint8_t>(recvBuffer[0]) & 0x0F) * 4;
        if (ip_header_len < IP_HDR_MIN || static_cast<size_t>(recv_len) < ip_header_len + ICMP_HDR_MIN) continue;

        const uint8_t* icmp_start = reinterpret_cast<const uint8_t*>(recvBuffer.data()) + ip_header_len;
        ICMPhdr l_icmp;
        memcpy(&l_icmp, icmp_start, std::min(sizeof(ICMPhdr), static_cast<size_t>(recv_len) - ip_header_len));
        uint8_t type = l_icmp.type;
        uint8_t code = l_icmp.code;
        uint32_t guid = l_icmp.data;

        bool matched = false;
        for (auto &pkt : packets) {
            if (pkt.status == PacketStatus::SENT) {
                uint32_t sent_guid = ntohl(bytes_to_uint32(pkt.guid,0));
                uint32_t recv_guid = ntohl(l_icmp.data);
                if (sent_guid == recv_guid && !is_error((TypeRequest)type)) {
                    pkt.status = PacketStatus::RESP_RECVD;
                    status_of_err((TypeRequest)type, (TypeCodes)code);
                    pkt.receive_timestamp = chrono::steady_clock::now();
                    auto dur_ms = chrono::duration_cast<chrono::milliseconds>(pkt.receive_timestamp - pkt.send_timestamp).count();
                    cout << "Packet id: " << pkt.id << " is Ok! "<< " duration: " << dur_ms << " ms\n";
                    cout << hex << "guid: ";
                    for (unsigned char byte : pkt.guid) {
                        cout << setw(2) << setfill('0') << hex << (int)byte << " ";
                    }
                    cout << dec << " type: " << (int)type << " code: " << (int)code << endl;
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            cout << "No matching packet guid found in this response\n";
        }
        cout << "response in Hex: ";
        print_hex(recvBuffer.data(), (int)recvBuffer.size(), recv_flag);
        cout << endl;
    }
}

int main()
{
    if (init_socket(sock) != 0) {
        cerr << "socket init failed\n";
        return 1;
    }

    struct sockaddr_in dest_addr; //хранит адрес, содержится внутри addrinfo
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(sin_addr);

    fd_set readfs;

    vector<char> recvBuffer(4096);
    vector<char> sendBuffer;
    vector<PacketData> packets;

    auto next_send = std::chrono::steady_clock::now();

    int countPacket = 4;
    int currPacket = 0;

    while (true) {
        // отправка пакета
        if (send_packets(sock, dest_addr, sendBuffer, currPacket, countPacket, next_send, packets)) {
            break;
        }

        // проверка тайм-аутов
        check_timeout(packets, RESPONSE_TIMEOUT_MS);

        // вывод об окончании отправки
        bool all_responses_received = true;
        for (auto& pkt : packets) {
            if (pkt.status == PacketStatus::SENT) {
                all_responses_received = false;
                break;
            }
        }
        if (currPacket > countPacket - 1 && all_responses_received) {
            cout << "Все пакеты отправлены." << endl;
            break;
        }

        // select и чтение ответов
        FD_ZERO(&readfs);
        FD_SET(sock, &readfs);
        timeval select_timeout{0, 100000};
        int select_flag = select(0, &readfs, NULL, NULL, &select_timeout);
        if (select_flag == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            cerr << "select failed with error: " << error_code << endl;
            break;
        }
        if (FD_ISSET(sock, &readfs)) {
            cout << "socket is ready!" << endl;
            read_socket(sock, recvBuffer, packets, currPacket);
        }

        Sleep(1);
    }

    for (const auto& pkt : packets) {
        print_packet(pkt);
        cout << "-----------------\n";
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}


