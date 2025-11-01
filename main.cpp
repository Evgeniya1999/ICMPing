#include <iomanip>
#include <iostream>
#include <chrono>
#include <ctime>
#include <optional>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/time.h>
#include <unistd.h>
#include <objbase.h>
#include <algorithm>
#include <cstdint>
#include <array>

//namespaces
using namespace std;
using namespace std::chrono;
//variables
SOCKET sock = INVALID_SOCKET;
WSAEVENT recvEvent;

int socket_flag;
int recv_flag;
int select_flag;

//constans
const int SEND_INTERVAL_MS = 1000;
const int RESPONSE_TIMEOUT_MS = 4000;
const char* sin_addr = "8.8.8.8";

constexpr size_t ICMP_HDR_MIN = 20;
constexpr size_t IP_HDR_MIN = 20;

const int GUID_LEN = 16;

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
    uint8_t guid[16];
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
    uint16_t identifier;
    uint16_t sequence;
    uint8_t data[16];
};
#pragma pack(pop)

//methods
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

array<uint8_t, 16> create_guid() {

    GUID g;
    array<uint8_t, 16> result{};
    HRESULT hr = CoCreateGuid(&g);
    if (!SUCCEEDED(hr)) {
        cerr << "CoCreateGuid failed " << "\n";
        return result;
    }
    RPC_CSTR guidStr = nullptr; //тип для вывода формата guid
    if (UuidToStringA(&g, &guidStr) == RPC_S_OK && guidStr != nullptr) {
        cout << "Generated GUID: " << reinterpret_cast<char*>(guidStr) << "\n";
        RpcStringFreeA(&guidStr);
    }
    uint32_t d1 = htonl(g.Data1);
    uint16_t d2 = htons(g.Data2);
    uint16_t d3 = htons(g.Data3);

    memcpy(result.data() + 0, &d1, 4);
    memcpy(result.data() + 4, &d2, 2);
    memcpy(result.data() + 6, &d3, 2);
    memcpy(result.data() + 8, g.Data4, 8);

    return result;
}
void print_hex(const char* data, int len, int countBytes)
{
    if (countBytes) cout << "size: " << countBytes << " bytes" << endl;
    cout << hex << uppercase << setfill('0');
    size_t to_show = min(static_cast<size_t>(len), static_cast<size_t>(60));
    for (size_t i = 0; i < to_show; ++i){
        cout << setw(2) << (static_cast<unsigned int>(static_cast<unsigned char>(data[i]))) << ' '; //сначала перевод в символ для преобразования от 0-255, затем в int чтобы перевести в число
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
    cout.copyfmt(oldState);

}
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
    auto resultGuid = create_guid();
    if (resultGuid.size() != 16) {
        cerr << "create_guid returned size != 16" << std::endl;
        return {};
    }

    icmphdr.type = 8;
    icmphdr.code = 0;
    icmphdr.identifier = htons(1234);
    icmphdr.sequence = htons(currP);
    memcpy(icmphdr.data, resultGuid.data(), sizeof(icmphdr.data));
    icmphdr.checksum = 0;

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
}
void print_packet(const PacketData& p) {
    cout << "Packet id: " << p.id << "\n";
    cout << "  status: " << status_to_string(p.status) << "\n";
    //if (p.status == PacketStatus::RESP_RECVD) {
        auto durr = chrono::duration_cast<chrono::milliseconds>(p.receive_timestamp - p.send_timestamp).count();
        cout << "  duration_time: "
             <<dec<< durr  << " ms\n";
    //} else {
    //    cout << "  duration_time: --\n";
    //}
    cout << "  guid: ";
    for (auto b : p.guid) printf("%02X ", (unsigned) b);
    cout << endl;
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
    //s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP); //режим сниффера
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
    DWORD dwBytesReturned = 0;
    BOOL bOptVal = TRUE;
    if (WSAIoctl(s, SIO_RCVALL, &bOptVal, sizeof(bOptVal), //привилегию администратора (Raw socket + SIO_RCVALL)
                 NULL, 0, &dwBytesReturned, NULL, NULL) == SOCKET_ERROR) {
    }
    int ttl_value = 1;
    if ( setsockopt( s, IPPROTO_IP, IP_TTL, (const char*)&ttl_value,  sizeof(ttl_value)) != 0 )
    {
        int error_code = WSAGetLastError();
        cerr << "nonblocking socket failed with error: " << error_code << endl;
        closesocket(s);
        WSACleanup();
        return -1;
    }
    int optval = 0;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (const char*)&optval, sizeof(optval)) == SOCKET_ERROR) {
        cerr << "setsockopt(IP_HDRINCL) failed: " << WSAGetLastError() << endl;
    }

    recvEvent = WSACreateEvent();
    if (recvEvent == WSA_INVALID_EVENT){
        cerr << "WSACreateEvent failed: " << WSAGetLastError() << endl;
        closesocket(s);
        WSACleanup();
        return -1;
    }
    if (WSAEventSelect(s, recvEvent, FD_READ | FD_CLOSE | FD_OOB) == SOCKET_ERROR){
        cerr << "WSAEventSelect failed: " <<  WSAGetLastError() << endl;
        WSACloseEvent(recvEvent);
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
        int send_flag = sendto(s,
                               sendBuffer.data(),
                               static_cast<int>(sendBuffer.size()),
                               0,
                               (struct sockaddr*)&dest_addr,
                               sizeof(dest_addr));
        cout << "elements in sendBuffer: " << sendBuffer.size() << " byte" <<  endl;

        if (send_flag == SOCKET_ERROR) {
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
            if (send_flag > 0 && static_cast<size_t>(send_flag) <= sendBuffer.size()) {
                print_hex(sendBuffer.data(), static_cast<int>(sendBuffer.size()), send_flag);
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

        char buffer[1024];

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

        const uint8_t* icmp_start = reinterpret_cast<const uint8_t*>(recvBuffer.data()) + ip_header_len;
        size_t total_icmp_len = static_cast<size_t>(recv_len) - ip_header_len;
        cout << "res total_icmp_len: " << total_icmp_len << endl;

        if (ip_header_len < IP_HDR_MIN || static_cast<size_t>(recv_len) < ip_header_len + ICMP_HDR_MIN) continue;

        ICMPhdr l_icmp;
        memcpy(&l_icmp, icmp_start, min(sizeof(ICMPhdr), static_cast<size_t>(recv_len) - ip_header_len));
        uint8_t type = l_icmp.type;
        uint8_t code = l_icmp.code;

        for (auto &pkt : packets) {
            if (pkt.status == PacketStatus::SENT) {

                if (is_error((TypeRequest)type)) {
                    status_of_err((TypeRequest)type, (TypeCodes)code);
                    pkt.status = PacketStatus::RESP_ERROR;
                    pkt.receive_timestamp = chrono::steady_clock::now();
                    break;
                }
                if (total_icmp_len < ICMP_HDR_MIN) {
                    pkt.status = PacketStatus::RESP_ERROR;
                    pkt.receive_timestamp = chrono::steady_clock::now();
                    break;
                }
                //cout << "pkt.guid " << sizeof(pkt.guid) << " ";
                //print_data_cout(pkt.guid);
                //cout << "l_icmp.data " << sizeof(l_icmp.data) << " ";
                //print_data_cout(l_icmp.data);
                if (total_icmp_len >= offsetof(ICMPhdr, data) + GUID_LEN &&
                    equal(pkt.guid, pkt.guid + GUID_LEN, l_icmp.data)) {
                    if (total_icmp_len > ICMP_HDR_MIN) {
                        pkt.status = PacketStatus::RESP_ERROR;
                        if (is_error((TypeRequest)type)) status_of_err((TypeRequest)type, (TypeCodes)code);
                    } else {
                        pkt.status = PacketStatus::RESP_RECVD;
                    }
                } else {
                    pkt.status = PacketStatus::RESP_ERROR;
                    if (is_error((TypeRequest)type)) status_of_err((TypeRequest)type, (TypeCodes)code);
                }

                pkt.receive_timestamp = chrono::steady_clock::now();
                auto dur_ms = chrono::duration_cast<chrono::milliseconds>(pkt.receive_timestamp - pkt.send_timestamp).count();
                cout << "Packet id: " << pkt.id << " duration: " << dur_ms << " ms\n";
                cout << hex << "guid: ";
                for (unsigned char byte : pkt.guid) {
                    cout << setw(2) << setfill('0') << hex << (int)byte << " ";
                }
                cout << dec << " type: " << (int)type << " code: " << (int)code << endl;
                break;
            }
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

    auto next_send = chrono::steady_clock::now();
    int countPacket = 4;
    int currPacket = 0;

    while (true) {
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

        //DWORD waitResult = WSAWaitForMultipleEvents(1, &recvEvent, FALSE, 100, FALSE);

        //if (waitResult == WSA_WAIT_EVENT_0) {
        //    // Событие произошло, получаем информацию о событии
        //    WSANETWORKEVENTS networkEvents;
        //    if (WSAEnumNetworkEvents(sock, recvEvent, &networkEvents) == SOCKET_ERROR) {
        //        cerr << "WSAEnumNetworkEvents failed: " << WSAGetLastError() << endl;
        //        // Обработка ошибки
        //        continue;
        //    }

        //    // Проверяем, что именно произошло
        //    if (networkEvents.lNetworkEvents & FD_READ) {
        //        // Успешно получены данные (обычный пакет или ICMP Type 11)
        //        cout << "FD_READ event triggered. Socket is ready!" << endl;
        //        // Ваш вызов функции чтения
        //        read_socket(sock, recvBuffer, packets, currPacket);
        //    }
        //    if (networkEvents.lNetworkEvents & FD_CLOSE) {
        //        // Соединение закрыто
        //        cerr << "FD_CLOSE event triggered." << endl;
        //    }
        //    // FD_OOB и другие события, если нужно
        //}
        //else if (waitResult == WSA_WAIT_TIMEOUT) {
        //    // Таймаут ожидания, продолжаем цикл
        //    // cout << "Timeout..." << endl;
        //}
        //else {
        //    // Другая ошибка WSAWaitForMultipleEvents
        //}


        //использовать IcmpSendEcho
        // select и чтение ответов
        FD_ZERO(&readfs);
        FD_SET(sock, &readfs);
        timeval select_timeout{0, 100000};
        //timeval select_timeout{0, 10000};
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
    cout << "Нажмите любую клавишу для выхода...";
    cin.get();
    return 0;
}



