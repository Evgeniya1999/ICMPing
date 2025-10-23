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
SOCKET sock;

int socket_flag;
int recv_flag;
int select_flag;

//constans
const int SEND_INTERVAL_MS = 1000;
const int RESPONSE_TIMEOUT_MS = 4000;
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
struct PacketData {
    int id{-1}; //для сравнения с кол-вом пакетов
    PacketStatus status = PacketStatus::NSEND;
    chrono::steady_clock::time_point send_timestamp;
    chrono::steady_clock::time_point receive_timestamp;
    vector<uint8_t> guid;
};
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
#pragma pack(push,1) //выравнивание
struct ICMPhdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t data;
};
#pragma pack(pop)

//methods
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
unsigned long createGuidPart() {
    GUID g;
    if (CoCreateGuid(&g) == S_OK) {
        // 32 бита
        return g.Data1;
    }
    return 0;
}
vector<char> packetForm(){
    ICMPhdr icmphdr;
    auto resultGuid = createGuidPart();
    cout << "GuidPart: " << resultGuid << endl;

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

    printf("type=%02X code=%02X ", icmphdr.type, icmphdr.code);
    printf("checksum=%04X ", icmphdr.checksum);
    printf("payload=%08X ", icmphdr.data);
    return sendBuffer;
}
std::pair<TypeRequest, TypeCodes> parse_of_request(const std::vector<char>& request, size_t size, vector<char>::iterator iterator);
pair <TypeRequest, string> status_of_err(TypeRequest type, TypeCodes code);
bool is_error (TypeRequest type);

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
int main()
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    wVersionRequested = MAKEWORD(2, 2); //задаёт версию библ winsock

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        cout <<"WSAStartup failed with error: " << err;
        return 1;
    }
    if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
        cout << "Could not find a usable version of Winsock.dll" << endl;
        WSACleanup();
        return 1;
    }
    else
        cout << "The Winsock 2.2 dll was found okay" << endl;

    struct addrinfo hints; //вход (как должно быть)
    struct addrinfo *result = NULL; //выход

    memset(&hints, 0, sizeof(hints));       // обязательно заполнить нулями
    hints.ai_family = AF_INET;              // IPv4
    hints.ai_socktype = SOCK_RAW;           // сырой сокет
    hints.ai_protocol = IPPROTO_ICMP;       // ICMP протокол

    err = getaddrinfo(NULL, "0", &hints, &result);
    if (err != 0) {
        cout <<"getaddrinfo failed with error: " << err << " " << gai_strerrorA(err);
        WSACleanup();
        return 1;
    }

    //INIT SOCKET
    sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        //cerr << "socket not valid. " << err;
        int error_code = WSAGetLastError();
        cerr << "create socket failed with error: " << error_code << endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    DWORD nonBlocking = 1;
    if ( ioctlsocket( sock, FIONBIO, &nonBlocking ) != 0 )
    {
        int error_code = WSAGetLastError();
        cerr << "nonblocking socket failed with error: " << error_code << endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    struct sockaddr_in dest_addr; // низкий уровень абстракции, хранит сам адрес, содержится внутри addrinfo
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

    // Создаем пустую структуру для хранения адреса отправителя
    struct sockaddr_in sender_addr;
    socklen_t sender_addr_len = sizeof(sender_addr);
    fd_set readfs;

    vector<char> recvBuffer(1500);
    vector<char> sendBuffer;
    vector<PacketData> packets;

    auto next_send = std::chrono::steady_clock::now();

    int countPacket = 4;
    int currPacket = 0;
    while (true) {
         auto now = steady_clock::now();
        if (currPacket <= countPacket-1) {
            if (now >= next_send) {
                sendBuffer = packetForm();
                //SENDTO
                int send_flag = sendto(sock,
                                       sendBuffer.data(),
                                       (int)sendBuffer.size(),
                                       0,
                                       (struct sockaddr*)&dest_addr,
                                       sizeof(dest_addr));
                cout << "send buffer size: " << sendBuffer.size() << " byte" << endl;
                if (send_flag == SOCKET_ERROR) {
                    int error_code = WSAGetLastError();
                    cerr << "sendto failed with error: " << error_code << endl;
                    break;
                } else {
                    PacketData packetData;
                    packetData.id = currPacket;
                    packetData.status = PacketStatus::SENT;
                    packetData.send_timestamp = chrono::steady_clock::now();
                    size_t data_off = offsetof(ICMPhdr, data);
                    packetData.guid.assign(
                        reinterpret_cast<uint8_t*>(sendBuffer.data() + data_off),
                        reinterpret_cast<uint8_t*>(sendBuffer.data() + data_off + sizeof(uint32_t))
                        );

                    cout << "send Hex: ";
                    for (int i = 0; i < send_flag; ++i) {
                        unsigned char c = (unsigned char)sendBuffer[i];
                        printf("%02X ", c);
                    }
                    cout << endl;

                    packets.push_back(packetData); // сохраняем пакет
                    currPacket++;
                    next_send = now + milliseconds(SEND_INTERVAL_MS);


                }
            }
        }
        //поиск запросов без ответа
        bool all_responses_received = true;
        for (auto& pkt : packets) {
            if (pkt.status == PacketStatus::SENT) {
                all_responses_received = false;
                if (chrono::duration_cast<milliseconds>(now - pkt.send_timestamp).count() > RESPONSE_TIMEOUT_MS) {
                    cout << "Packet with id " << pkt.id << " timed out. Lost package." << endl;
                    pkt.status = PacketStatus::TIMED_OUT;
                    break;
                }
            }
        }
        if (currPacket > countPacket - 1 && all_responses_received) {
            cout << "Все пакеты отправлены." << endl;
            break;
        }

        FD_ZERO(&readfs);
        FD_SET(sock, &readfs); //добавление дескриптора файла в набор для совершения операции

        struct timeval select_timeout;
        select_timeout.tv_sec = 0;
        select_timeout.tv_usec = 100000;

        //SELECT
        select_flag = select(0, &readfs, NULL, NULL, &select_timeout);
        if (select_flag == SOCKET_ERROR){
            int error_code = WSAGetLastError();
            cerr << "select failed with error: " << error_code << endl;
            break;
        }
        if (FD_ISSET(sock, &readfs)){ // есть ли данные для чтения
            cout << "socket is ready!" << endl;
            cout << "packets.size(): "<< packets.size() << " " << "count: " << countPacket << " " << "currP: " << currPacket << endl;
                //RECVFROM
                while(true) {
                    sender_addr_len = sizeof(sender_addr);
                    recv_flag = recvfrom(sock, recvBuffer.data(), (int)recvBuffer.size(), 0, (struct sockaddr *)&sender_addr, &sender_addr_len); //приём данных по сокету
                    if (recv_flag == SOCKET_ERROR) {
                        int error_code = WSAGetLastError();
                        if (error_code == WSAEWOULDBLOCK) {
                            cout << "end read " << endl;
                            break;
                        } else {
                            cerr << "recvfrom failed with error: " << error_code << endl;
                        }
                    } else if (recv_flag > 0 ){
                        cout << "read packet " << currPacket << endl;

                        bool matched = false;
                        auto recv_end = recvBuffer.begin() + recv_flag;
                        for (auto &pkt : packets) {
                            //парсинг ответов(поиск guid в строке ответа) и присвоение статуса "ответ получен"
                            if (pkt.status == PacketStatus::SENT) {
                                if (pkt.guid.empty()) continue;
                                cout << "Searching for GUID (hex): ";
                                for (unsigned char byte : pkt.guid) {
                                    cout << setw(2) << setfill('0') << hex << (int)byte << " ";
                                }
                                cout << endl;

                                cout << "In recvBuffer (hex): ";

                                for (auto it = recvBuffer.begin(); it != recv_end; ++it) {
                                    cout << setw(2) << setfill('0') << hex << (int)(unsigned char)*it << " ";
                                }
                                cout << endl;
                                auto it = search(
                                    recvBuffer.begin(), recvBuffer.end(),
                                    pkt.guid.begin(), pkt.guid.end(),
                                    [](char b1, uint8_t b2){ return static_cast<uint8_t>(b1) == b2; }
                                    );
                                if (it != recvBuffer.end()) {
                                    auto [recvType, recvCode] = parse_of_request(recvBuffer, recvBuffer.size(), it);
                                    status_of_err(recvType, recvCode);
                                    if (is_error(recvType) == true){
                                        pkt.status = PacketStatus::RESP_ERROR;
                                    }else{
                                        pkt.status = PacketStatus::RESP_RECVD;
                                    }
                                    pkt.receive_timestamp = chrono::steady_clock::now();
                                    auto dur_ms = chrono::duration_cast<milliseconds>(pkt.receive_timestamp - pkt.send_timestamp).count();
                                    cout << "\nMatched packet id: " << pkt.id << " duration: " <<dec<< dur_ms << " ms\n";
                                    matched = true;
                                    break;
                                }
                            }
                        }
                        if (!matched) {
                            cout << "No matching packet guid found in this response\n";
                        }
                        cout << "recv Hex: ";
                        for (int i = 0; i < recv_flag; ++i) {
                            unsigned char c = (unsigned char)recvBuffer[i];
                            printf("%02X ", c);
                            if (i == 19) {
                                cout << "     " ;
                            }
                        }
                        cout << endl;
                    }
                }
        } else {
            //cout << "данных для чтения нет или вышел тайм аут последнего пакета " << endl;
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

bool is_error (TypeRequest type){
    if (type == TypeRequest::TYPE3      ||
        type == TypeRequest::TYPE11     ||
        type == TypeRequest::TYPE12     ||
        type == TypeRequest::TYPE5){
        return true;
    } else return false;
}
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
pair<TypeRequest, TypeCodes> parse_of_request(const std::vector<char>& request,size_t size, vector<char>::iterator iterator){
    TypeRequest type;
    TypeCodes code;
    if (iterator != request.end()) {
        printf("code=%02X\n", static_cast<unsigned char>(*(iterator-3)));
        printf("type=%02X\n", static_cast<unsigned char>(*(iterator-4)));

    } else {
        cout << ("Pattern not found\n") << endl;
    }
    return make_pair(type, code);
}
