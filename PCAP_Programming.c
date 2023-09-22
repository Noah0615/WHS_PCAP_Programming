#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>

#pragma pack(push, 1)

// printUsage(), printMACAddress(), printIPAddress() �Լ��� ����ڿ��� ���� �޽����� ����ϰų� MAC �ּҿ� IP �ּҸ� ����ϴ� �� ���˴ϴ�.
typedef struct {
    uint8_t dst_MAC[6];
    uint8_t src_MAC[6];
    uint16_t ether_type;
} EthernetHeader;

typedef struct {
    uint8_t v_l;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} IPHeader;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} TCPHeader;

typedef struct {
    EthernetHeader eth;
    IPHeader ip;
    TCPHeader tcp;
} Packet;

#pragma pack(pop)

// printUsage(), printMACAddress(), printIPAddress() �Լ��� ����ڿ��� ���� �޽����� ����ϰų� MAC �ּҿ� IP �ּҸ� ����ϴ� �� ���˴ϴ�.
void printUsage() {
    printf("����: pcap_test <�������̽�>\n");
    printf("����: pcap_test wlan0\n");
}

void printMACAddress(uint8_t* addr) {
    printf(" >>>> %02X:%02X:%02X:%02X:%02X:%02X\n",
        addr[0], addr[1], addr[2], addr[3],
        addr[4], addr[5]);
}

void printIPAddress(uint32_t ip) {
    printf(" >>>> %d.%d.%d.%d\n", ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printUsage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "��ġ�� �� �� �����ϴ�. %s: %s\n", dev, errbuf);
        return -1;
    }
    printf("pcap �ڵ��� ���������� �������ϴ�.\n");

    unsigned char* real_data;

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* data;

        int res = pcap_next_ex(handle, &header, &data);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        Packet* packet = (Packet*)data;

        if (ntohs(packet->eth.ether_type) != 2048) { // If not IPv4
            continue;
        }

        uint8_t ip_header_len = (packet->ip.v_l & 0xF) * 4;
        uint8_t tcp_header_len = (packet->tcp.offset_reserved >> 4) * 4;

        uint16_t ip_len = ntohs(packet->ip.total_len);

        if (packet->ip.protocol != 6) { //if not TCP
            continue;
        }

        printf("\nIP ��Ŷ ����: %d\n", ip_len);
        printf("IP ��� ����: %d\n", ip_header_len);
        printf("TCP ����: %d\n", tcp_header_len);
        printf("----------------------------\n");

        // �̴��� ���
        printf("������ MAC �ּ�");
        printMACAddress(packet->eth.dst_MAC);
        printf("����� MAC �ּ�");
        printMACAddress(packet->eth.src_MAC);
        printf("�̴��� Ÿ�� >> %04X\n", ntohs(packet->eth.ether_type));
        printf("----------------------------\n");

        // IP ���
        printf("������ IP �ּ�");
        printIPAddress(packet->ip.dst_ip);
        printf("����� IP �ּ�");
        printIPAddress(packet->ip.src_ip);
        printf("�������� >> %04X\n", packet->ip.protocol);
        printf("----------------------------\n");

        // TCP ���
        printf("������ ��Ʈ >> %d\n", ntohs(packet->tcp.dst_port));
        printf("����� ��Ʈ >> %d\n", ntohs(packet->tcp.src_port));

        // ������
        if (ip_len - ip_header_len - tcp_header_len > 0) {
            real_data = (unsigned char*)(packet + sizeof(Ether) + ip_header_len + tcp_header_len);
            printf("������ >> \n");
            for (int i = 0; i < ip_len - ip_header_len - tcp_header_len; i++) {
                printf("%02X ", real_data[i]);
                if (i % 16 == 0) {
                    printf("\n");
                }
            }
            printf("\n");
        }
        printf("============================\n");
    }

    pcap_close(handle);
    return 0;
}
