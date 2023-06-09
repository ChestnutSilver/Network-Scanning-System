#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <WinSock2.h>
#include <Windows.h>
#include <pcap.h>
#include<stdint.h>

#pragma comment(lib, "packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")

int enumAdapters()
{
	pcap_if_t* allAdapters;    // ���������豸����
	pcap_if_t* ptr;            // ���ڱ�����ָ��
	int index = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* ��ȡ���ػ����豸�б� */
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &allAdapters, errbuf) != -1)
	{
		/* ��ӡ������Ϣ�б� */
		for (ptr = allAdapters; ptr != NULL; ptr = ptr->next)
		{
			// printf("������ַ: %x ����ID: %s \n", ptr->addresses, ptr->name);
			++index;
			if (ptr->description)
				printf("ID: %d --> Name: %s \n", index, ptr->description);
		}
	}

	/* ������Ҫ�豸�б��ˣ��ͷ��� */
	pcap_freealldevs(allAdapters);
	return index;
}

#define hcons(A) (((WORD)(A)&0xFF00)>>8) | (((WORD)(A)&0x00FF)<<8)

// ��� ������·��
void PrintEtherHeader(const u_char* packetData)
{
	typedef struct ether_header {
		u_char ether_dhost[6];    // Ŀ���ַ
		u_char ether_shost[6];    // Դ��ַ
		u_short ether_type;       // ��̫������
	} ether_header;

	struct ether_header* eth_protocol;
	eth_protocol = (struct ether_header*)packetData;

	u_short ether_type = ntohs(eth_protocol->ether_type);  // ��̫������
	u_char* ether_src = eth_protocol->ether_shost;         // ��̫��ԭʼMAC��ַ
	u_char* ether_dst = eth_protocol->ether_dhost;         // ��̫��Ŀ��MAC��ַ

	printf("����: 0x%x \t", ether_type);
	printf("ԭMAC��ַ: %02X:%02X:%02X:%02X:%02X:%02X \t",
		ether_src[0], ether_src[1], ether_src[2], ether_src[3], ether_src[4], ether_src[5]);
	printf("Ŀ��MAC��ַ: %02X:%02X:%02X:%02X:%02X:%02X \n",
		ether_dst[0], ether_dst[1], ether_dst[2], ether_dst[3], ether_dst[4], ether_dst[5]);
}

void PrintIPHeader(const u_char* packetData)
{
	typedef struct ip_header
	{
		char version : 4;
		char headerlength : 4;
		char cTOS;
		unsigned short totla_length;
		unsigned short identification;
		unsigned short flags_offset;
		char time_to_live;
		char Protocol;
		unsigned short check_sum;
		unsigned int SrcAddr;
		unsigned int DstAddr;
	}ip_header;

	struct ip_header* ip_protocol;

	// +14 ����������·��
	ip_protocol = (struct ip_header*)(packetData + 14);
	SOCKADDR_IN Src_Addr, Dst_Addr = { 0 };

	u_short check_sum = ntohs(ip_protocol->check_sum);
	int ttl = ip_protocol->time_to_live;
	int proto = ip_protocol->Protocol;

	Src_Addr.sin_addr.s_addr = ip_protocol->SrcAddr;
	Dst_Addr.sin_addr.s_addr = ip_protocol->DstAddr;

	printf("Դ��ַ: %15s --> ", inet_ntoa(Src_Addr.sin_addr));
	printf("Ŀ���ַ: %15s --> ", inet_ntoa(Dst_Addr.sin_addr));

	printf("У���: %5X --> TTL: %4d --> Э������: ", check_sum, ttl);
	switch (ip_protocol->Protocol)
	{
		case 1: printf("ICMP \n"); break;
		case 2: printf("IGMP \n"); break;
		case 6: printf("TCP \n");  break;
		case 17: printf("UDP \n"); break;
		case 89: printf("OSPF \n"); break;
		default: printf("None \n"); break;
	}
}

void PrintTCPHeader(const unsigned char* packetData)
{
	typedef struct tcp_header
	{
		short SourPort;                 // Դ�˿ں�16bit
		short DestPort;                 // Ŀ�Ķ˿ں�16bit
		unsigned int SequNum;           // ���к�32bit
		unsigned int AcknowledgeNum;    // ȷ�Ϻ�32bit
		unsigned char reserved : 4, offset : 4; // Ԥ��ƫ��

		unsigned char  flags;               // ��־ 

		short WindowSize;               // ���ڴ�С16bit
		short CheckSum;                 // �����16bit
		short surgentPointer;           // ��������ƫ����16bit
	}tcp_header;

	struct tcp_header* tcp_protocol;
	// +14 ����������·�� +20 ����IP��
	tcp_protocol = (struct tcp_header*)(packetData + 14 + 20);

	u_short sport = ntohs(tcp_protocol->SourPort);
	u_short dport = ntohs(tcp_protocol->DestPort);
	int window = tcp_protocol->WindowSize;
	int flags = tcp_protocol->flags;

	printf("Դ�˿�: %6d --> Ŀ��˿�: %6d --> ���ڴ�С: %7d --> ��־: (%d)",
		sport, dport, window, flags);

	if (flags & 0x08) printf("PSH ���ݴ���\n");
	else if (flags & 0x10) printf("ACK ��Ӧ\n");
	else if (flags & 0x02) printf("SYN ��������\n");
	else if (flags & 0x20) printf("URG \n");
	else if (flags & 0x01) printf("FIN �ر�����\n");
	else if (flags & 0x04) printf("RST ��������\n");
	else printf("None δ֪\n");
}

void PrintUDPHeader(const unsigned char* packetData)
{
	typedef struct udp_header {
		uint32_t sport;   // Դ�˿�
		uint32_t dport;   // Ŀ��˿�
		uint8_t zero;     // ����λ
		uint8_t proto;    // Э���ʶ
		uint16_t datalen; // UDP���ݳ���
	}udp_header;

	struct udp_header* udp_protocol;
	// +14 ����������·�� +20 ����IP��
	udp_protocol = (struct udp_header*)(packetData + 14 + 20);

	u_short sport = ntohs(udp_protocol->sport);
	u_short dport = ntohs(udp_protocol->dport);
	u_short datalen = ntohs(udp_protocol->datalen);

	printf("Դ�˿�: %5d --> Ŀ��˿�: %5d --> ��С: %5d \n", sport, dport, datalen);
}


void PrintICMPHeader(const unsigned char* packetData)
{
	typedef struct icmp_header {
		uint8_t type;        // ICMP����
		uint8_t code;        // ����
		uint16_t checksum;   // У���
		uint16_t identification; // ��ʶ
		uint16_t sequence;       // ���к�
		uint32_t init_time;      // ����ʱ���
		uint16_t recv_time;      // ����ʱ���
		uint16_t send_time;      // ����ʱ���
	}icmp_header;


	struct icmp_header* icmp_protocol;
	// +14 ����������·�� +20 ����IP��
	icmp_protocol = (struct icmp_header*)(packetData + 14 + 20);

	int type = icmp_protocol->type;
	int init_time = icmp_protocol->init_time;
	int send_time = icmp_protocol->send_time;
	int recv_time = icmp_protocol->recv_time;
	if (type == 8)
	{
		printf("����ʱ���: %d --> ����ʱ���: %d --> ����ʱ���: %d ����: ",
			init_time, send_time, recv_time);

		switch (type)
		{
			case 0: printf("����Ӧ���� \n"); break;
			case 8: printf("���������� \n"); break;
			default:break;
		}
	}
}


void MonitorAdapter(int nChoose)
{
	pcap_if_t* adapters;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &adapters, errbuf) != -1)
	{
		// �ҵ�ָ��������
		for (int x = 0; x < nChoose - 1; ++x)
			adapters = adapters->next;

		char errorBuf[PCAP_ERRBUF_SIZE];

		// PCAP_OPENFLAG_PROMISCUOUS = ��������Ϊ����ģʽ
		// 1000 => 1000�����������������ֱ�ӷ��س�ʱ
		pcap_t* handle = pcap_open(adapters->name, 65534, 1, PCAP_OPENFLAG_PROMISCUOUS, 0, 0);

		if (adapters == NULL)
			return;

		// printf("��ʼ����: % \n", adapters->description);
		pcap_pkthdr* Packet_Header;    // ���ݰ�ͷ
		const u_char* Packet_Data;    // ���ݱ���
		int retValue;
		while ((retValue = pcap_next_ex(handle, &Packet_Header, &Packet_Data)) >= 0)
		{
			if (retValue == 0)
				continue;
			// printf("��������: %d \n", Packet_Header->len);
			//PrintEtherHeader(Packet_Data);
			//PrintIPHeader(Packet_Data);
			//PrintTCPHeader(Packet_Data);
			//PrintUDPHeader(Packet_Data);
			PrintICMPHeader(Packet_Data);
		}
	}
}


int main(int argc, char* argv[])
{
	int network = enumAdapters();
	printf("��������: %d \n", network);

	MonitorAdapter(5);


	system("Pause");

}