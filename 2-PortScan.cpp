#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <pcap.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <string>
#include <bitset>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")

using namespace std;

/* �ó���ͨ������pcap_open_live����������ӿڣ���ʹ��pcap_findalldevs_ex������ȡ��������ӿڡ�
   Ȼ����ʹ��pcap_addr�ṹ�����ÿ������ӿڵ�IP��ַ����ʹ��ϵͳ���÷���ping�����ж�ÿ��IP��ַ�Ƿ�ɴ
   ��󣬳�������ɴ��IP��ַ��
   ��ע�⣬�ó������Ϊʾ�������ܴ���һЩ©���Ͳ���֮�������ʹ��ping�����ж������Ƿ�ɴ���ܴ����󱨺�©�������⡣
   ��ˣ���ʵ��ʹ���У���������Ҫ���ݾ�����������޸ĺ��Ż���*/

   // ɨ��˿ں���
void scan_port(string ip, int port) {
    WSADATA wsaData;
    SOCKET s;
    struct sockaddr_in server;
    int ret;

    // ��ʼ��Winsock
    ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        cerr << "Error: WSAStartup failed with error " << ret << endl;
        return;
    }

    // �����׽���
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        cerr << "Error: socket creation failed with error " << WSAGetLastError() << endl;
        WSACleanup();
        return;
    }

    // ����server�ĵ�ַ��Ϣ
    server.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr.s_addr);
    server.sin_port = htons(port);

    // ���ӵ�Ŀ������
    ret = connect(s, (struct sockaddr*)&server, sizeof(server));
    if (ret == SOCKET_ERROR) {
        // �˿�δ����
        if (WSAGetLastError() == WSAECONNREFUSED) {
            cout << "Port " << port << " is closed" << endl;
        }
        else {
            cerr << "Error: connect failed with error " << WSAGetLastError() << endl;
        }
    }
    else {
        // �˿��ѿ���
        cout << "Port " << port << " is open" << endl;
    }

    closesocket(s);
    WSACleanup();
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* dev;

    // ��ȡ��������ӿ�
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        cerr << "Error in pcap_findalldevs_ex: " << errbuf << endl;
        return -1;
    }

    // ������������ӿ�
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        pcap_t* handle;
        struct pcap_pkthdr header;
        const u_char* packet;
        string dev_ip;

        // ������ӿ�
        handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL)
        {
            cerr << "Error in pcap_open_live: " << errbuf << endl;
            continue;
        }

        // ��ȡ����ӿڵ�IP��ַ
        struct pcap_addr* addr;
        for (addr = dev->addresses; addr != NULL; addr = addr->next)
        {
            if (addr->addr->sa_family == AF_INET)
            {
                dev_ip = inet_ntoa(((struct sockaddr_in*)addr->addr)->sin_addr);
                break;
            }
        }

        // ָ������ip
        string target_ip = "129.211.214.28";

        // ɨ��˿�
        for (int i = 20; i <= 1000; i++) {
            scan_port(target_ip, i);
        }

        pcap_close(handle);
    }

    pcap_freealldevs(alldevs);
    return 0;
}