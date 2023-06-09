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

/* 该程序通过调用pcap_open_live函数打开网络接口，并使用pcap_findalldevs_ex函数获取所有网络接口。
   然后，它使用pcap_addr结构体遍历每个网络接口的IP地址，并使用系统调用发送ping包来判断每个IP地址是否可达。
   最后，程序输出可达的IP地址。
   请注意，该程序仅作为示例，可能存在一些漏洞和不足之处，如仅使用ping包来判断主机是否可达可能存在误报和漏报等问题。
   因此，在实际使用中，您可能需要根据具体情况进行修改和优化。*/

   // 扫描端口函数
void scan_port(string ip, int port) {
    WSADATA wsaData;
    SOCKET s;
    struct sockaddr_in server;
    int ret;

    // 初始化Winsock
    ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        cerr << "Error: WSAStartup failed with error " << ret << endl;
        return;
    }

    // 创建套接字
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        cerr << "Error: socket creation failed with error " << WSAGetLastError() << endl;
        WSACleanup();
        return;
    }

    // 设置server的地址信息
    server.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &server.sin_addr.s_addr);
    server.sin_port = htons(port);

    // 连接到目标主机
    ret = connect(s, (struct sockaddr*)&server, sizeof(server));
    if (ret == SOCKET_ERROR) {
        // 端口未开放
        if (WSAGetLastError() == WSAECONNREFUSED) {
            cout << "Port " << port << " is closed" << endl;
        }
        else {
            cerr << "Error: connect failed with error " << WSAGetLastError() << endl;
        }
    }
    else {
        // 端口已开放
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

    // 获取所有网络接口
    if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        cerr << "Error in pcap_findalldevs_ex: " << errbuf << endl;
        return -1;
    }

    // 遍历所有网络接口
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        pcap_t* handle;
        struct pcap_pkthdr header;
        const u_char* packet;
        string dev_ip;

        // 打开网络接口
        handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL)
        {
            cerr << "Error in pcap_open_live: " << errbuf << endl;
            continue;
        }

        // 获取网络接口的IP地址
        struct pcap_addr* addr;
        for (addr = dev->addresses; addr != NULL; addr = addr->next)
        {
            if (addr->addr->sa_family == AF_INET)
            {
                dev_ip = inet_ntoa(((struct sockaddr_in*)addr->addr)->sin_addr);
                break;
            }
        }

        // 指定主机ip
        string target_ip = "129.211.214.28";

        // 扫描端口
        for (int i = 20; i <= 1000; i++) {
            scan_port(target_ip, i);
        }

        pcap_close(handle);
    }

    pcap_freealldevs(alldevs);
    return 0;
}