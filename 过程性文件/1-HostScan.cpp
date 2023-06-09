#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS


#include <iostream>
#include <pcap.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
using namespace std;

/*该程序通过调用pcap_open_live函数打开网络接口，并使用pcap_findalldevs_ex函数获取所有网络接口。
然后，它使用pcap_addr结构体遍历每个网络接口的IP地址，并使用系统调用发送ping包来判断每个IP地址是否可达。
最后，程序输出可达的IP地址。
请注意，该程序仅作为示例，可能存在一些漏洞和不足之处，如仅使用ping包来判断主机是否可达可能存在误报和漏报等问题。
因此，在实际使用中，您可能需要根据具体情况进行修改和优化。*/
int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    int i = 0;
    string subnet = "129.211.214.";
    string ip;

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

        // 遍历IP段中的所有IP地址
        for (int j = 1; j <= 255; j++)
        {
            ip = subnet + to_string(j);
            if (ip == dev_ip)
                continue;

            // 发送ping包
            string ping_cmd = "ping -n 1 -w 1000 " + ip;
            if (system(ping_cmd.c_str()) == 0)
            {
                cout << "Host " << ip << " is up" << endl;
            }
        }

        pcap_close(handle);
    }

    pcap_freealldevs(alldevs);
    return 0;
}