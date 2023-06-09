#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS


#include <iostream>
#include <pcap.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
using namespace std;

/*�ó���ͨ������pcap_open_live����������ӿڣ���ʹ��pcap_findalldevs_ex������ȡ��������ӿڡ�
Ȼ����ʹ��pcap_addr�ṹ�����ÿ������ӿڵ�IP��ַ����ʹ��ϵͳ���÷���ping�����ж�ÿ��IP��ַ�Ƿ�ɴ
��󣬳�������ɴ��IP��ַ��
��ע�⣬�ó������Ϊʾ�������ܴ���һЩ©���Ͳ���֮�������ʹ��ping�����ж������Ƿ�ɴ���ܴ����󱨺�©�������⡣
��ˣ���ʵ��ʹ���У���������Ҫ���ݾ�����������޸ĺ��Ż���*/
int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    int i = 0;
    string subnet = "129.211.214.";
    string ip;

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

        // ����IP���е�����IP��ַ
        for (int j = 1; j <= 255; j++)
        {
            ip = subnet + to_string(j);
            if (ip == dev_ip)
                continue;

            // ����ping��
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