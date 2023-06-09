#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

using namespace std::chrono_literals;

constexpr int THREAD_NUM = 10;  // �߳���
constexpr int PORT_BEGIN = 1;  // ɨ��˿���ʼ��
constexpr int PORT_END = 1000; // ɨ��˿ڽ�����

std::mutex s_mutex;  // �����������ڱ���������Դ
std::atomic<int> s_port(PORT_BEGIN);  // ԭ�ӱ��������ڼ�¼Ҫɨ��Ķ˿ں�

void scan_port(const std::string& ip)
{
    while (true)
    {
        int port = s_port++;  // ��ȡҪɨ��Ķ˿ںţ�ԭ�Ӳ���
        if (port > PORT_END)  // ���ɨ��Ķ˿ں��Ѿ������˷�Χ������ѭ��
            break;

        sockaddr_in addr{};  // ����һ��sockaddr_in���͵ı�������ʾҪ���ӵĵ�ַ
        addr.sin_family = AF_INET;  // ���õ�ַ����ΪIPv4
        addr.sin_port = htons(port);  // ���ö˿ں�
        addr.sin_addr.s_addr = inet_addr(ip.c_str());  // ����IP��ַ

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  // ����TCP�׽���
        if (s == INVALID_SOCKET)  // ��������׽���ʧ�ܣ�����������һ���˿�
            continue;

        u_long mode = 1;
        if (ioctlsocket(s, FIONBIO, &mode) == SOCKET_ERROR)  // �����׽���Ϊ������ģʽ
        {
            closesocket(s);
            continue;
        }

        int result = connect(s, (sockaddr*)&addr, sizeof(addr));  // ���ӵ�ָ����ַ
        if (result == SOCKET_ERROR)  // �������ʧ��
        {
            int error = WSAGetLastError();  // ��ȡ������
            if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS)  // ��������벻��"���ڽ�����"��"�������ᱻ����"
            {
                closesocket(s);  // �ر��׽��֣�����������һ���˿�
                continue;
            }
        }
        else if (result == 0)  // ������ӳɹ�
        {
            std::lock_guard<std::mutex> lock(s_mutex);  // ����������������Դ
            std::cout << "Port " << port << " is open." << std::endl;  // ���ɨ����
        }

        fd_set writefds{};  // ����һ���ļ����������ϣ����ڵȴ��׽��ֿ�д�¼�
        FD_ZERO(&writefds);
        FD_SET(s, &writefds);

        timeval timeout{};  // ���ó�ʱʱ��
        timeout.tv_sec = 1;  // ��ʱʱ��Ϊ1��
        timeout.tv_usec = 0;

        result = select(0, nullptr, &writefds, nullptr, &timeout);  // �ȴ��׽��ֿ�д�¼�
        if (result == SOCKET_ERROR)  // ������ִ���
        {
            closesocket(s);  // �ر��׽��֣�����������һ���˿�
            continue;
        }
        else if (result == 0)  // �����ʱ
        {
            closesocket(s);  // �ر��׽��֣�����������һ���˿�
            continue;
        }

        std::lock_guard<std::mutex> lock(s_mutex);  // ����������������Դ
        std::cout << "Port " << port << " is open." << std::endl;  // ���ɨ����
        closesocket(s);  // �ر��׽���
    }
}

int main()
{
    WSADATA wsaData{};  // ��ʼ��Winsock��
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0)  // �����ʼ��ʧ�ܣ����������Ϣ
    {
        std::cerr << "WSAStartup failed with error: " << err << std::endl;
        return -1;
    }

    std::string ip = "127.0.0.1";  // Ҫɨ�������IP

    std::thread threads[THREAD_NUM];  // ��������߳�
    for (int i = 0; i < THREAD_NUM; ++i)
    {
        threads[i] = std::thread(scan_port, ip);  // ÿ���̵߳���scan_port��������ɨ��
    }

    for (int i = 0; i < THREAD_NUM; ++i)
    {
        threads[i].join();  // �ȴ������߳̽���
    }

    WSACleanup();  // �ر�Winsock��

    return 0;
}

