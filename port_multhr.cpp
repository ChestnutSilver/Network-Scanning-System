
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <winsock2.h>
#include <QString>
#include "mainwindow.h"
#include "ui_mainwindow.h"

#pragma comment(lib, "ws2_32.lib")

using namespace std;

constexpr int THREAD_NUM = 1000;  // 线程数
constexpr int PORT_BEGIN = 1;  // 扫描端口起始号
constexpr int PORT_END = 65535; // 扫描端口结束号

std::mutex s_mutex;
std::atomic<int> s_port(PORT_BEGIN);
QList<int>open_port;

void scan_port(const std::string& ip,int pstart, int pend)
{
    while (true)
    {
        int port = s_port++;
        if (port > PORT_END||port>pend)
            break;

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(ip.c_str());

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET)
            continue;

        u_long mode = 1;
        if (ioctlsocket(s, FIONBIO, &mode) == SOCKET_ERROR)
        {
            closesocket(s);
            continue;
        }

        int result = connect(s, (sockaddr*)&addr, sizeof(addr));
        if (result == SOCKET_ERROR)
        {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS)
            {
                closesocket(s);
                continue;
            }
        }
        else if (result == 0)
        {
            std::lock_guard<std::mutex> lock(s_mutex);
            if(port>=pstart){
                std::cout << "Port " << port << " is open." << std::endl;
                open_port.append(port);
            }
        }

        fd_set writefds{};
        FD_ZERO(&writefds);
        FD_SET(s, &writefds);

        timeval timeout{};
        timeout.tv_sec = 1;  // 超时时间为1秒
        timeout.tv_usec = 0;

        result = select(0, nullptr, &writefds, nullptr, &timeout);
        if (result == SOCKET_ERROR)
        {
            closesocket(s);
            continue;
        }
        else if (result == 0)
        {
            closesocket(s);
            continue;
        }

        std::lock_guard<std::mutex> lock(s_mutex);
        std::cout << "Port " << port << " is open." << std::endl;
        open_port.append(port);
        closesocket(s);
    }
}

int MainWindow::portscan_multhr(QString s,int pstart,int pend)
{
    WSADATA wsaData{};
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    open_port.clear();
    if (err != 0)
    {
        std::cerr << "WSAStartup failed with error: " << err << std::endl;
        return -1;
    }

    std::string ip = s.toStdString();  // 要扫描的主机IP

    std::thread threads[THREAD_NUM];
    for (int i = 0; i < THREAD_NUM; ++i)
    {
        threads[i] = std::thread(scan_port, ip,pstart,pend);
    }

    for (int i = 0; i < THREAD_NUM; ++i)
    {
        threads[i].join();
    }

    WSACleanup();

    for(int i=0;i<open_port.size();i++)
        ui->textB_port->append(QString::number(open_port[i]));
    return 0;
}
