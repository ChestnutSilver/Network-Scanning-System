#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

using namespace std::chrono_literals;

constexpr int THREAD_NUM = 10;  // 线程数
constexpr int PORT_BEGIN = 1;  // 扫描端口起始号
constexpr int PORT_END = 1000; // 扫描端口结束号

std::mutex s_mutex;  // 互斥锁，用于保护共享资源
std::atomic<int> s_port(PORT_BEGIN);  // 原子变量，用于记录要扫描的端口号

void scan_port(const std::string& ip)
{
    while (true)
    {
        int port = s_port++;  // 获取要扫描的端口号，原子操作
        if (port > PORT_END)  // 如果扫描的端口号已经超出了范围，结束循环
            break;

        sockaddr_in addr{};  // 创建一个sockaddr_in类型的变量，表示要连接的地址
        addr.sin_family = AF_INET;  // 设置地址类型为IPv4
        addr.sin_port = htons(port);  // 设置端口号
        addr.sin_addr.s_addr = inet_addr(ip.c_str());  // 设置IP地址

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);  // 创建TCP套接字
        if (s == INVALID_SOCKET)  // 如果创建套接字失败，继续尝试下一个端口
            continue;

        u_long mode = 1;
        if (ioctlsocket(s, FIONBIO, &mode) == SOCKET_ERROR)  // 设置套接字为非阻塞模式
        {
            closesocket(s);
            continue;
        }

        int result = connect(s, (sockaddr*)&addr, sizeof(addr));  // 连接到指定地址
        if (result == SOCKET_ERROR)  // 如果连接失败
        {
            int error = WSAGetLastError();  // 获取错误码
            if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS)  // 如果错误码不是"正在进行中"或"操作将会被阻塞"
            {
                closesocket(s);  // 关闭套接字，继续尝试下一个端口
                continue;
            }
        }
        else if (result == 0)  // 如果连接成功
        {
            std::lock_guard<std::mutex> lock(s_mutex);  // 加锁，保护共享资源
            std::cout << "Port " << port << " is open." << std::endl;  // 输出扫描结果
        }

        fd_set writefds{};  // 创建一个文件描述符集合，用于等待套接字可写事件
        FD_ZERO(&writefds);
        FD_SET(s, &writefds);

        timeval timeout{};  // 设置超时时间
        timeout.tv_sec = 1;  // 超时时间为1秒
        timeout.tv_usec = 0;

        result = select(0, nullptr, &writefds, nullptr, &timeout);  // 等待套接字可写事件
        if (result == SOCKET_ERROR)  // 如果出现错误
        {
            closesocket(s);  // 关闭套接字，继续尝试下一个端口
            continue;
        }
        else if (result == 0)  // 如果超时
        {
            closesocket(s);  // 关闭套接字，继续尝试下一个端口
            continue;
        }

        std::lock_guard<std::mutex> lock(s_mutex);  // 加锁，保护共享资源
        std::cout << "Port " << port << " is open." << std::endl;  // 输出扫描结果
        closesocket(s);  // 关闭套接字
    }
}

int main()
{
    WSADATA wsaData{};  // 初始化Winsock库
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0)  // 如果初始化失败，输出错误信息
    {
        std::cerr << "WSAStartup failed with error: " << err << std::endl;
        return -1;
    }

    std::string ip = "127.0.0.1";  // 要扫描的主机IP

    std::thread threads[THREAD_NUM];  // 创建多个线程
    for (int i = 0; i < THREAD_NUM; ++i)
    {
        threads[i] = std::thread(scan_port, ip);  // 每个线程调用scan_port函数进行扫描
    }

    for (int i = 0; i < THREAD_NUM; ++i)
    {
        threads[i].join();  // 等待所有线程结束
    }

    WSACleanup();  // 关闭Winsock库

    return 0;
}

