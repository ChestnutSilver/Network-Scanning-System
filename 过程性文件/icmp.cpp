// 忽略安全警告
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// 引入需要的头文件
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <string>

using namespace std;

int main() {
    // 初始化 Winsock 库
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        cerr << "WSAStartup failed." << endl;
        return 1;
    }

    // 遍历所有 IP 地址
    string baseIp = "129.211.214.";
    for (int i = 1; i <= 255; i++) {
        string ip = baseIp + to_string(i);
        cout << "Pinging " << ip << "..." << endl;

        // 创建 ICMP 文件句柄
        HANDLE hIcmpFile = IcmpCreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE) {
            cerr << "Unable to open handle." << endl;
            continue;
        }

        // 构造 ICMP 请求报文
        DWORD dwRetVal = 0;
        char SendData[] = "Data Buffer";
        LPVOID ReplyBuffer = NULL;
        DWORD ReplySize = 0;

        ReplySize = sizeof(ICMP_ECHO_REPLY) + sizeof(SendData);
        ReplyBuffer = (VOID*)malloc(ReplySize);
        if (ReplyBuffer == NULL) {
            cerr << "Unable to allocate memory." << endl;
            continue;
        }

        // 发送 ICMP 请求报文并等待响应
        dwRetVal = IcmpSendEcho(hIcmpFile, inet_addr(ip.c_str()), SendData, sizeof(SendData),
            NULL, ReplyBuffer, ReplySize, 1000);
        if (dwRetVal != 0) {
            // 解析 ICMP 响应报文并显示结果
            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
            struct in_addr ReplyAddr;
            ReplyAddr.S_un.S_addr = pEchoReply->Address;
            cout << "Received reply from " << inet_ntoa(ReplyAddr) << endl;
        }
        else {
            cerr << "Call to IcmpSendEcho failed." << endl;
        }

        // 释放内存和文件句柄
        free(ReplyBuffer);
        IcmpCloseHandle(hIcmpFile);
    }

    // 清理 Winsock 库
    WSACleanup();
    return 0;
}

