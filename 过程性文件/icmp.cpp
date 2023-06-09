// ���԰�ȫ����
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// ������Ҫ��ͷ�ļ�
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <string>

using namespace std;

int main() {
    // ��ʼ�� Winsock ��
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        cerr << "WSAStartup failed." << endl;
        return 1;
    }

    // �������� IP ��ַ
    string baseIp = "129.211.214.";
    for (int i = 1; i <= 255; i++) {
        string ip = baseIp + to_string(i);
        cout << "Pinging " << ip << "..." << endl;

        // ���� ICMP �ļ����
        HANDLE hIcmpFile = IcmpCreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE) {
            cerr << "Unable to open handle." << endl;
            continue;
        }

        // ���� ICMP ������
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

        // ���� ICMP �����Ĳ��ȴ���Ӧ
        dwRetVal = IcmpSendEcho(hIcmpFile, inet_addr(ip.c_str()), SendData, sizeof(SendData),
            NULL, ReplyBuffer, ReplySize, 1000);
        if (dwRetVal != 0) {
            // ���� ICMP ��Ӧ���Ĳ���ʾ���
            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
            struct in_addr ReplyAddr;
            ReplyAddr.S_un.S_addr = pEchoReply->Address;
            cout << "Received reply from " << inet_ntoa(ReplyAddr) << endl;
        }
        else {
            cerr << "Call to IcmpSendEcho failed." << endl;
        }

        // �ͷ��ڴ���ļ����
        free(ReplyBuffer);
        IcmpCloseHandle(hIcmpFile);
    }

    // ���� Winsock ��
    WSACleanup();
    return 0;
}

