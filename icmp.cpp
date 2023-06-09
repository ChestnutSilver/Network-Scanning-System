#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <QString>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <iostream>
#include <string>

using namespace std;



int MainWindow::hostscan_icmp(QString s) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        cerr << "WSAStartup failed." << endl;
        return 1;
    }
    string baseIp = s.toStdString();
    //string baseIp = "129.211.214.";
    for (int i = 255; i >= 1; i--) {
        string ip = baseIp + to_string(i);
        cout << "Pinging " << ip << "..." << endl;

        HANDLE hIcmpFile = IcmpCreateFile();
        if (hIcmpFile == INVALID_HANDLE_VALUE) {
            cerr << "Unable to open handle." << endl;
            continue;
        }

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

        dwRetVal = IcmpSendEcho(hIcmpFile, inet_addr(ip.c_str()), SendData, sizeof(SendData),
            NULL, ReplyBuffer, ReplySize, 1000);
        if (dwRetVal != 0) {
            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)ReplyBuffer;
            struct in_addr ReplyAddr;
            ReplyAddr.S_un.S_addr = pEchoReply->Address;
            ui->textB_host->append(inet_ntoa(ReplyAddr));
            cout << "Received reply from " << inet_ntoa(ReplyAddr) << endl;
        }
        else {
            cerr << "Call to IcmpSendEcho failed." << endl;
        }

        free(ReplyBuffer);
        IcmpCloseHandle(hIcmpFile);
    }

    WSACleanup();
    return 0;
}
