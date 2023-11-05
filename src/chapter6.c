#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#define INET6_ADDRSTRLEN    45

typedef struct
{
    WINDIVERT_IPHDR ip;
    WINDIVERT_TCPHDR tcp;
} TCPPACKET, *POINTERTCPPACKET;
static int IsRuleMatch(unsigned char*, UINT, HANDLE);

int __cdecl main(int argc, char **argv)
{
    HANDLE handle, console;
    unsigned char packet[WINDIVERT_MTU_MAX];
    UINT packet_len;
    UINT payload_len;
    WINDIVERT_ADDRESS recv_addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_TCPHDR tcp_header;
    char src_str[INET6_ADDRSTRLEN+1], dst_str[INET6_ADDRSTRLEN+1];

    // コンソールハンドル取得
    console = GetStdHandle(STD_OUTPUT_HANDLE);
    // WinDivertハンドルをオープン
    handle = WinDivertOpen(
        "tcp.SrcPort == 80",
        WINDIVERT_LAYER_NETWORK, 
        0, 
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_FRAGMENTS);
    if (handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, 
                "エラー: WinDivertデバイスが開けませんでした (コード：%d)\n",
                GetLastError());
        exit(EXIT_FAILURE);
    }
    // メインループ
    while (TRUE)
    {
        // パケットの受信
        if (!WinDivertRecv(handle, packet, 
                            sizeof(packet), &packet_len, &recv_addr))
        {
            fprintf(stderr, "パケットの読み込みに失敗しました\n");
            continue;
        }
        // 各種パケットヘッダーにパースする
        WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,
            NULL, NULL, NULL, &tcp_header, NULL, NULL,
            &payload_len, NULL, NULL);

        if (ip_header != NULL)
        {
            WinDivertHelperFormatIPv4Address(
                WinDivertHelperNtohl(ip_header->SrcAddr),
                src_str, sizeof(src_str));
            WinDivertHelperFormatIPv4Address(
                WinDivertHelperNtohl(ip_header->DstAddr),
                dst_str, sizeof(dst_str));
            SetConsoleTextAttribute(console,
                FOREGROUND_GREEN | FOREGROUND_RED);
            printf("IPv4 [Version=%u HdrLength=%u TOS=%u Length=%u Id=0x%.4X "
                "Reserved=%u DF=%u MF=%u FragOff=%u TTL=%u Protocol=%u "
                "Checksum=0x%.4X 送信元IPアドレス=%s 宛先IPアドレス=%s]\n",
                ip_header->Version, ip_header->HdrLength,
                WinDivertHelperNtohs(ip_header->TOS), 
                WinDivertHelperNtohs(ip_header->Length),
                WinDivertHelperNtohs(ip_header->Id), 
                WINDIVERT_IPHDR_GET_RESERVED(ip_header),
                WINDIVERT_IPHDR_GET_DF(ip_header),
                WINDIVERT_IPHDR_GET_MF(ip_header),
                WinDivertHelperNtohs(WINDIVERT_IPHDR_GET_FRAGOFF(ip_header)), 
                ip_header->TTL,
                ip_header->Protocol, 
                WinDivertHelperNtohs(ip_header->Checksum), 
                src_str, dst_str);
        }
        if (tcp_header != NULL)
        {
            SetConsoleTextAttribute(console, FOREGROUND_GREEN);
            printf("TCP [送信元ポート=%u 宛先ポート=%u SeqNum=%u AckNum=%u "
                "HdrLength=%u Reserved1=%u Reserved2=%u Urg=%u Ack=%u "
                "Psh=%u Rst=%u Syn=%u Fin=%u Window=%u Checksum=0x%.4X "
                "UrgPtr=%u]\n",
                WinDivertHelperNtohs(tcp_header->SrcPort), 
                WinDivertHelperNtohs(tcp_header->DstPort),
                WinDivertHelperNtohl(tcp_header->SeqNum), 
                WinDivertHelperNtohl(tcp_header->AckNum),
                tcp_header->HdrLength, tcp_header->Reserved1,
                tcp_header->Reserved2, tcp_header->Urg, tcp_header->Ack,
                tcp_header->Psh, tcp_header->Rst, tcp_header->Syn,
                tcp_header->Fin, 
                WinDivertHelperNtohs(tcp_header->Window),
                WinDivertHelperNtohs(tcp_header->Checksum), 
                WinDivertHelperNtohs(tcp_header->UrgPtr));
            
            //パケットがルールと一致するか確認
            IsRuleMatch(packet,packet_len,console);

            //パケットの中身を表示する
            for (int i = 0; i < packet_len; i++)
            {
                if (i % 40 == 0)
                {
                    printf("\n\t");
                }
                if (isprint(packet[i]))
                {
                    putchar(packet[i]);
                }
                else
                {
                    putchar('.');
                }
            }
            printf("\n");
        }
    }
}

/*
    * IsRuleMatch : ルールにマッチするか
    * 
    */

static int IsRuleMatch(unsigned char *packet, UINT packet_len, HANDLE console){
    char *rules = "uid=0(root)";
    for (int i = 0; i < packet_len; i++){
        if(packet[i] == rules[0]){
            for(int i2 = 0; i2 < strlen(rules) && i+i2 < packet_len; i2++){
                if(packet[i + i2] != rules[i2]){
                    break;
                }
                if(i2 == strlen(rules) - 1){
                    SetConsoleTextAttribute(console, FOREGROUND_RED);
                    printf("アラート：ルールと一致しました！\n");
                    return 1;
                }
            }
        }
    }
    return 0;
}