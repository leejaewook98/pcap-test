#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#define BUFSIZE 1024

typedef struct EthernetHeader{
    unsigned char Src_Mac[6]; //signed = -128 ~ 127, unsigned = 0 ~ 255
    unsigned char Des_Mac[6];
    unsigned short Type;
}EthernetHeader;

typedef struct IPHeader{
    unsigned char Version : 4;
    unsigned char header_len : 4;
    unsigned char TOS;      //Type Of Service
    unsigned short TotalLen;
    unsigned short Identifi;
    unsigned int FO : 13;
    unsigned char TTL; //time to live
    unsigned char Protocal;
    unsigned short HeaderCheck;
    struct in_addr src_ip, des_ip;
    // inet_addr()함수 : Dotte-Decimal Notation 형식을 빅엔디안 32비트 값으로 변환
}IPHeader;

typedef struct TCPHeader{
    unsigned short Src_Port;
    unsigned short Dst_Port;
    unsigned int Seq_Num;
    unsigned int Aac_Num;
    unsigned char Offset : 4;
    unsigned char Reserved : 4;
    unsigned short Window;
    unsigned short Check;
    unsigned short UP;
}TCPHeader;

typedef struct Payloaddata
{
    unsigned short HTP[16];
}Payloaddata;

void usage()
{
    printf("Write Interface Name\n");
    printf("Sample : pcap_test ens33\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[])
{
    if (argc != 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[])
{
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZE, 1, 1000, errbuf);
    IPHeader *tlen;
    unsigned int lengh;

    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1; //exit(1);
    }

void PrintEthernet(const unsigned char *packet);
void PrintIP(const unsigned char *packet);
void PrintTCP(const unsigned char *packet);
void PrintPayload(const unsigned char *packet);

    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) // -1 || -2
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));

        PrintEthernet(packet);
        packet += 14;
        PrintIP(packet);
        tlen = (IPHeader *)packet;
        lengh = htons(tlen->TotalLen) - (unsigned short)(tlen->header_len)*4;
        packet +=(unsigned short)(tlen->header_len)*4;
        PrintTCP(packet);
        packet += (unsigned char)lengh;
        PrintPayload(packet);
        //printf("%u bytes captured\n", header->caplen);
    }
    pcap_close(pcap);
} //main end


void PrintEthernet(const unsigned char *packet)
{
    EthernetHeader *eh;
    eh = (EthernetHeader *)packet;
    printf("\n---------- Ethernet Header ---------\n");
    printf("Src Mac %02x:%02x:%02x:%02x:%02x:%02x \n",eh -> Src_Mac[0],eh -> Src_Mac[1],eh -> Src_Mac[2],eh -> Src_Mac[3],eh -> Src_Mac[4],eh -> Src_Mac[5]);
    printf("Dst Mac %02x:%02x:%02x:%02x:%02x:%02x \n",eh -> Des_Mac[0],eh -> Des_Mac[1],eh -> Des_Mac[2],eh -> Des_Mac[3],eh -> Des_Mac[4],eh -> Des_Mac[5]);
    printf("\n");
}

void PrintIP(const unsigned char *packet)
{
    IPHeader *ih;
    ih = (IPHeader *)packet;
    printf("---------- IP Header ----------\n");
    if (ih -> Protocal == 0x06) //printf ("TCP\n");
    printf("Source IP  : %s\n", inet_ntoa(ih->src_ip) );
    //inet_ntoa() 함수 : 네트워크 바이트 순서의 32비트 값을 Dotted-Decimal Notation으로 변환시켜주는 함수
    printf("Destiation IP  : %s\n", inet_ntoa(ih->des_ip) );
    printf("\n");
}

void PrintTCP(const unsigned char *packet)
{
    TCPHeader *th;
    th = (TCPHeader *)packet;
    printf("---------- TCP Header ========\n");
    printf("Src Port : %d\n", ntohs(th->Src_Port)); // ntohs : 3412 -> 1234
    printf("Dst Port : %d\n", ntohs(th->Dst_Port));
    printf("\n");
}

void PrintPayload(const unsigned char *packet)
{
    Payloaddata *pd;
    pd = (Payloaddata *)packet;
    printf("---------- Payload data ----------\n");
    for(int i =0; i<16; i++)
    {
        printf("%02x ",pd -> HTP[i]);
    }
    printf("\n");
}

