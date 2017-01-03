//============================================================================
// Name        : udp_send.cpp
// Email       : zhangpeng06@21vianet.com
// Version     : 1.0V
// Copyright   : Copyright 2010. 21Vianet Group, Inc. All Rights Reserved.
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h> 
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
//建华的dns解析库 lijianhua02@21vianet.com
#include "ldc_packet_mgr.h"

#define MAX_PAYLOAD  2048
#define MAX_IP_LEN   32
#define SRC_PORT     24417
#define DST_PORT     53

using namespace std;

uint16_t csum_udp(uint16_t *ptr,int nbytes);

uint16_t csum(uint16_t *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
            sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t udp_checksum(in_addr_t saddr, \
             in_addr_t daddr, \
             uint16_t *buffer, \
             int size)
{
    unsigned char rawBuf[1024];
    struct pseudo_hdr
    {
        struct in_addr  src;
        struct in_addr  dst;
        uint8_t         mbz;
        uint8_t         proto;
        uint16_t        len;
    } __attribute__((__packed__));

    uint16_t sum = 0;
    struct pseudo_hdr *ph;
    int ph_len = sizeof(struct pseudo_hdr);
    ph = (struct pseudo_hdr *)rawBuf;
    ph->src.s_addr = saddr;
    ph->dst.s_addr = daddr;
    ph->mbz = 0;
    ph->proto = IPPROTO_UDP;
    ph->len = htons(size); //这里的长度为udp header + payload 的总和
    //buffer = udpheader + payload,  size = sizeof(udpheader + payload)
    memcpy(rawBuf + ph_len, buffer, size);
    //ph_len + size 是虚假头长＋UDP长＋payload长来计算checksum
    sum = csum_udp((uint16_t *)rawBuf, ph_len + size);
    return sum;
}

uint16_t csum_udp(uint16_t *ptr,int nbytes)
{
    uint32_t sum;
    uint16_t oddbyte;
    uint16_t answer;

    sum=0;
    while(nbytes>1) 
    {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) 
    {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return answer;
}

int main(int argc, char *argv[])
{
    if(argc != 4)
    {
        printf("Please according to the following order: ip_src->ip_dst->domain");
        return false;
    }

    char packet[MAX_PAYLOAD] = {0};

    int socket_raw_fd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    const int ok = 1;
    setsockopt(socket_raw_fd, IPPROTO_IP, IP_HDRINCL, (char *)&ok, sizeof(ok));

    char ip_src[MAX_IP_LEN];
    char ip_dst[MAX_IP_LEN];
    strcpy(ip_src, argv[1]);
    strcpy(ip_dst, argv[2]);

    struct sockaddr_in src, din;

    uint16_t src_port = SRC_PORT;
    uint16_t dst_port = DST_PORT;

    uint32_t pack_size, tot_len;

    src.sin_family = AF_INET;
    src.sin_addr.s_addr = inet_addr(ip_src);
    src.sin_port = htons(src_port);

    din.sin_family = AF_INET;
    din.sin_addr.s_addr = inet_addr(ip_dst);
    din.sin_port = htons(dst_port);

    struct iphdr  *ip  = (struct iphdr*)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    pack_size = MAX_PAYLOAD - sizeof(struct iphdr) - sizeof(struct udphdr);

    //构造dns包
    ldc_packet_mgr dns;
    std::string type = "A";
    //char domain[] = "kwcdn.miaopai.com";
    char domain[255];
    strcpy(domain, argv[3]);

    char *udp_payload = (char *)udp + sizeof(struct udphdr);
    pack_size = dns.create_packet(udp_payload, pack_size, (char *)domain, 0, type);
    //打印构造的dns包的结果
    dns.parse_dns_packet((unsigned char *)(udp + sizeof(struct udphdr)), pack_size);
    printf("packet size %u\n", pack_size);

    ip->protocol = IPPROTO_UDP;
    ip->saddr = inet_addr(ip_src);
    ip->daddr = inet_addr(ip_dst);
    ip->ihl = 20/4;
    ip->version = 4;
    ip->tos = 16;

    tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + pack_size;
    ip->tot_len = htons(tot_len) ;
    ip->id = htons(54321);
    ip->ttl = 64;
    ip->check = csum((unsigned short *)packet, sizeof(struct iphdr));

    udp->source = htons(src_port);
    udp->dest = htons(dst_port);
    udp->len = htons(sizeof(struct udphdr) + pack_size);
    udp->check = 0;
    udp->check = udp_checksum(src.sin_addr.s_addr, din.sin_addr.s_addr, (uint16_t *)udp, tot_len - sizeof(struct iphdr));

    printf("tot_len %u\n", tot_len);
    dns.parse_dns_packet((unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr)), pack_size);

    //发送自己构造的dns格式,由于应用原始套接字，故需要在root权限下执行
    if(sendto(socket_raw_fd, (void *)packet, tot_len, 0, (struct sockaddr *)&din, (socklen_t)sizeof(din)) < 0)
    {
        perror("sendto() error,");
        exit(-1);
    }

    close(socket_raw_fd);

	return 0;
}
