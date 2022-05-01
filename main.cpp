#include <pcap.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <ctype.h>
#include <iostream>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/**
 * 以太网头数据结构
 */
#define SIZE_ETHERNET 14                    // 以太网包头长度
#define ETHER_ADDR_LEN  6                   // mac地址长度
struct packet_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    //源地址
    u_char  ether_shost[ETHER_ADDR_LEN];    //目的地址
    u_short ether_type;                     //具体协议
};
/**
 * IP头数据结构
 */
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
struct packet_ip {
    u_char  ip_vhl;
    u_char  ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char  ip_ttl;
    u_char  ip_p;
    u_short ip_sum;
    struct  in_addr ip_src,ip_dst;
};
/**
 * TCP头数据结构
 */
struct packet_tcp {
    u_short th_sport;
    u_short th_dport;
    u_int th_seq;
    u_int th_ack;
    u_char th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};
/**
 * UDP头数据结构
 */
struct packet_udp {
    uint16_t sport;
    uint16_t dport;
    uint16_t udp_length;
    uint16_t udp_sum;
};

//打印以太网头信息
void print_ethernet(u_char * ptr){
    int macLength = ETHER_ADDR_LEN;
    do{
        printf ("%s%x", (macLength == ETHER_ADDR_LEN)?"":":", *ptr++);
    }while(--macLength>0);
    std::cout<<std::endl;
}

void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct packet_ethernet *ethernet;  // 以太网头
    const struct packet_ip *ip;              // IP头
    const struct packet_tcp *tcp;            // TCP头
    const struct packet_udp *udp;            // UDP头
    const char *payload;                     // 包体
    int size_ip;
    int size_tcp;

    /* 以太网头 */
    ethernet = (struct packet_ethernet*)(packet);
    std::cout<<"来源mac地址: "<<std::endl;
    print_ethernet((u_char *)(ethernet->ether_shost));
    std::cout<<"目的mac地址: "<<std::endl;
    print_ethernet((u_char *)(ethernet->ether_dhost));

    /* IP头 */
    ip = (struct packet_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("无效的IP头长度: %u bytes\n", size_ip);
        return;
    }

    int proto_flag;
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            /* TCP头 */
            std::cout<<"TCP协议报文"<< ip->ip_p<<std::endl;
            tcp = (struct packet_tcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp)*4;
            if (size_tcp < 20) {
                std::cout<<"无效的TCP头长度:"<< size_tcp <<"bytes"<<std::endl;
                return;
            }
            std::cout<<"序列号:"<< ntohs(tcp->th_seq)<<std::endl;
            std::cout<<"确认号:"<< ntohs(tcp->th_ack)<<std::endl;
            std::cout<<"来源IP:"<< inet_ntoa(ip->ip_src)<<" "<<"端口:"<<ntohs(tcp->th_sport)<<std::endl;
            std::cout<<"目的IP:"<< inet_ntoa(ip->ip_dst)<<" "<<"端口:"<<ntohs(tcp->th_dport)<<std::endl;
            return;
        case IPPROTO_UDP:
            /* UDP头 */
            std::cout<<"UDP协议报文"<< ip->ip_p<<std::endl;
            udp = (struct packet_udp *) (packet + SIZE_ETHERNET + size_ip);
            std::cout<<"来源IP:"<< inet_ntoa(ip->ip_src)<<" "<<"端口:"<<ntohs(udp->sport)<<std::endl;
            std::cout<<"目的IP:"<< inet_ntoa(ip->ip_dst)<<" "<<"端口:"<<ntohs(udp->dport)<<std::endl;
        default:
            std::cout<<"其他未设定解析逻辑的报文"<< ip->ip_p<<std::endl;
            return;
    }
}

int main() {
    pcap_t *handle;                 //会话句柄
    char error[100];                //错误信息字符串
    struct pcap_pkthdr pack;        //包参数
    const u_char *packet;           //实际的包
    struct pcap_pkthdr header;      //由pcap.h定义
    struct bpf_program filter;      //过滤器
    char filter_app[] = "";         //过滤表达式
    char file[]="nd_packet.cap";         //cap文件
    //打开文件
    if((handle=pcap_open_offline(file,error))== nullptr)
    {
        std::cout<<"error = "<<error<<std::endl;
        return(0);
    }
    //过滤文件，函数返回-1为失败
    pcap_compile(handle,&filter,filter_app,1,0);
    //解析文件，函数返回-1为失败
    if(pcap_setfilter(handle,&filter)==0)
    {
        pcap_loop(handle, -1, loop_callback, nullptr);
    }
    return(0);
}
