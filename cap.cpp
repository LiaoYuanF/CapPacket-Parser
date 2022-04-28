#include <iostream>
#include <stdio.h>
#include <fstream>
#include <assert.h>
#include <queue>
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#pragma warning( disable : 4996)
using namespace std;

typedef unsigned int  bpf_u_int32;
typedef unsigned short  u_short;
typedef int bpf_int32;

typedef struct pcap_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;
	bpf_u_int32 sigfigs;
	bpf_u_int32 snaplen;
	bpf_u_int32 linktype;
}pcap_file_header;
void prinfPcapFileHeader(pcap_file_header *pfh) {
	if (pfh == NULL) {
		return;
	}
	printf("=====================\n"
		"magic:0x%0x\n"
		"version_major:%u\n"
		"version_minor:%u\n"
		"thiszone:%d\n"
		"sigfigs:%u\n"
		"snaplen:%u\n"
		"linktype:%u\n"
		"=====================\n",
		pfh->magic,
		pfh->version_major,
		pfh->version_minor,
		pfh->thiszone,
		pfh->sigfigs,
		pfh->snaplen,
		pfh->linktype);
}
typedef struct timestamp {
	bpf_u_int32 timestamp_s;
	bpf_u_int32 timestamp_ms;
}timestamp;
typedef struct pcap_header {
	timestamp ts;
	bpf_u_int32 capture_len;
	bpf_u_int32 len;

}pcap_header;
void printfPcapHeader(pcap_header *ph) {
	if (ph == NULL) {
		return;
	}
	printf("=====================\n"
		"ts.timestamp_s:%u\n"
		"ts.timestamp_ms:%u\n"
		"capture_len:%u\n"
		"len:%d\n"
		"=====================\n",
		ph->ts.timestamp_s,
		ph->ts.timestamp_ms,
		ph->capture_len,
		ph->len);
}
typedef struct MAC {
	unsigned char DST1;
	unsigned char DST2;
	unsigned char DST3;
	unsigned char DST4;
	unsigned char DST5;
	unsigned char DST6;
}MAC;
void printMAC(MAC *mac) {
	if (mac == NULL) {
		return;
	}
	printf("\n==%02x:%02x:%02x:%02x:%02x:%02x", mac->DST1, mac->DST2, mac->DST3, mac->DST4, mac->DST5, mac->DST6);
}
typedef struct ether_type {
	unsigned short tp;
}ether_type;
int print_ether_type(ether_type *ether_type) {
	if (ether_type == NULL) {
		return -1;
	}
	printf("\nether_type:%04x", ntohs(ether_type->tp));
	switch (ntohs(ether_type->tp)) {
	case 0x0800://ipv4
		printf(",IPv4");
		return 1;
		break;
	case 0x8086://arp
		printf(",ARP");
		return 2;
		break;
	case 0x8035://darp
		printf(",DARP");
		return 3;
		break;
	case 0x86DD://ipv6
		printf(",IPv6");
		return 4;
		break;
	default://else
		printf(",UNKNOWN");
		return 0;
	}
}
typedef struct IP {
	unsigned char DST1;
	unsigned char DST2;
	unsigned char DST3;
	unsigned char DST4;
}IP;
typedef struct ip_header {
	int version;
	int IP_len;
	//跳过服务类型域
	unsigned short Total_length;
	//跳过identification
	bool DF;
	bool MF;
	int offset;
	unsigned char TTL;
	unsigned char protocol;
	unsigned short Header_checksum;
	IP srcip;
	IP dstip;
}ip_header;
typedef struct tcp_header {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int seq_num;
	unsigned int ack_num;
	int tcp_len;
	bool flag[6];
	unsigned short win_size;
	unsigned short check_sum;
	unsigned short urgent_pointer;
}tcp_header;
typedef struct udp_header {
	unsigned short src_port;
	unsigned short dst_port;
	unsigned short udp_len;
	unsigned short check_sum;
}udp_header;
typedef struct summary {
	int type;
	int len;
	unsigned short inport;
	unsigned short outport;
		int inout;
}summary;
void printPcap(void * data, size_t size) {
	unsigned  short iPos = 0;
	//int * p = (int *)data;
	//unsigned short* p = (unsigned short *)data;
	if (data == NULL) {
		return;
	}
	printf("\n==data:0x%x,len:%lu=========", data, size);

	for (iPos = 0; iPos < size / sizeof(unsigned short); iPos++) {
		//printf(" %x ",(int)( * (p+iPos) ));
		//unsigned short a = ntohs(p[iPos]);

		unsigned short a = ntohs(*((unsigned short *)data + iPos));
		if (iPos % 8 == 0) printf("\n");
		if (iPos % 4 == 0) printf(" ");
		printf("%04x", a);
	}
	/*
	for (iPos=0; iPos <= size/sizeof(int); iPos++) {
	//printf(" %x ",(int)( * (p+iPos) ));
	int a = ntohl(p[iPos]);
	//int a = ntohl( *((int *)data + iPos ) );
	if (iPos %4==0) printf("\n");
	printf("%08x ",a);
	}
	*/
	printf("\n============\n");
}

IP thisip{ 192,168,1,111 };

int main() {
	char pfh = '~';
	FILE *fp = fopen("testcap.cap","rb");
	if (fp == NULL) {
		printf("open file error.");
		exit(0);
	}
	/*int i = 0;
	fread(&pfh, sizeof(char), 1, fp);
	while (!feof(fp)) {
		cout << char(pfh);
		i++;
		read:fread(&pfh, sizeof(char), 1, fp);
		if (!(pfh>=48 && pfh<=57 || pfh>=97&&pfh<=102))
			goto read;
	}
	cout << i;
	*/
	pcap_file_header fph;
	fread(&fph, sizeof(pcap_file_header), 1, fp);
	prinfPcapFileHeader(&fph);
	//for count
	int tcppacketnum = 0;
	int udppacketnum = 0;
	int other = 0;
	long long int tcpdatanum = 0;
	long long int udpdatanum = 0;
	int tcpcontrol[6] = {0,0,0,0,0,0};	
	queue<summary>SUM;
	int tcpfragment = 0;
	int udpfragment = 0;
	int tcpisdevided = 0;
	int udpisdevided = 0;
	//
	int count = 0, readSize = 0;
	void* buff = NULL;
	pcap_header PH;
	buff = (void *)malloc(1514);
	for (count = 1; ; count++) {
		memset(buff, 0, 1514);
		//read pcap header to get a packet
		//get only a pcap head count .
		readSize = fread(&PH, sizeof(pcap_header), 1, fp);
		if (readSize <= 0)
			break;
		printfPcapHeader(&PH);
		if (buff == NULL) {
			fprintf(stderr, "malloc memory failed.\n");
			exit(0);
		}
		//get a packet contents.
		//read ph.capture_len bytes.
		readSize = fread(buff, 1,PH.capture_len, fp);
		if (readSize != PH.capture_len) {
			free(buff);
			fprintf(stderr, "pcap file parse error.\n");
			exit(0);
		}
		printPcap(buff, PH.capture_len);
		byte* pbuf = (byte*)buff;
		//读取以太网段
		MAC dstmac;
		memcpy(&dstmac, pbuf, sizeof(dstmac));
		pbuf += sizeof(dstmac);
		printMAC(&dstmac);

		MAC srcmac;
		memcpy(&srcmac, pbuf, sizeof(srcmac));
		pbuf += sizeof(srcmac);
		printMAC(&srcmac);

		ether_type Ether_type;
		memcpy(&Ether_type, pbuf, sizeof(Ether_type));
		pbuf += sizeof(Ether_type);
		print_ether_type(&Ether_type);
		//读取IP段，先确定ip头长度
		ip_header iphead;
		unsigned char V_I;
		memcpy(&V_I, pbuf, sizeof(V_I));
		pbuf += sizeof(V_I);
		pbuf += sizeof(V_I);//跳过t_o_s
		iphead.version = int((V_I & unsigned char(240))>>4);
		iphead.IP_len = int(V_I & unsigned char(15));

		memcpy(&iphead.Total_length, pbuf, sizeof(iphead.Total_length));
		iphead.Total_length = ntohs(iphead.Total_length);//大小端转换
		pbuf += sizeof(iphead.Total_length);
		pbuf += sizeof(iphead.Total_length);//跳过id
		unsigned short DMF;
		memcpy(&DMF, pbuf, sizeof(DMF));//2字节
		pbuf += sizeof(DMF);
		DMF = ntohs(DMF);
		iphead.DF = bool((DMF & unsigned short(16384)));
		iphead.MF = bool((DMF & unsigned short(8192)));
		iphead.offset = int((DMF & unsigned short(8191)));
		
		memcpy(&iphead.TTL, pbuf, sizeof(iphead.TTL));//1字节
		pbuf += sizeof(iphead.TTL);

		memcpy(&iphead.protocol, pbuf, sizeof(iphead.protocol));//1字节
		pbuf += sizeof(iphead.protocol);
		memcpy(&iphead.Header_checksum, pbuf, sizeof(iphead.Header_checksum));//2字节
		iphead.Header_checksum = ntohs(iphead.Header_checksum);
		pbuf += sizeof(iphead.Header_checksum);

		memcpy(&iphead.srcip, pbuf, sizeof(iphead.srcip));//4字节
		pbuf += sizeof(iphead.srcip);
		memcpy(&iphead.dstip, pbuf, sizeof(iphead.dstip));//4字节
		pbuf += sizeof(iphead.dstip);
		pbuf += (iphead.IP_len-5)*sizeof(int);
		//IP头读取结束
		tcp_header th;
		udp_header uh;
		int istcp = 0, isudp = 0;
		if (int(iphead.protocol) == 6) {//如果是TCP
			tcppacketnum++;
			istcp = 1;
			if (iphead.offset != 0 || iphead.MF==true)
				tcpfragment++;
			if (iphead.offset != 0 && iphead.MF == false)
				tcpisdevided++;
			memcpy(&th.src_port, pbuf, sizeof(th.src_port));//2字节
			th.src_port = ntohs(th.src_port);
			pbuf += sizeof(th.src_port);
			memcpy(&th.dst_port, pbuf, sizeof(th.dst_port));//2字节
			th.dst_port = ntohs(th.dst_port);
			pbuf += sizeof(th.dst_port);
			memcpy(&th.seq_num, pbuf, sizeof(th.seq_num));//4字节
			th.seq_num = ntohs(th.seq_num);
			pbuf += sizeof(th.seq_num);
			memcpy(&th.ack_num, pbuf, sizeof(th.ack_num));//4字节
			th.ack_num = ntohs(th.ack_num);
			pbuf += sizeof(th.ack_num);
			unsigned short tmp;
			memcpy(&tmp, pbuf, sizeof(tmp));//4bit
			tmp = ntohs(tmp);
			pbuf += sizeof(tmp);
			th.tcp_len = int((tmp & unsigned short(61440)) >> 12);
			th.flag[0] = bool((tmp & unsigned short(32)));
			th.flag[1] = bool((tmp & unsigned short(16)));
			th.flag[2] = bool((tmp & unsigned short(8)));
			th.flag[3] = bool((tmp & unsigned short(4)));
			th.flag[4] = bool((tmp & unsigned short(2)));
			th.flag[5] = bool((tmp & unsigned short(1)));
			for (int i = 0;i < 6;i++) {
				if (th.flag[i] == true)
					tcpcontrol[i]++;
			}
			memcpy(&th.win_size, pbuf, sizeof(th.win_size));//4字节
			th.win_size = ntohs(th.win_size);
			pbuf += sizeof(th.win_size);
			memcpy(&th.check_sum, pbuf, sizeof(th.check_sum));//4字节
			th.check_sum = ntohs(th.check_sum);
			pbuf += sizeof(th.check_sum);
			memcpy(&th.urgent_pointer, pbuf, sizeof(th.urgent_pointer));//4字节
			th.urgent_pointer = ntohs(th.urgent_pointer);
			pbuf += sizeof(th.urgent_pointer);
			pbuf += (th.tcp_len - 5) * sizeof(int);
			tcpdatanum += (PH.len - 4 * th.tcp_len);
			int tmpint;
			if (thisip.DST1 == iphead.srcip.DST1&&thisip.DST2 == iphead.srcip.DST2&&thisip.DST3 == iphead.srcip.DST3&&thisip.DST4 == iphead.srcip.DST4)
				tmpint = 1;
			else if (thisip.DST1 == iphead.dstip.DST1&&thisip.DST2 == iphead.dstip.DST2&&thisip.DST3 == iphead.dstip.DST3&&thisip.DST4 == iphead.dstip.DST4)
				tmpint = 2;
			else
				tmpint = 0;
			SUM.push(summary{1,iphead.Total_length,th.dst_port,th.src_port,tmpint });
		}
		else if (int(iphead.protocol) == 17) {//如果是UDP
			isudp = 1;
			udppacketnum++;
			if (iphead.offset != 0 || iphead.MF == true)
				udpfragment++;
			if (iphead.offset != 0 && iphead.MF == false)
				udpisdevided++;
			memcpy(&uh.src_port, pbuf, sizeof(uh.src_port));//2字节
			uh.src_port = ntohs(uh.src_port);
			pbuf += sizeof(uh.src_port);
			memcpy(&uh.dst_port, pbuf, sizeof(uh.dst_port));//2字节
			uh.dst_port = ntohs(uh.dst_port);
			pbuf += sizeof(uh.dst_port);
			memcpy(&uh.udp_len, pbuf, sizeof(uh.udp_len));//2字节
			uh.udp_len = ntohs(uh.udp_len);
			pbuf += sizeof(uh.udp_len);
			memcpy(&uh.check_sum, pbuf, sizeof(uh.check_sum));//2字节
			uh.check_sum = ntohs(uh.check_sum);
			pbuf += sizeof(uh.check_sum);
			udpdatanum += (uh.udp_len - 8);
			
			int tmpint;
			if (thisip.DST1 == iphead.srcip.DST1&&thisip.DST2 == iphead.srcip.DST2&&thisip.DST3 == iphead.srcip.DST3&&thisip.DST4 == iphead.srcip.DST4)
				tmpint = 1;
			else if (thisip.DST1 == iphead.dstip.DST1&&thisip.DST2 == iphead.dstip.DST2&&thisip.DST3 == iphead.dstip.DST3&&thisip.DST4 == iphead.dstip.DST4)
				tmpint = 2;
			else
				tmpint = 0;
			SUM.push(summary{ 2,iphead.Total_length,uh.dst_port,uh.src_port ,tmpint});
		}
		else
			other++;
		//解析包完成。下面对包进行统计

		printf("\n===count:%d,readSize:%d===\n", count, readSize);
		if (feof(fp) || readSize <= 0) {
			break;
		}
	}
	//下面是统计，读者可自行编写
	/*
	cout <<"tcppacketnum:"<< tcppacketnum << "\n" <<"udppacketnum:"<< udppacketnum << endl;
	cout << "tcpdatanum:" << tcpdatanum << "\n" << "udpdatanum:" << udpdatanum << endl;
	cout << "有 " << tcpfragment+udpfragment<<" 个分组是片段" <<",其中TCP有"<<tcpfragment<<"个，UDP有"<<udpfragment<<"个"<< endl;
	cout << "有 " << tcpisdevided + udpisdevided << " 个数据报被分片" << ",其中TCP有" << tcpisdevided << "个，UDP有" << udpisdevided << "个" << endl;
	cout << "在"<<count-1<<"个分组中，各flag出现数量如下："<< endl;
	for (int i = 0;i < 6;i++) {
		cout <<"第"<< i << "个flag:" << tcpcontrol[i]<<"次"<< endl;
	}
	summary S;
	ofstream Out;
	Out.open("tomatlab.txt", ios::out | ios::app);
	if (!Out.is_open())
		return 0;
	while (!SUM.empty()) {
		S = SUM.front();
		SUM.pop();
		Out<<S.type << "\t" << S.len << "\t" << S.inport <<"\t"<< S.outport <<"\t"<<S.inout<< "\n";
	}
	Out.close();*/
	fclose(fp);
}