#include<stdio.h>  
#include<stdlib.h>  
#include<signal.h>  
#include<unistd.h>  
#include<netinet/ip_icmp.h>  
#include<netdb.h>  
#include<string.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<sys/time.h>  
#include<netinet/in.h>  
#include<arpa/inet.h>  
#include<pthread.h>  
  
struct sockaddr_in dst_addr;  //目的端标识，套接字地址结构
struct sockaddr_in recv_addr;  
struct timeval tvrecv;  //收到数据报的时间
char icmp_pkt[1024] = {0};  //请求报文
char recv_pkt[1024] = {0};  //应答报文
int sockfd = 0, bytes = 56, nsend_pkt = 0, nrecv_pkt = 0;  //发送和接收报文的个数
pid_t pid; //进程ID 
  
void statistics();  
int in_chksum(unsigned short *buf, int size);  
int pack(int send_pkt);  
void *send_ping();  
int unpack(char *recv_pkt, int size);  
void *recv_ping();  
void tv_sub(struct timeval *out,struct timeval *in);  
  
int main(int argc, char **argv)  
{  
    int size = 50 * 1024;  //接收缓冲区的字节长度
    int errno = -1;  
    int ttl = 64;  //数据报生存周期
    void *tret;  
    pthread_t send_id,recv_id;  //线程ID
    struct in_addr ipv4_addr;  //IPv4地址，sockaddr_in中的一部分
    struct hostent *ipv4_host;  
    struct protoent *protocol = NULL;  //协议信息
// struct protoent {
//        char  *p_name;       /* official protocol name */
//        char **p_aliases;    /* alias list */
//        int    p_proto;      /* protocol number */
// }

  
    if (argc < 2)  //必须有一个参数，表示目的主机地址
    {  
        printf("usage: ./ping <host>\n");  
        return -1;  
    }  
    if ((protocol = getprotobyname("icmp")) == NULL) //返回对于给定协议名的相关协议信息;检查是否有协议相关信息 
    {  
        printf("unkown protocol\n");  
        return -1;  
    }  
  
    if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)  //创建一个套接字：IPv4,IP协议的数据报接口，协议名
    {  
        printf("socket fail\n");  
        return -1;  
    }  
    //setsockopt为套接字选项接口，用于控制套接字行为。
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));  //选项是通用的套接字层次选项，选项为：接收缓冲区的字节长度
    setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));  //IP是控制这个选项的协议，设置组播
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));  //IP，设置主机发送数据报的生存时间
/*type = struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
    unsigned char sin_zero[8];
}*/
    memset(&dst_addr, 0, sizeof(dst_addr));  
    dst_addr.sin_family = AF_INET; 
    errno = inet_aton(argv[1], &ipv4_addr);  //将Internet主机地址，从点分十进制转化为二进制格式（网络字节序）
    if (errno == 0)  //地址无效
    {  
        ipv4_host = gethostbyname(argv[1]);  //通过主机名得到地址
        if (NULL == ipv4_host)  
        {  
            printf("connect: Invalid argument\n");  
            return -1;  
        }  
        memcpy(&(dst_addr.sin_addr), ipv4_host->h_addr, sizeof(struct in_addr));  
    }  
    else  
    {  
        memcpy(&(dst_addr.sin_addr), &(ipv4_addr.s_addr), sizeof(struct in_addr));  
    }  
  
    pid = getpid();  //得到进程ID
    printf("PING %s (%s) %d bytes of data.\n",argv[1], inet_ntoa(dst_addr.sin_addr), bytes);  
    signal(SIGINT, statistics);  //当用户按中断键时产生此信号， 注册信号处理程序。
      
    errno = pthread_create(&send_id, NULL, send_ping, NULL);  
    if (errno != 0)  
    {  
        printf("send_ping thread fail\n");  
        return -1;  
    }  
    errno = pthread_create(&recv_id, NULL, recv_ping, NULL);  
    if (errno != 0)  
    {  
        printf("recv_ping thread fail\n");  
        return -1;  
    }  
    pthread_join(send_id, &tret);  
    pthread_join(recv_id, &tret);  
  
    return 0;  
}  
  
void statistics() //统计发送和接收数据报的书目，计算丢包率。（若一次发送数据报没有得到回应，则代表丢包） 
{  
    printf("\n--- %s ping statistics ---\n", inet_ntoa(dst_addr.sin_addr));  
    printf("%d packets transmitted, %d received, %.3f%c packet loss\n",  
        nsend_pkt, nrecv_pkt, (float)100*(nsend_pkt - nrecv_pkt)/nsend_pkt, '%');  
    close(sockfd);  
  
    exit(0);  
}  
  
int in_chksum(unsigned short *buf, int size)  
{  
    int nleft = size;  
    int sum = 0;  
    unsigned short *w = buf;  
    unsigned short ans = 0;  
  
    while(nleft > 1)  
    {  
        sum += *w++;  
        nleft -= 2;  
    }  
    if (nleft == 1)  
    {  
        *(unsigned char *) (&ans) = *(unsigned char *)w;  
        sum += ans;  
    }  
    sum = (sum >> 16) + (sum & 0xFFFF);  
    sum += (sum >> 16);  
    ans = ~sum;  
    return ans;  
}  
  
int pack(int send_pkt)  //构建ICMP报文
{  
    struct icmp *pkt = (struct icmp *)icmp_pkt; //ICMP报文结构体 
    struct timeval *time = NULL;  
/* type = struct icmp { 
    u_int8_t icmp_type; 8位类型
    u_int8_t icmp_code; 8位代码
    u_int16_t icmp_cksum; 16位校验和
    union { //不同类型和代码有不同的内容
        u_char ih_pptr;
        struct in_addr ih_gwaddr;
        struct ih_idseq ih_idseq;
        u_int32_t ih_void;
        struct ih_pmtu ih_pmtu;
        struct ih_rtradv ih_rtradv;
    } icmp_hun;
    union {
        struct {...} id_ts;
        struct {...} id_ip;
        struct icmp_ra_addr id_radv;
        u_int32_t id_mask;
        u_int8_t id_data[1];
    } icmp_dun;
}*/ 
    pkt->icmp_type = ICMP_ECHO;  //类型
    pkt->icmp_cksum = 0;  //校验和
    pkt->icmp_seq = htons(nsend_pkt); //序号  
    pkt->icmp_id = pid;  //标识符字段：置成发送进程的ID号
    time = (struct timeval *)pkt->icmp_data;  
    gettimeofday(time, NULL);  
    pkt->icmp_cksum = in_chksum((unsigned short *)pkt, bytes + 8);  
  
    return bytes + 8;  
}  
  
void *send_ping()  
{  
    int send_bytes = 0;  
    int ret = -1;  
  
    while(1)  
    {  
        nsend_pkt++;  
        send_bytes = pack(nsend_pkt);  
  
        ret = sendto(sockfd, icmp_pkt, send_bytes, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));  //发送报文
        if (ret == -1)  
        {  
            printf("send fail\n");  
            sleep(1);  
            continue;  
        }  
        sleep(1);  
    }  
}  
  
void tv_sub(struct timeval *out,struct timeval *in)  
{  
    if ((out->tv_usec-=in->tv_usec) < 0)  
    {  
        --out->tv_sec;  
        out->tv_usec += 1000000;  
    }  
  
    out->tv_sec -= in->tv_sec;  
}  
  
int unpack(char *recv_pkt, int size)  
{  
    struct iphdr *ip = NULL;  
    int iphdrlen;  
    struct icmp *icmp;  
    struct timeval *tvsend;  
    double rtt;  //往返时间
  
    ip = (struct iphdr *)recv_pkt;  
    iphdrlen = ip->ihl<<2;  
    icmp = (struct icmp *)(recv_pkt + iphdrlen);  
  
    size -= iphdrlen;  
    if (size < 8)  
    {  
        printf("ICMP size is less than 8\n");  
        return -1;  
    }  
  
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid))  
    {  
        tvsend = (struct timeval *)icmp->icmp_data;  
        tv_sub(&tvrecv, tvsend);  
        rtt = tvrecv.tv_sec * 1000 + (double)tvrecv.tv_usec / (double)1000;  
        printf("%d byte from %s: icmp_seq = %d ttl=%d rtt=%.3fms\n",  
            size,inet_ntoa(recv_addr.sin_addr),ntohs(icmp->icmp_seq), ip->ttl, rtt);  
    }  
    else  
    {  
        return -1;  
    }  
    return 0;  
}  
  
void *recv_ping()  
{  
    fd_set rd_set;  //一个很大的字节数组，每一个可能的描述符保持1位
    struct timeval time;  //I/O多路转接需要等待的时间长度
    time.tv_sec = 5;  
    time.tv_usec = 0;  
    int ret = 0, nread = 0,recv_len = 0;  
      
    recv_len = sizeof(recv_addr);  
    while(1)  
    {  
        FD_ZERO(&rd_set);  //所有位设置为0
        FD_SET(sockfd, &rd_set);  //开启描述符中的一位，sockfd
        ret = select(sockfd + 1, &rd_set, NULL, NULL, &time);  
	//执行I/O多路转接。time:愿意等待的时间长度。rd_set指向读描述符集的指针。第一个参数：最大文件描述符编号值加1
        if (ret <= 0)  //等待超时或出错
        {  
            continue;  
        }  
        else if (FD_ISSET(sockfd, &rd_set))  //测试描述符集中的sockfd位是否仍处于打开状态
        {  
            nread = recvfrom(sockfd, recv_pkt, sizeof(recv_pkt), 0, (struct sockaddr *)&recv_addr,(socklen_t *) &recv_len);  
            if (nread < 0)  
            {  
                continue;  
            }  
            gettimeofday(&tvrecv, NULL);  
  
            if (unpack(recv_pkt, nread) == -1)  
            {  
                continue;  
            }  
            nrecv_pkt++;  
        }  
    }  
}  
