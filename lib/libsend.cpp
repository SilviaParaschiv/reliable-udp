#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <cassert>
#include <poll.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <cstring>
#include <unistd.h>
#include <algorithm>
#include <vector>

using namespace std;

std::map<int, struct connection *> cons;

struct pollfd data_fds[MAX_CONNECTIONS];
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;
static int next_local_conn_id = 0;

enum
{
    TYPE_SYN = 1,
    TYPE_SYN_ACK = 2,
    TYPE_ACK = 3,
    TYPE_DATA = 4,
};

static const int MAX_RETRIES = 200;
static const int DATA_CHECKSUM_SIZE = sizeof(uint32_t);
static int link_speed = 0;
static int link_delay = 0;
static std::map<int, int> advertised_windows;

static uint32_t checksum(char *buffer, int len)
{
    uint32_t sum = 0;
    for (int i = 0; i < len; i++)
    {
        sum = sum * 31 + (uint8_t)buffer[i];
    }
    return sum;
}

static uint32_t segment_checksum(uint8_t conn_id, uint16_t seq, char *buffer, int len)
{
    uint32_t sum = checksum(buffer, len);
    sum = sum * 31 + conn_id;
    sum = sum * 31 + seq;
    sum = sum * 31 + (uint16_t)len;
    return sum;
}

static int compute_link_window_segmengts()
{
    int max_payload = MAX_DATA_SIZE - DATA_CHECKSUM_SIZE;
    int window_bytes = link_speed * link_delay * 125;

    int window_segments = window_bytes / max_payload;
    if (window_segments < 1)
        window_segments = 1;

    if (window_segments > 512)
        window_segments = 512;

    return window_segments;
}

static int effective_window(connection *con, int conn_id)
{
    auto it = advertised_windows.find(conn_id);
    if (it == advertised_windows.end())
        return con->max_window_seq;
    if (it->second > con->max_window_seq)
        return con->max_window_seq;
    return it->second;
}

static poli_tcp_data_hdr build_data_header(int conn_id, uint16_t seq, int payload_len)
{
    poli_tcp_data_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.protocol_id = POLI_PROTOCOL_ID;
    hdr.conn_id = (uint8_t)conn_id;
    hdr.type = TYPE_DATA;
    hdr.seq_num = htons(seq);
    hdr.len = htons((uint16_t)payload_len);
    return hdr;
}

int send_data(int conn_id, char *buffer, int len)
{
    if (len <= 0)
        return 0;

    pthread_mutex_lock(&cons[conn_id]->con_lock);

    connection *con = cons[conn_id];
    int max_payload = MAX_DATA_SIZE - DATA_CHECKSUM_SIZE;

    int needed_segments = len / max_payload;
    if (len % max_payload != 0)
        needed_segments++;

    int win = effective_window(con, conn_id);

    if ((int)con->send_window.size() + needed_segments > win)
    {
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
        return -1;
    }

    int sent_bytes = 0;
    while (sent_bytes < len)
    {
        int current_len = min(len - sent_bytes, max_payload);
        int packet_size = sizeof(poli_tcp_data_hdr) + DATA_CHECKSUM_SIZE + current_len;

        vector<char> packet(packet_size);

        poli_tcp_data_hdr hdr = build_data_header(conn_id, con->next_seq, current_len);
        uint32_t check = segment_checksum((uint8_t)conn_id, con->next_seq, buffer + sent_bytes, current_len);
        check = htonl(check);

        char *packet_ptr = packet.data();
        memcpy(packet_ptr, &hdr, sizeof(hdr));
        packet_ptr += sizeof(hdr);
        memcpy(packet_ptr, &check, DATA_CHECKSUM_SIZE);
        packet_ptr += DATA_CHECKSUM_SIZE;
        memcpy(packet_ptr, buffer + sent_bytes, current_len);

        sendto(con->sockfd, packet.data(), packet.size(), 0,(struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

        con->send_window.push_back(packet);
        con->send_window_seq.push_back(con->next_seq);
        con->next_seq++;
        sent_bytes += current_len;
    }

    pthread_mutex_unlock(&cons[conn_id]->con_lock);
    return sent_bytes;
}

static bool valid_ack(poli_tcp_ctrl_hdr *ack, int conn_id)
{
    return ack->protocol_id == POLI_PROTOCOL_ID &&
           ack->conn_id == (uint8_t)conn_id &&
           ack->type == TYPE_ACK;
}

static bool seq_before(uint16_t a, uint16_t b)
{
    return (int16_t)(a - b) < 0;
}

static void remove_confirmed_seg(connection *con, uint16_t ack_num)
{
    while (!con->send_window.empty())
    {
        uint16_t first_seq = con->send_window_seq.front();

        if (!seq_before(first_seq, ack_num))
            break;

        con->send_window.pop_front();
        con->send_window_seq.pop_front();
    }
}

static void handle_received_ack(int conn_id, char *buf)
{
    poli_tcp_ctrl_hdr ack;
    memcpy(&ack, buf, sizeof(ack));

    if (cons.find(conn_id) == cons.end())
        return;

    pthread_mutex_lock(&cons[conn_id]->con_lock);
    connection *con = cons[conn_id];

    if (valid_ack(&ack, conn_id))
    {
        uint16_t ack_num = ntohs(ack.ack_num);
        uint16_t recv_window = ntohs(ack.recv_window);
        advertised_windows[conn_id] = recv_window;
        remove_confirmed_seg(con, ack_num);
    }

    pthread_mutex_unlock(&cons[conn_id]->con_lock);
}

static void retransmit_window(int conn_id)
{
    if (cons.find(conn_id) == cons.end())
        return;

    pthread_mutex_lock(&cons[conn_id]->con_lock);
    connection *con = cons[conn_id];

    if (!con->send_window.empty())
    {
        for (auto it = con->send_window.begin(); it != con->send_window.end(); ++it)
            sendto(con->sockfd, it->data(), it->size(), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
    }

    pthread_mutex_unlock(&cons[conn_id]->con_lock);
}

void *sender_handler(void *arg)
{
    char buf[MAX_SEGMENT_SIZE];

    while (1)
    {
        int conn_id = -1;
        int res = recv_message_or_timeout(buf, MAX_SEGMENT_SIZE, &conn_id);

        if (res >= (int)sizeof(poli_tcp_ctrl_hdr))
        {
            handle_received_ack(conn_id, buf);
        }
        else if (res == -1)
        {
            retransmit_window(conn_id);
        }
    }
}

static void init_server_addr(connection *con, uint32_t ip, uint16_t port)
{
    memset(&con->servaddr, 0, sizeof(con->servaddr));
    con->servaddr.sin_family = AF_INET;
    con->servaddr.sin_addr.s_addr = ip;
    con->servaddr.sin_port = htons(port);
}

static poli_tcp_ctrl_hdr build_syn(int conn_id)
{
    poli_tcp_ctrl_hdr syn;
    memset(&syn, 0, sizeof(syn));
    syn.protocol_id = POLI_PROTOCOL_ID;
    syn.conn_id = (uint8_t)conn_id;
    syn.type = TYPE_SYN;

    return syn;
}

static bool valid_syn_ack(poli_tcp_ctrl_hdr *msg)
{
    uint16_t port_value = ntohs(msg->recv_window);
    uint16_t check_value = ntohs(msg->ack_num);

    return msg->protocol_id == POLI_PROTOCOL_ID &&
           msg->type == TYPE_SYN_ACK &&
           check_value == (uint16_t)(port_value ^ 0xbeef);
}

static void init_server_connection(connection *con, int conn_id)
{
    pthread_mutex_init(&con->con_lock, NULL);
    con->next_seq = 0;
    con->expected_seq = 0;
    con->max_window_seq = compute_link_window_segmengts();
    advertised_windows[conn_id] = con->max_window_seq;
    cons.insert({conn_id, con});
}

int setup_connection(uint32_t ip, uint16_t port)
{
    /* Implement the sender part of the Three Way Handshake. Blocks
    until the connection is established */
    struct connection *con = new connection();
    int conn_id = next_local_conn_id++;
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    init_server_addr(con, ip, port);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 5000;
    if (setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        perror("Error");
    }

    poli_tcp_ctrl_hdr syn = build_syn(conn_id);
    bool established = false;
    int retry = 0;

    while (retry < MAX_RETRIES && !established)
    {
        sendto(con->sockfd, &syn, sizeof(syn), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

        char buf[sizeof(poli_tcp_ctrl_hdr)];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);

        int n = recvfrom(con->sockfd, buf, sizeof(buf), 0,(struct sockaddr *)&from, &from_len);
        if (n >= (int)sizeof(poli_tcp_ctrl_hdr))
        {
            poli_tcp_ctrl_hdr syn_ack;
            memcpy(&syn_ack, buf, sizeof(syn_ack));

            if (valid_syn_ack(&syn_ack))
            {
                conn_id = syn_ack.conn_id;
                con->conn_id = conn_id;
                con->servaddr = from;
                con->servaddr.sin_port = syn_ack.recv_window;

                poli_tcp_ctrl_hdr ack;
                memset(&ack, 0, sizeof(ack));

                ack.protocol_id = POLI_PROTOCOL_ID;
                ack.conn_id = (uint8_t)conn_id;
                ack.type = TYPE_ACK;
                ack.ack_num = htons(1);
                ack.recv_window = htons(1);

                int sent_acks = 0;
                while (sent_acks < 5)
                {
                    sendto(con->sockfd, &ack, sizeof(ack), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
                    sent_acks++;
                }

                established = true;
            }
        }
        retry++;
    }

    init_server_connection(con, conn_id);

    data_fds[fdmax].fd = con->sockfd;
    data_fds[fdmax].events = POLLIN;
    timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME, 0);
    timer_fds[fdmax].events = POLLIN;
    struct itimerspec spec;

    int timeout_ms = 2 * link_delay;
    if (timeout_ms < 5)
        timeout_ms = 5;

    if (timeout_ms > 30)
        timeout_ms = 30;

    spec.it_value.tv_sec = timeout_ms / 1000;
    spec.it_value.tv_nsec = (timeout_ms % 1000) * 1000000;
    spec.it_interval.tv_sec = timeout_ms / 1000;
    spec.it_interval.tv_nsec = (timeout_ms % 1000) * 1000000;
    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);
    fdmax++;

    DEBUG_PRINT("Connection established!");

    return conn_id;
}

void init_sender(int speed, int delay)
{
    pthread_t thread1;
    int ret;
    link_speed = speed;
    link_delay = delay;
    ret = pthread_create(&thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}