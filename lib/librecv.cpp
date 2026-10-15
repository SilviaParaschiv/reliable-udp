#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <poll.h>
#include <cassert>
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

static int listen_sock = -1;
static bool listen_bound = false;
static int next_conn_id = 0;
static int recv_buffer_limit = 0;
static const int DATA_CHECKSUM_SIZE = sizeof(uint32_t);

enum
{
    TYPE_SYN = 1,
    TYPE_SYN_ACK = 2,
    TYPE_ACK = 3,
    TYPE_DATA = 4,
};

static int buffered_bytes(connection *con)
{
    int bytes = con->recv_buffer.size();
    for (auto &entry : con->out_of_order)
    {
        bytes += entry.second.size();
    }
    return bytes;
}

static uint16_t compute_recv_window(connection *con)
{
    int free_bytes = recv_buffer_limit - buffered_bytes(con);

    if (free_bytes <= 0)
        return 0;

    int free_segments = free_bytes / (MAX_DATA_SIZE - DATA_CHECKSUM_SIZE);

    if (free_segments > con->max_window_seq)
        free_segments = con->max_window_seq;
    return (uint16_t)free_segments;
}

static void send_ack(connection *con, int conn_id, uint16_t ack_num)
{
    poli_tcp_ctrl_hdr ack;
    memset(&ack, 0, sizeof(ack));
    ack.protocol_id = POLI_PROTOCOL_ID;
    ack.conn_id = (uint8_t)conn_id;
    ack.type = TYPE_ACK;
    ack.ack_num = htons(ack_num);
    ack.recv_window = htons(compute_recv_window(con));
    sendto(con->sockfd, &ack, sizeof(ack), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
}

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

static int take_from_recv_buffer(connection *con, char *buffer, int max_len)
{
    int copied = 0;
    while (copied < max_len && !con->recv_buffer.empty())
    {
        buffer[copied] = con->recv_buffer.front();
        con->recv_buffer.pop_front();
        copied++;
    }

    return copied;
}

int recv_data(int conn_id, char *buffer, int len)
{
    int received = 0;
    do
    {
        pthread_mutex_lock(&cons[conn_id]->con_lock);

        connection *con = cons[conn_id];
        received = take_from_recv_buffer(con, buffer, len);
        if (received > 0)
            send_ack(con, conn_id, con->expected_seq);

        pthread_mutex_unlock(&cons[conn_id]->con_lock);

        if (received == 0)
            usleep(1000);

    } while (received == 0);

    return received;
}

static bool valid_data_header(poli_tcp_data_hdr *hdr, int conn_id)
{
    return hdr->protocol_id == POLI_PROTOCOL_ID &&
           hdr->conn_id == (uint8_t)conn_id &&
           hdr->type == TYPE_DATA;
}

static bool valid_data_size(int received_bytes, uint16_t data_len)
{
    int min_size = sizeof(poli_tcp_data_hdr) + DATA_CHECKSUM_SIZE + data_len;

    if (data_len > MAX_DATA_SIZE - DATA_CHECKSUM_SIZE)
        return false;
    if (received_bytes < min_size)
        return false;

    return true;
}

static bool seq_before(uint16_t a, uint16_t b)
{
    return (int16_t)(a - b) < 0;
}

static void save_seg_if_needed(connection *con, uint16_t seq, char *payload, uint16_t data_len)
{

    if (seq_before(seq, con->expected_seq))
        return;

    uint16_t diff = (uint16_t)(seq - con->expected_seq);
    if (diff >= con->max_window_seq)
        return;

    if (buffered_bytes(con) + data_len > recv_buffer_limit)
        return;

    if (con->out_of_order.find(seq) != con->out_of_order.end())
        return;

    con->out_of_order[seq] = vector<char>(payload, payload + data_len);
}

static void move_ready_seg(connection *con)
{

    if (con->out_of_order.find(con->expected_seq) == con->out_of_order.end())
        return;

    do
    {
        vector<char> data = con->out_of_order[con->expected_seq];

        for (size_t i = 0; i < data.size(); i++)
            con->recv_buffer.push_back(data[i]);

        con->out_of_order.erase(con->expected_seq);
        con->expected_seq++;
    } while (con->out_of_order.find(con->expected_seq) != con->out_of_order.end());
}

static void process_data_segment(connection *con, int conn_id, char *segment, poli_tcp_data_hdr *hdr, int res)
{
    uint16_t seq = ntohs(hdr->seq_num);
    uint16_t data_len = ntohs(hdr->len);

    if (!valid_data_size(res, data_len))
        return;

    uint32_t sent_checksum;
    memcpy(&sent_checksum, segment + sizeof(poli_tcp_data_hdr), DATA_CHECKSUM_SIZE);
    sent_checksum = ntohl(sent_checksum);

    char *payload = segment + sizeof(poli_tcp_data_hdr) + DATA_CHECKSUM_SIZE;

    uint32_t computed_checksum = segment_checksum((uint8_t)conn_id, seq, payload, data_len);

    if (sent_checksum != computed_checksum)
    {
        send_ack(con, conn_id, con->expected_seq);
        return;
    }

    save_seg_if_needed(con, seq, payload, data_len);
    move_ready_seg(con);
    send_ack(con, conn_id, con->expected_seq);
}

void *receiver_handler(void *arg)
{

    char segment[MAX_SEGMENT_SIZE];
    DEBUG_PRINT("Starting recviver handler\n");

    while (1)
    {
        int conn_id = -1;
        int res;

        do
        {
            res = recv_message_or_timeout(segment, MAX_SEGMENT_SIZE, &conn_id);
        } while (res == -14);

        if (res < (int)sizeof(poli_tcp_data_hdr))
            continue;

        poli_tcp_data_hdr hdr;
        memcpy(&hdr, segment, sizeof(hdr));

        if (cons.find(conn_id) == cons.end())
            continue;

        pthread_mutex_lock(&cons[conn_id]->con_lock);
        connection *con = cons[conn_id];

        if (valid_data_header(&hdr, conn_id))
            process_data_segment(con, conn_id, segment, &hdr, res);
        pthread_mutex_unlock(&con->con_lock);
    }
}

static bool is_valid_syn(poli_tcp_ctrl_hdr *syn)
{
    return syn->protocol_id == POLI_PROTOCOL_ID && syn->type == TYPE_SYN;
}

static void wait_for_syn(char *buf, struct sockaddr_in *client_addr)
{
    while (1)
    {
        poli_tcp_ctrl_hdr syn;
        socklen_t client_len = sizeof(*client_addr);

        int bytes = recvfrom(listen_sock, buf, MAX_SEGMENT_SIZE, 0,(struct sockaddr *)client_addr, &client_len);
        if (bytes >= (int)sizeof(syn))
        {
            memcpy(&syn, buf, sizeof(syn));
            if (is_valid_syn(&syn))
                break;
        }
    }
}

static int create_data_socket(uint32_t ip, struct sockaddr_in *local_addr)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(local_addr, 0, sizeof(*local_addr));
    local_addr->sin_family = AF_INET;
    local_addr->sin_addr.s_addr = ip;
    local_addr->sin_port = 0;
    bind(sockfd, (struct sockaddr *)local_addr, sizeof(*local_addr));
    socklen_t local_len = sizeof(*local_addr);
    getsockname(sockfd, (struct sockaddr *)local_addr, &local_len);

    return sockfd;
}

static poli_tcp_ctrl_hdr make_syn_ack(int conn_id, struct sockaddr_in *local_addr)
{
    poli_tcp_ctrl_hdr syn_ack;
    memset(&syn_ack, 0, sizeof(syn_ack));

    syn_ack.protocol_id = POLI_PROTOCOL_ID;
    syn_ack.conn_id = (uint8_t)conn_id;
    syn_ack.type = TYPE_SYN_ACK;
    syn_ack.ack_num = htons((uint16_t)(ntohs(local_addr->sin_port) ^ 0xbeef));
    syn_ack.recv_window = local_addr->sin_port;

    return syn_ack;
}

static bool valid_ack(poli_tcp_ctrl_hdr *ack, int conn_id)
{
    return ack->protocol_id == POLI_PROTOCOL_ID &&
           ack->conn_id == (uint8_t)conn_id &&
           ack->type == TYPE_ACK;
}

static bool wait_for_final_ack(connection *con,struct sockaddr_in *client_addr,poli_tcp_ctrl_hdr *syn_ack,char *buf,int conn_id)
{
    int tries = 0;
    while (tries < 20)
    {
        sendto(listen_sock, syn_ack, sizeof(*syn_ack), 0,(struct sockaddr *)client_addr, sizeof(*client_addr));

        int bytes = recvfrom(con->sockfd, buf, MAX_SEGMENT_SIZE, 0, NULL, NULL);

        if (bytes >= (int)sizeof(poli_tcp_ctrl_hdr))
        {
            poli_tcp_ctrl_hdr ack;
            memcpy(&ack, buf, sizeof(ack));

            if (valid_ack(&ack, conn_id))
                return true;
        }
        tries++;
    }
    return false;
}

static void bind_listen_socket(uint32_t ip, uint16_t port)
{
    if (listen_bound)
        return;

    int enable = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    addr.sin_port = htons(port);

    bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr));
    listen_bound = true;
}

static void init_new_connection(connection *con, int conn_id)
{
    pthread_mutex_init(&con->con_lock, NULL);
    con->next_seq = 0;
    con->expected_seq = 0;
    con->max_window_seq = recv_buffer_limit / (MAX_DATA_SIZE - DATA_CHECKSUM_SIZE);

    if (con->max_window_seq < 32)
        con->max_window_seq = 32;

    if (con->max_window_seq > 512)
        con->max_window_seq = 512;

    cons.insert({conn_id, con});
}

int wait4connect(uint32_t ip, uint16_t port)
{
    bind_listen_socket(ip, port);

    char buf[MAX_SEGMENT_SIZE];
    while (1)
    {
        struct sockaddr_in client_addr;
        wait_for_syn(buf, &client_addr);

        connection *con = new connection();

        int conn_id = next_conn_id++;
        con->conn_id = conn_id;
        con->servaddr = client_addr;

        struct sockaddr_in local_addr;
        con->sockfd = create_data_socket(ip, &local_addr);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 5000;
        if (setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        {
            perror("Error");
        }

        poli_tcp_ctrl_hdr syn_ack = make_syn_ack(conn_id, &local_addr);

        if (!wait_for_final_ack(con, &client_addr, &syn_ack, buf, conn_id))
        {
            close(con->sockfd);
            continue;
        }

        init_new_connection(con, conn_id);

        data_fds[fdmax].fd = con->sockfd;
        data_fds[fdmax].events = POLLIN;
        timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME, 0);
        timer_fds[fdmax].events = POLLIN;

        struct itimerspec spec;
        spec.it_value.tv_sec = 1;
        spec.it_value.tv_nsec = 0;
        spec.it_interval.tv_sec = 1;
        spec.it_interval.tv_nsec = 0;
        timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);
        fdmax++;

        DEBUG_PRINT("Connection established!");
        return conn_id;
    }
}

void init_receiver(int recv_buffer_bytes)
{
    pthread_t thread1;
    int ret;
    recv_buffer_limit = recv_buffer_bytes;
    listen_sock = socket(AF_INET, SOCK_DGRAM, 0);
    listen_bound = false;
    ret = pthread_create(&thread1, NULL, receiver_handler, NULL);
    assert(ret == 0);
}