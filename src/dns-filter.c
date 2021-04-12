#include <winsock2.h>
#include <mswsock.h>
#include "mongoose.h"
#include "uthash.h"

#define ip_str_min 7
#define ip_str_max 15

#define dns_timeout 500
#define dns_name_max 256
#define dns_queue_max 65536
#define dns_header_len sizeof(struct mg_dns_header)
#define dns_listen_url "udp://0.0.0.0:53"

#define socket_timeout 1000
#define socket_buf_size (512 * 1024)

typedef bool (*read_line_cb)(const char* line, size_t len);

struct dns_server
{
    struct dns_server* next;
    struct mg_connection* connection;
};

struct dns_item
{
    UT_hash_handle hh;

    unsigned long expire;
    uint16_t txnid;

    struct mg_addr peer;
    uint16_t peer_txnid;
};

struct host_addr
{
    UT_hash_handle hh;
    char* addr;
};

#pragma pack(push, 1)
struct dns_answer
{
    //point to the name in the DNS question 
    //always 0xc0, 0x0c (crazy people)
    //https://www.zytrax.com/books/dns/ch15/

    uint16_t pname;
    uint16_t atype;
    uint16_t aclass;
    uint32_t ttl;
    uint16_t alen;
};
#pragma pack(pop)

struct mg_mgr* mgr = NULL;
struct mg_connection* dns_connection = NULL;

struct dns_server* dns_servers = NULL;
struct dns_server* dns_servers_tail = NULL;
uint32_t dns_servers_count = 0;

struct host_addr* host_addrs = NULL;
struct dns_item* dns_queue = NULL;
uint32_t dns_queue_len = 0;
uint16_t dns_queue_txnid = 0;
unsigned long dns_queue_clean_time = 0;

int info_error(const char* text)
{
    printf("%s\n", text);
    return 1;
}

bool fix_udp_behavior(SOCKET socket)
{
    BOOL bValue = FALSE;
    DWORD dwBytesReturned = 0;

    int r1 = WSAIoctl(socket, SIO_UDP_CONNRESET, &bValue, sizeof(bValue), NULL, 0, &dwBytesReturned, NULL, NULL);
    int r2 = WSAIoctl(socket, SIO_UDP_NETRESET, &bValue, sizeof(bValue), NULL, 0, &dwBytesReturned, NULL, NULL);
    return (r1 == 0 && r2 == 0);
}

bool set_socket_buf(SOCKET socket, int rcvSize, int sndSize)
{
    int r1 = setsockopt(socket, SOL_SOCKET, SO_RCVBUF, &rcvSize, sizeof(rcvSize));
    int r2 = setsockopt(socket, SOL_SOCKET, SO_SNDBUF, &sndSize, sizeof(sndSize));
    return (r1 == 0 && r2 == 0);
}

int dns_parse_record(bool is_question, const uint8_t* buf, size_t len, size_t ofs, struct mg_dns_rr* record, char* name, size_t name_len)
{
    const struct mg_dns_header* header = (struct mg_dns_header*)buf;
    const uint8_t* s = buf + ofs, *e = &buf[len];
    if (len < dns_header_len || len > 512 || s >= e)
        return 0;

    memset(record, 0, sizeof(*record));
    if ((record->nlen = (uint16_t)mg_dns_parse_name(buf, len, ofs, name, name_len)) == 0)
        return 0;

    s += record->nlen + 4;
    if (s > e) 
        return 0;

    record->atype = ((uint16_t)s[-4] << 8) | s[-3];
    record->aclass = ((uint16_t)s[-2] << 8) | s[-1];
    if (is_question)
        return record->nlen + 4;

    s += 6;
    if (s > e) 
        return 0;

    record->alen = ((uint16_t)s[-2] << 8) | s[-1];
    if (s + record->alen > e) 
        return 0;

    return record->nlen + record->alen + 10;
}

bool dns_parse(bool is_question, const uint8_t* buf, size_t len, struct mg_dns_rr* record, char* name, size_t name_len)
{
    if (len < dns_header_len)
        return false;

    const struct mg_dns_header* header = (struct mg_dns_header*)buf;
    uint16_t num_answers = mg_ntohs(header->num_answers);
    uint16_t num_questions = mg_ntohs(header->num_questions);
    if (num_questions > 1 || num_answers > (is_question ? 0 : 10))
        return false;

    size_t ofs = dns_header_len;
    for (size_t i = 0; i < num_questions; i++)
    {
        size_t n = dns_parse_record(true, buf, len, ofs, record, name, name_len);
        if (n == 0)
            return false;

        ofs += n;
    }

    for (size_t i = 0; i < num_answers; i++)
    {
        struct mg_dns_rr answer_record;
        char answer_name[dns_name_max];

        size_t n = dns_parse_record(false, buf, len, ofs, &answer_record, &answer_name, dns_name_max);
        if (n == 0) 
            return false;

        ofs += n;
    }

    return true;
}

struct dns_item* dns_queue_add(struct mg_addr* peer, uint16_t peer_txnid)
{
    struct dns_item* item = NULL;

    HASH_FIND_UINT16(dns_queue, &dns_queue_txnid, item);
    if (item != NULL)
        return NULL;

    item = (struct dns_item*)calloc(1, sizeof(*item));
    item->txnid = dns_queue_txnid;
    item->expire = mg_millis() + dns_timeout;
    item->peer = *peer;
    item->peer_txnid = peer_txnid;

    HASH_ADD_UINT16(dns_queue, txnid, item);

    dns_queue_txnid++;
    dns_queue_len++;

    return item;
}

void dns_queue_remove(struct dns_item* item)
{
    HASH_DEL(dns_queue, item);
    free(item);

    dns_queue_len--;
}

void dns_queue_clean_expired()
{
    if (dns_queue == NULL)
        return;

    unsigned long now = mg_millis();
    unsigned long past = now - dns_queue_clean_time;

    if (past > dns_timeout)
    {
        dns_queue_clean_time = now;

        struct dns_item* item, * next;
        HASH_ITER(hh, dns_queue, item, next)
        {
            if (now > item->expire)
                dns_queue_remove(item);
        }
    }
}

void dns_queue_answer(struct mg_connection* connection)
{
    struct mg_dns_rr record;
    char dns_name[dns_name_max];

    if (dns_parse(false, connection->recv.buf, connection->recv.len, &record, &dns_name, dns_name_max))
    {
        struct mg_dns_header* header = (struct mg_dns_header*)connection->recv.buf;
        uint16_t txnid = mg_ntohs(header->txnid);

        struct dns_item* item;
        HASH_FIND_UINT16(dns_queue, &txnid, item);

        if (item != NULL)
        {
            struct mg_dns_header* header = (struct mg_dns_header*)connection->recv.buf;
            header->txnid = mg_htons(item->peer_txnid);

            dns_connection->peer = item->peer;
            mg_send(dns_connection, connection->recv.buf, connection->recv.len);

            dns_queue_remove(item);
        }
    }
}

void dns_resolved(struct mg_connection* connection, int event, void* event_data, void* fn_data)
{
    if (event == MG_EV_POLL)
    {
        if (!connection->is_readable)
            dns_queue_clean_expired();
    }
    else if (event == MG_EV_READ)
    {
        dns_queue_answer(connection);
        dns_queue_clean_expired();

        mg_iobuf_delete(&connection->recv, connection->recv.len);
    }
}

bool dns_check_filter(const char* name, struct mg_dns_rr* record)
{
    if (record->atype != 1 && record->atype != 28)
        return false;

    struct host_addr* item = NULL;
    HASH_FIND_STRN(host_addrs, name, strlen(name), item);
    if (item == NULL)
        return false;

    const char* addr_type = (record->atype == 1) ? "A" : "AAAA";
    printf("blocked %s %s\n", name, addr_type);
    return true;
}

void dns_answer_zero(struct mg_connection* connection, struct mg_dns_rr* record)
{
    size_t addr_len = (record->atype == 1 ? 4 : 16);
    size_t answer_len = connection->recv.len + sizeof(struct dns_answer) + addr_len;

    void* answer_data = calloc(1, answer_len);
    memcpy(answer_data, connection->recv.buf, connection->recv.len);

    struct mg_dns_header* header = (struct mg_dns_header*)answer_data;
    header->num_answers = mg_htons(1);
    header->flags = 0;

    struct dns_answer* answer = (struct dns_answer*)((char*)answer_data + connection->recv.len);
    answer->pname = ((uint16_t)0x0c << 8) | 0xc0;
    answer->atype = mg_htons(record->atype);
    answer->aclass = mg_htons(record->aclass);
    answer->ttl = mg_htons(10);
    answer->alen = mg_htons(addr_len);

    mg_send(connection, answer_data, answer_len);
    free(answer_data);
}

void dns_answer_resolve(struct mg_connection* connection)
{
    if (dns_queue_len < dns_queue_max)
    {
        struct mg_dns_header* header = (struct mg_dns_header*)connection->recv.buf;
        struct dns_item* item = dns_queue_add(&connection->peer, mg_htons(header->txnid));

        if (item != NULL)
        {
            header->txnid = mg_htons(item->txnid);

            for (struct dns_server* server = dns_servers; server != NULL; server = server->next)
                mg_send(server->connection, connection->recv.buf, connection->recv.len);
        }
    }
}

void dns_listen(struct mg_connection* connection, int event, void* event_data, void* fn_data)
{
    if (event == MG_EV_READ)
    {
        struct mg_dns_rr record;
        char dns_name[dns_name_max];

        if (dns_parse(true, connection->recv.buf, connection->recv.len, &record, &dns_name, dns_name_max))
        {
            if (dns_check_filter(dns_name, &record))
                dns_answer_zero(connection, &record);
            else
                dns_answer_resolve(connection);
        }

        mg_iobuf_delete(&connection->recv, connection->recv.len); 
    }
}

bool read_file_lines(const char* file, const read_line_cb callback)
{
    FILE* f = fopen(file, "rb");
    if (f == NULL)
        return false;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0)
        return false;

    unsigned char* buf = calloc(1, fsize);
    fseek(f, 0, SEEK_SET);
    fread(buf, 1, fsize, f);
    fclose(f);

    unsigned char* head = buf;
    unsigned char* pos = buf;
    unsigned char* tail = buf + fsize;
    bool read_ok = true;

    for (; pos <= tail; pos++)
    {
        if (*pos == '\n' || pos == tail)
        {
            unsigned char* ltail = pos;
            while (--ltail >= head && *ltail == '\r') { }

            if (!callback(head, ltail - head + 1))
            {
                read_ok = false;
                break;
            }

            head = pos + 1;
        }
    }

    free(buf);
    return read_ok;
}

bool read_dns_line(const char* line, size_t len)
{
    if (len < ip_str_min || len > ip_str_max || line[0] == '#')
        return true;

    char addr[40];
    memcpy(&addr, "udp://", 6);
    memcpy(&addr[6], line, len);
    memcpy(&addr[6 + len], ":53\0", 4);

    struct dns_server* server = calloc(1, sizeof(struct dns_server));
    server->connection = mg_connect(mgr, addr, NULL, NULL);
    if (server->connection == NULL)
        return false;

    server->connection->fn = dns_resolved;
    if (!fix_udp_behavior(server->connection->fd) ||
        !set_socket_buf(server->connection->fd, socket_buf_size, socket_buf_size))
        return false;

    if (dns_servers == NULL)
    {
        dns_servers = server;
        dns_servers_tail = server;
    }
    else
    {
        dns_servers_tail->next = server;
        dns_servers_tail = server;
    }

    dns_servers_count++;
    return true;
}

bool read_hosts_line(const char* line, size_t len)
{
    if (len < ip_str_min || line[0] == '#')
        return true;

    char* space = memchr(line, ' ', len);
    if (space == NULL)
        return true;

    size_t ip_len = space - line;
    if (ip_len != ip_str_min)
        return true;

    if (strncmp(line, "0.0.0.0", ip_str_min) != 0)
        return true;

    size_t addr_len = len - ip_len - 1;
    if (addr_len == 0)
        return true;

    char* addr = calloc(1, addr_len + 1);
    memcpy(addr, space + 1, addr_len);
    
    struct host_addr* item = NULL;
    HASH_FIND_STRN(host_addrs, addr, addr_len, item);
    if (item != NULL)
        return true;

    item = (struct host_addr*)calloc(1, sizeof(*item));
    item->addr = addr;

    HASH_ADD_STRN(host_addrs, addr, addr_len, item);
    return true;
}

int main(void) 
{
    if (!read_file_lines("hosts.txt", read_hosts_line))
        return info_error("read hosts.txt failed");

    printf("loaded %u items from hosts.txt\n", HASH_COUNT(host_addrs));
    
    mgr = calloc(1, sizeof(struct mg_mgr));
    mg_mgr_init(mgr);

    dns_connection = mg_listen(mgr, dns_listen_url, dns_listen, NULL);
    if (dns_connection == NULL)
        return info_error("listen udp port 53 failed");

    if (!fix_udp_behavior(dns_connection->fd) ||
        !set_socket_buf(dns_connection->fd, socket_buf_size, socket_buf_size))
        return info_error("dns_connection socket set failed");

    if (!read_file_lines("dns.txt", read_dns_line) || dns_servers == NULL)
        return info_error("read dns.txt failed");

    printf("loaded %u items from dns.txt\n", dns_servers_count);
    printf("listening on %s...\n", dns_listen_url);

    while (true)
        mg_mgr_udp_poll(mgr, socket_timeout);

    return 0;
}
