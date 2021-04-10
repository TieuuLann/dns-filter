#include <winsock2.h>
#include <mswsock.h>
#include "mongoose.h"

#define dns_timeout 1000
#define dns_name_max 256
#define dns_queue_max 65535
#define dns_header_len sizeof(struct mg_dns_header)
#define socket_buf_size (512 * 1024)

struct dns_item
{
    struct dns_queue_item* next;
    unsigned long expire;
    uint16_t txnid;

    struct mg_addr peer;
    uint16_t peer_txnid;
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


struct mg_connection* dns_connection = NULL;
struct mg_connection* dns_ext_connection = NULL;

struct dns_item* dns_queue = NULL;
struct dns_item* dns_queue_tail = NULL;
uint32_t dns_queue_len = 0;
uint16_t dns_txnid = 1;

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

bool dns_parse(bool is_question, const uint8_t* buf, size_t len, size_t ofs, struct mg_dns_rr* record, char* name, size_t name_len) 
{
    const struct mg_dns_header* header = (struct mg_dns_header*)buf;
    const uint8_t* s = buf + ofs, *e = &buf[len];
    if (len < sizeof(*header) || len > 512 || s >= e)
        return false;

    uint16_t num_answers = mg_ntohs(header->num_answers);
    if (mg_ntohs(header->num_questions) > 1 || num_answers > (is_question ? 0 : 10))
        return false;

    memset(record, 0, sizeof(*record));
    if ((record->nlen = (uint16_t)mg_dns_parse_name(buf, len, ofs, name, name_len)) == 0)
        return false;

    s += record->nlen + 4;
    if (s > e) 
        return false;

    record->atype = ((uint16_t)s[-4] << 8) | s[-3];
    record->aclass = ((uint16_t)s[-2] << 8) | s[-1];
    if (is_question)
        return true;

    for (uint16_t i = 0; i < num_answers; i++)
    {
        s += 12;
        if (s > e) 
            return false;

        record->alen = ((uint16_t)s[-2] << 8) | s[-1];
        
        if (record->atype == 1 && record->alen != 4)
            return false;

        if (record->atype == 28 && record->alen != 16)
            return false;

        s += record->alen;
        if (s > e)
            return false;
    }

    return true;
}

struct dns_item* dns_queue_add(struct mg_addr* peer, uint16_t peer_txnid)
{
    struct dns_item* item = (struct dns_item*)calloc(1, sizeof(*item));

    item->next = NULL;
    item->expire = mg_millis() + dns_timeout;
    item->txnid = dns_txnid;
    item->peer = *peer;
    item->peer_txnid = peer_txnid;   

    if (dns_queue == NULL)
        dns_queue = item;

    if (dns_queue_tail != NULL)
        dns_queue_tail->next = item;

    dns_queue_tail = item;
    dns_queue_len++;

    if (++dns_txnid == 0)
        dns_txnid = 1;

    return item;
}

void dns_queue_remove(struct dns_item* item)
{
    struct dns_item** it = &dns_queue;
    while (*it != item) 
        it = &(*it)->next;

    if (*it == dns_queue_tail)
        dns_queue_tail = NULL;

    *it = item->next;
    free(item);

    dns_queue_len--;
}

void dns_resolved(struct mg_connection* connection, int event, void* event_data, void* fn_data)
{
    if (event == MG_EV_POLL)
    {
        unsigned long now = mg_millis();

        struct dns_item* item, * tmp;
        for (item = dns_queue; item != NULL; item = tmp)
        {
            tmp = item->next;
            if (now > item->expire)
                dns_queue_remove(item);
        }
    }
    else if (event == MG_EV_READ)
    {
        struct mg_dns_message message;
        int resolved = 0;

        struct mg_dns_rr record;
        if (dns_parse(false, connection->recv.buf, connection->recv.len, dns_header_len, &record, NULL, 0))
        {
            struct mg_dns_header* header = (struct mg_dns_header*)connection->recv.buf;
            uint16_t txnid = mg_ntohs(header->txnid);

            struct dns_item*item, * next;
            for (item = dns_queue; item != NULL; item = next)
            {
                next = item->next;
                if (item->txnid != txnid)
                    continue;

                struct mg_dns_header* header = (struct mg_dns_header*)connection->recv.buf;
                header->txnid = mg_htons(item->peer_txnid);

                dns_connection->peer = item->peer;
                mg_send(dns_connection, connection->recv.buf, connection->recv.len);

                dns_queue_remove(item);
            }
        }

        mg_iobuf_delete(&connection->recv, connection->recv.len);
    }
}

bool dns_check_filter(const char* name, struct mg_dns_rr* record)
{
    if (record->atype != 1 && record->atype != 28)
        return false;

    //printf("%s %u\n", name, record->atype);
    return (strcmp(name, "mail.ru") == 0);
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

void dns_answer_resolve(struct mg_connection* connection, struct mg_dns_rr* record)
{
    struct mg_dns_header* header = (struct mg_dns_header*)connection->recv.buf;
    struct dns_item* item = dns_queue_add(&connection->peer, mg_htons(header->txnid));

    header->txnid = mg_htons(item->txnid);
    mg_send(dns_ext_connection, connection->recv.buf, connection->recv.len);
}

void dns_listen(struct mg_connection* connection, int event, void* event_data, void* fn_data)
{
    if (event == MG_EV_READ)
    {
        if (dns_queue_len < dns_queue_max)
        {
            struct mg_dns_rr record;
            char dns_name[dns_name_max];
            if (dns_parse(true, connection->recv.buf, connection->recv.len, dns_header_len, &record, &dns_name, dns_name_max))
            {
                if (dns_check_filter(dns_name, &record))
                    dns_answer_zero(connection, &record);
                else
                    dns_answer_resolve(connection, &record);
            }
        }

        mg_iobuf_delete(&connection->recv, connection->recv.len); 
    }
}

int exit_error(const char* error)
{
    printf("%s\n", error);
    return 1;
}

int main(void) 
{
    struct mg_mgr mgr;

    mg_mgr_init(&mgr);
    dns_connection = mg_listen(&mgr, "udp://0.0.0.0:53", dns_listen, NULL);
    dns_ext_connection = mg_connect(&mgr, "udp://8.8.8.8:53", NULL, NULL);
    dns_ext_connection->fn = dns_resolved;

    if (!fix_udp_behavior(dns_connection->fd) ||
        !fix_udp_behavior(dns_ext_connection->fd))
        return exit_error("fix_udp_connreset failed");

    if (!set_socket_buf(dns_connection->fd, socket_buf_size, socket_buf_size))
        return exit_error("set_socket_buf failed");

    while (true)
        mg_mgr_udp_poll(&mgr, 1000);

    return 0;
}
