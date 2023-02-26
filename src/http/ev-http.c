#include "ev-http.h"
#include <stdio.h>
#include <string.h>
#include <llhttp.h>

#define EV_HTTP_IO_SIZE     (64 * 1024)

/**
 * @brief Align \p size to \p align, who's value is larger or equal to \p size
 *   and can be divided with no remainder by \p align.
 * @note \p align must equal to 2^n
 */
#define ALIGN_WITH(size, align) \
    (((uintptr_t)(size) + ((uintptr_t)(align) - 1)) & ~((uintptr_t)(align) - 1))

#if defined(_WIN32)
#   define sscanf(b, f, ...)    sscanf_s(b, f, ##__VA_ARGS__)
#endif

typedef struct ev_http_send_token
{
    ev_tcp_write_req_t  token;
    ev_http_conn_t*     conn;
    size_t              size;

#if defined(_MSC_VER)
#   pragma warning(push)
#   pragma warning(disable : 4200)
#endif
    unsigned char       data[];
#if defined(_MSC_VER)
#   pragma warning(pop)
#endif
} ev_http_send_token_t;

struct ev_http_conn_s
{
    ev_list_node_t      node;                       /**< Node for #ev_http_t::client_table */

    ev_http_t*          belong;                     /**< HTTP instance. */
    ev_tcp_t            client_sock;                /**< Client socket. */

    ev_tcp_read_req_t   recv_req;                   /**< Recv request token. */
    char                recv_buf[EV_HTTP_IO_SIZE];  /**< Recv buffer */

    ev_http_message_t*  on_parsing;                 /**< The message we are processing. */
    llhttp_t            parser;                     /**< HTTP parser */
    llhttp_settings_t   parser_setting;             /**< HTTP parser settings */

    int                 need_cb;
    ev_http_cb          evt_cb;
    void*               evt_arg;
};

/**
 * @brief Ensure \p str have enough capacity for \p size.
 * @param[in] str   String container.
 * @param[in] size  Required size, not including NULL terminator.
 * @return          UV error code.
 */
static int s_uv_http_str_ensure_size(ev_http_str_t* str, size_t size)
{
    /* Check if it is a constant string. */
    if (str->ptr != NULL && str->cap == 0)
    {
        abort();
    }

    if (str->cap >= size)
    {
        return 0;
    }

    size_t new_cap_plus_one;
    if (size > EV_HTTP_IO_SIZE)
    {
        new_cap_plus_one = ALIGN_WITH(size + 1, 4096);
    }
    else
    {
        size_t aligned_size = ALIGN_WITH(size + 1, sizeof(void*));
        size_t double_cap = str->cap << 1;
        new_cap_plus_one = aligned_size > double_cap ? aligned_size : double_cap;
    }

    void* new_ptr = realloc(str->ptr, new_cap_plus_one);
    if (new_ptr == NULL)
    {
        return EV_ENOMEM;
    }

    str->ptr = new_ptr;
    str->cap = new_cap_plus_one - 1;
    return 0;
}


static void s_uv_http_str_destroy(ev_http_str_t* str)
{
    if (str->ptr != NULL && str->cap != 0)
    {
        free(str->ptr);
    }
    str->ptr = NULL;
    str->len = 0;
    str->cap = 0;
}

static int s_uv_http_str_append(ev_http_str_t* str, const void* at, size_t length)
{
    size_t required_size = str->len + length;
    int ret = s_uv_http_str_ensure_size(str, required_size);
    if (ret != 0)
    {
        return ret;
    }

    memcpy(str->ptr + str->len, at, length);
    str->ptr[required_size] = '\0';
    str->len = required_size;

    return 0;
}

static void _ev_http_on_close(ev_tcp_t* sock)
{
    ev_http_t* http = EV_CONTAINER_OF(sock, ev_http_t, listen_sock);
    if (http->close_cb != NULL)
    {
        http->close_cb(http);
    }
}

static void _ev_http_callback(ev_http_conn_t* conn, ev_http_event_t evt, void* evt_data)
{
    ev_http_t* http = conn->belong;

    ev_http_cb cb;
    void* arg;
    if (conn->evt_cb != NULL)
    {
        cb = conn->evt_cb;
        arg = conn->evt_arg;
    }
    else
    {
        cb = http->evt_cb;
        arg = http->evt_arg;
    }

    cb(conn, evt, evt_data, arg);
}

static void _ev_http_on_client_close(ev_tcp_t* sock)
{
    ev_http_conn_t* conn = EV_CONTAINER_OF(sock, ev_http_conn_t, client_sock);

    if (conn->need_cb)
    {
        _ev_http_callback(conn, EV_HTTP_CLOSE, NULL);
    }

    free(conn);
}

static void _ev_http_destroy_message(ev_http_message_t* msg)
{
    s_uv_http_str_destroy(&msg->url);
    s_uv_http_str_destroy(&msg->status);
    s_uv_http_str_destroy(&msg->version);
    s_uv_http_str_destroy(&msg->body);
    s_uv_http_str_destroy(&msg->method);

    size_t i;
    for (i = 0; i < msg->header_len; i++)
    {
        s_uv_http_str_destroy(&msg->headers[i].name);
        s_uv_http_str_destroy(&msg->headers[i].value);
    }
    if (msg->headers != NULL)
    {
        free(msg->headers);
        msg->headers = NULL;
    }
    msg->header_len = 0;
    msg->header_cap = 0;

    free(msg);
}

static void _ev_http_close_connection(ev_http_conn_t* conn, int need_cb)
{
    ev_http_t* http = conn->belong;

    if (conn->on_parsing != NULL)
    {
        _ev_http_destroy_message(conn->on_parsing);
        conn->on_parsing = NULL;
    }

    conn->need_cb = need_cb;
    ev_list_erase(&http->client_table, &conn->node);
    ev_tcp_exit(&conn->client_sock, _ev_http_on_client_close);
}

static int s_uv_http_parse_url(const char* url, char* ip, int* port)
{
    size_t pos;
    if (strncmp(url, "http://", 7) == 0)
    {
        url += 7;
        *port = 80;

        int is_ipv6 = 0;
        int is_ipv6_end = 0;
        for (pos = 0; url[pos] != '\0'; pos++)
        {
            switch (url[pos])
            {
            case '[':
                if (pos != 0)
                {
                    return -1;
                }
                is_ipv6 = 1;
                break;

            case ']':
                if (!is_ipv6)
                {
                    return -1;
                }
                is_ipv6_end = 1;
                memcpy(ip, url + 1, pos - 2);
                ip[pos - 2] = '\0';
                break;

            case ':':
                if (pos == 0)
                {
                    return -1;
                }
                if (is_ipv6 && !is_ipv6_end)
                {
                    break;
                }
                if (!is_ipv6)
                {
                    memcpy(ip, url, pos);
                    ip[pos] = '\0';
                }
                if (sscanf(url + pos + 1, "%d", port) != 1)
                {
                    return -1;
                }
                break;

            default:
                break;
            }
        }

        return 0;
    }

    return EV_EINVAL;
}

static int s_uv_http_url_to_addr(struct sockaddr_storage* addr, const char* url)
{
	int ret;

	char ip[64]; int port;
	if ((ret = s_uv_http_parse_url(url, ip, &port)) != 0)
	{
		return ret;
	}

	ret = strstr(ip, ":") ? ev_ipv6_addr(ip, port, (struct sockaddr_in6*)addr)
		: ev_ipv4_addr(ip, port, (struct sockaddr_in*)addr);

	return ret;
}

static int s_uv_http_bind_address(ev_http_t* http, const char* url)
{
	int ret;

	struct sockaddr_storage listen_addr;
	if ((ret = s_uv_http_url_to_addr(&listen_addr, url)) != 0)
	{
		return ret;
	}

	if ((ret = ev_tcp_bind(&http->listen_sock, (struct sockaddr*)&listen_addr, 0)) != 0)
	{
		return ret;
	}

	return 0;
}

static void _ev_http_on_read(ev_tcp_read_req_t* req, size_t size, int stat)
{
    int ret;
    ev_http_conn_t* conn = EV_CONTAINER_OF(req, ev_http_conn_t, recv_req);

    if (stat != 0)
    {
        _ev_http_callback(conn, EV_HTTP_ERROR, (void*)ev_strerror(stat));
        _ev_http_close_connection(conn, 1);
        return;
    }

    if ((ret = llhttp_execute(&conn->parser, conn->recv_buf, size)) != 0)
    {
        _ev_http_callback(conn, EV_HTTP_ERROR, (void*)llhttp_errno_name(ret));
        _ev_http_close_connection(conn, 1);
        return;
    }
}

static void _ev_http_on_accept(ev_tcp_t* lisn_sock, ev_tcp_t* conn_sock, int stat)
{
    (void)lisn_sock;
    ev_http_conn_t* conn = EV_CONTAINER_OF(conn_sock, ev_http_conn_t, client_sock);

    if (stat != 0)
    {
        _ev_http_close_connection(conn, 0);
        return;
    }

    _ev_http_callback(conn, EV_HTTP_ACCEPT, NULL);

    ev_buf_t buf = ev_buf_make(conn->recv_buf, sizeof(conn->recv_buf));
    int ret = ev_tcp_read(conn_sock, &conn->recv_req, &buf, 1, _ev_http_on_read);
    if (ret != 0)
    {
        _ev_http_close_connection(conn, 1);
        return;
    }
}

static int s_uv_http_on_parser_ensure_headers(ev_http_message_t* msg)
{
    if (msg->header_len < msg->header_cap)
    {
        return 0;
    }

    size_t new_cap = msg->header_cap * 2;
    size_t new_size = sizeof(uv_http_header_t) * new_cap;
    uv_http_header_t* new_header = realloc(msg->headers, new_size);
    if (new_header == NULL)
    {
        return EV_ENOMEM;
    }

    msg->headers = new_header;
    msg->header_cap = new_cap;
    return 0;
}

static int _ev_http_on_parser_begin(llhttp_t* parser)
{
    const size_t default_header_cap = 32;
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);

    if ((conn->on_parsing = malloc(sizeof(ev_http_message_t))) == NULL)
    {
        return EV_ENOMEM;
    }
    memset(conn->on_parsing, 0, sizeof(*conn->on_parsing));

    size_t malloc_size = sizeof(uv_http_header_t) * (default_header_cap);
    if ((conn->on_parsing->headers = malloc(malloc_size)) == NULL)
    {
        return EV_ENOMEM;
    }
    memset(conn->on_parsing->headers, 0, malloc_size);
    conn->on_parsing->header_cap = default_header_cap;

    return 0;
}

static int s_uv_http_on_parser_url(llhttp_t* parser, const char* at, size_t length)
{
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);
    ev_http_message_t* msg = conn->on_parsing;
    return s_uv_http_str_append(&msg->url, at, length);
}

static int s_uv_http_on_parser_status(llhttp_t* parser, const char* at, size_t length)
{
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);
    ev_http_message_t* msg = conn->on_parsing;
    return s_uv_http_str_append(&msg->status, at, length);
}

static int s_uv_http_on_parser_method(llhttp_t* parser, const char* at, size_t length)
{
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);
    ev_http_message_t* msg = conn->on_parsing;
    return s_uv_http_str_append(&msg->method, at, length);
}

static int s_uv_http_on_parser_version(llhttp_t* parser, const char* at, size_t length)
{
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);
    ev_http_message_t* msg = conn->on_parsing;
    return s_uv_http_str_append(&msg->version, at, length);
}

static int s_uv_http_on_parser_header_field(llhttp_t* parser, const char* at, size_t length)
{
    int ret;
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);
    ev_http_message_t* msg = conn->on_parsing;

    if ((ret = s_uv_http_on_parser_ensure_headers(msg)) != 0)
    {
        return ret;
    }

    return s_uv_http_str_append(&msg->headers[msg->header_len].name, at, length);
}

static int s_uv_http_on_parser_header_value(llhttp_t* parser, const char* at, size_t length)
{
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);
    ev_http_message_t* msg = conn->on_parsing;

    return s_uv_http_str_append(&msg->headers[msg->header_len].value, at, length);
}

static int s_uv_http_on_parser_header_value_complete(llhttp_t* parser)
{
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);
    ev_http_message_t* msg = conn->on_parsing;

    msg->header_len++;
    return 0;
}

static int s_uv_http_on_parser_body(llhttp_t* parser, const char* at, size_t length)
{
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);
    ev_http_message_t* msg = conn->on_parsing;
    return s_uv_http_str_append(&msg->body, at, length);
}

static int s_uv_http_on_parser_complete(llhttp_t* parser)
{
    ev_http_conn_t* conn = EV_CONTAINER_OF(parser, ev_http_conn_t, parser);
    ev_http_message_t* msg = conn->on_parsing;
    conn->on_parsing = NULL;

    _ev_http_callback(conn, EV_HTTP_MESSAGE, msg);
    _ev_http_destroy_message(msg);

    return 0;
}

static int _ev_http_try_accept(ev_http_t* http, ev_http_conn_t** conn)
{
    int ret;
    ev_http_conn_t* new_conn = malloc(sizeof(ev_http_conn_t));
    if (new_conn == NULL)
    {
        return EV_ENOMEM;
    }
    memset(new_conn, 0, sizeof(*new_conn));

    llhttp_settings_init(&new_conn->parser_setting);
    new_conn->parser_setting.on_message_begin = _ev_http_on_parser_begin;
    new_conn->parser_setting.on_url = s_uv_http_on_parser_url;
    new_conn->parser_setting.on_status = s_uv_http_on_parser_status;
    new_conn->parser_setting.on_method = s_uv_http_on_parser_method;
    new_conn->parser_setting.on_version = s_uv_http_on_parser_version;
    new_conn->parser_setting.on_header_field = s_uv_http_on_parser_header_field;
    new_conn->parser_setting.on_header_value = s_uv_http_on_parser_header_value;
    new_conn->parser_setting.on_header_value_complete = s_uv_http_on_parser_header_value_complete;
    new_conn->parser_setting.on_body = s_uv_http_on_parser_body;
    new_conn->parser_setting.on_message_complete = s_uv_http_on_parser_complete;
    llhttp_init(&new_conn->parser, HTTP_BOTH, &new_conn->parser_setting);

    /* Initialize nessary fields */
    new_conn->belong = http;
    if ((ret = ev_tcp_init(http->loop, &new_conn->client_sock)) != 0)
    {
        free(new_conn);
        return ret;
    }
    ev_list_push_back(&http->client_table, &new_conn->node);

    /* Try to accept. */
    ret = ev_tcp_accept(&http->listen_sock, &new_conn->client_sock, _ev_http_on_accept);
    if (ret != 0)
    {
        _ev_http_close_connection(new_conn, 0);
        return ret;
    }

    if (conn != NULL)
    {
        *conn = new_conn;
    }

    return 0;
}

int ev_http_init(ev_loop_t* loop, ev_http_t* http)
{
    int ret;
    memset(http, 0, sizeof(*http));

    http->loop = loop;
    if ((ret = ev_tcp_init(loop, &http->listen_sock)) != 0)
    {
        return ret;
    }

    return 0;
}

void ev_http_exit(ev_http_t* http, ev_http_close_cb cb)
{
    ev_list_node_t* it;
    while ((it = ev_list_begin(&http->client_table)) != 0)
    {
        ev_http_conn_t* conn = EV_CONTAINER_OF(it, ev_http_conn_t, node);
        _ev_http_close_connection(conn, 1);
    }

    http->close_cb = cb;
    ev_tcp_exit(&http->listen_sock, _ev_http_on_close);
}

int ev_http_listen(ev_http_t* http, const char* url, ev_http_cb cb, void* arg)
{
	int ret;
	if ((ret = s_uv_http_bind_address(http, url)) != 0)
	{
		return ret;
	}

    if ((ret = ev_tcp_listen(&http->listen_sock, 1024)) != 0)
    {
        return ret;
    }

    http->evt_cb = cb;
    http->evt_arg = arg;

    return _ev_http_try_accept(http, NULL);
}

int ev_http_close(ev_http_conn_t* conn)
{
    _ev_http_close_connection(conn, 1);
    return 0;
}

static void _ev_http_on_send(ev_tcp_write_req_t* req, size_t size, int stat)
{
    (void)size;
    ev_http_send_token_t* token = EV_CONTAINER_OF(req, ev_http_send_token_t, token);
    ev_http_conn_t* conn = token->conn;

    free(token);

    if (stat != 0)
    {
        _ev_http_close_connection(conn, 1);
    }
}

int ev_http_send(ev_http_conn_t* conn, const void* data, size_t size)
{
    size_t malloc_size = sizeof(ev_http_send_token_t) + size;
    ev_http_send_token_t* token = malloc(malloc_size);
    if (token == NULL)
    {
        return EV_ENOMEM;
    }

    memcpy(token->data, data, size);
    token->size = size;
    token->conn = conn;

    ev_buf_t buf = ev_buf_make(token->data, token->size);
    int ret = ev_tcp_write(&conn->client_sock, &token->token, &buf, 1, _ev_http_on_send);
    if (ret != 0)
    {
        free(token);
        return ret;
    }

    return 0;
}
