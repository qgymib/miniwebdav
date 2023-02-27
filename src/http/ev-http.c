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

/**
 * @brief Static initializer for #ev_http_str_t.
 */
#define EV_HTTP_STR_INIT    { NULL, 0, 0 }

#if defined(_WIN32)
#   define sscanf(b, f, ...)        sscanf_s(b, f, ##__VA_ARGS__)
#   define strncasecmp(s1, s2, n)   _strnicmp(s1, s2, n)
#endif

typedef enum ev_http_conn_action_type
{
    EV_HTTP_CONN_ACTION_SEND,
    EV_HTTP_CONN_ACTION_SERVE,
} ev_http_conn_action_type_t;

typedef struct ev_http_send_token
{
    ev_tcp_write_req_t          token;  /**< Send token. */
    ev_http_str_t               data;   /**< Data to send. No need to free. */
} ev_http_send_token_t;

typedef struct ev_http_serve_token
{
    ev_http_str_t               method;         /**< METHOD. No need to free. */
    ev_http_str_t               url;            /**< URL. No need to free. */
    ev_http_str_t               root_path;      /**< Root path. No need to free. */
    ev_http_str_t               ssi_pattern;    /**< SSI. No need to free. */
    ev_http_str_t               extra_headers;  /**< Extra headers. No need to free. */
    ev_http_str_t               mime_types;     /**< MIME. No need to free. */
    ev_http_str_t               page404;        /**< Path to 404 page. No need to free. */
    ev_http_str_t               if_none_match;  /**< Value of `If-None-Match`. No need to free. */
    ev_http_str_t               range;          /**< Value of `Range`. No need to free. */
    ev_http_fs_t*               fs;             /**< File system instance. */

    void*                       fd;             /**< File descriptor. */
    size_t                      remain_size;    /**< How many bytes remain to send. */
} ev_http_serve_token_t;

typedef struct ev_http_conn_action
{
    ev_list_node_t              node;   /**< #ev_http_conn_t::send_queue */
    ev_http_conn_t*             conn;   /**< The connection we are working on. */
    ev_http_conn_action_type_t  type;   /**< Action type. */

    union
    {
        ev_http_send_token_t    send;
        ev_http_serve_token_t   serve;
    }as;
} ev_http_conn_action_t;

struct ev_http_conn_s
{
    ev_list_node_t              node;                       /**< Node for #ev_http_t::client_table */

    ev_http_t*                  belong;                     /**< HTTP instance. */
    ev_tcp_t                    client_sock;                /**< Client socket. */

    ev_tcp_read_req_t           recv_req;                   /**< Recv request token. */
    char                        recv_buf[EV_HTTP_IO_SIZE];  /**< Recv buffer */

    ev_http_message_t*          on_parsing;                 /**< The message we are processing. */
    llhttp_t                    parser;                     /**< HTTP parser */
    llhttp_settings_t           parser_setting;             /**< HTTP parser settings */

    ev_list_t                   send_queue;                 /**< Send queue. */

    int                         need_cb;
    ev_http_cb                  evt_cb;
    void*                       evt_arg;
};

static ev_http_str_t s_empty_str = EV_HTTP_STR_INIT;

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

static int s_uv_http_str_vprintf(ev_http_str_t* str, const char* fmt, va_list ap)
{
    va_list ap_bak;
    va_copy(ap_bak, ap);
    int ret = vsnprintf(NULL, 0, fmt, ap_bak);
    va_end(ap_bak);

    size_t required_cap = str->len + ret;
    if (s_uv_http_str_ensure_size(str, required_cap) != 0)
    {
        return EV_ENOMEM;
    }

    if (vsnprintf(str->ptr + str->len, ret + 1, fmt, ap) != ret)
    {
        abort();
    }
    str->len += ret;

    return ret;
}

static int s_uv_http_str_printf(ev_http_str_t* str, const char* fmt, ...)
{
    int ret;
    va_list ap;
    va_start(ap, fmt);
    {
        ret = s_uv_http_str_vprintf(str, fmt, ap);
    }
    va_end(ap);

    return ret;
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

static void s_uv_http_fs_release(struct uv_http_fs* self)
{
    (void)self;
}

static int s_uv_http_fs_stat(struct uv_http_fs* self, const char* path, size_t* size, time_t* mtime)
{
    (void)self;
#if defined(_WIN32)
    struct _stat st;
    if (_stat(path, &st) != 0)
    {
        return 0;
    }
    int is_dir = st.st_mode & _S_IFDIR;
#else
    struct stat st;
    if (stat(path, &st) != 0)
    {
        return 0;
    }
    int is_dir = S_ISDIR(st.st_mode);
#endif

    if (size != NULL)
    {
        *size = st.st_size;
    }
    if (mtime != NULL)
    {
        *mtime = st.st_mtime;
    }
    return EV_HTTP_FS_READ | EV_HTTP_FS_WRITE | (is_dir ? EV_HTTP_FS_DIR : 0);
}

static void s_uv_http_fs_ls(struct uv_http_fs* self, const char* path,
    void (*cb)(const char* path, void* arg), void* arg)
{
    (void)self;
#if defined(_WIN32)

    ev_http_str_t fix_path = EV_HTTP_STR_INIT;
    s_uv_http_str_printf(&fix_path, "%s/*", path);

    WIN32_FIND_DATAA find_data;
    HANDLE dp = FindFirstFileA(fix_path.ptr, &find_data);
    s_uv_http_str_destroy(&fix_path);
    if (dp == INVALID_HANDLE_VALUE)
    {
        return;
    }

    do
    {
        if (strcmp(find_data.cFileName, ".") == 0 || strcmp(find_data.cFileName, "..") == 0)
        {
            continue;
        }
        cb(find_data.cFileName, arg);
    } while (FindNextFileA(dp, &find_data));

    FindClose(dp);

#else
    DIR* dir;
    struct dirent* dp;

    if ((dir = opendir(path)) == NULL)
    {
        return;
    }

    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
        {
            continue;
        }
        cb(dp->d_name, arg);
    }
    closedir(dir);
#endif
}

static void* s_uv_http_fs_open(struct uv_http_fs* self, const char* path, int flags)
{
    (void)self;
    const char* mode = flags == EV_HTTP_FS_READ ? "rb" : "a+b";

#if defined(_WIN32)
    FILE* f;
    if (fopen_s(&f, path, mode) != 0)
    {
        return NULL;
    }
    return (void*)f;
#else
    return (void*)fopen(path, mode);
#endif
}

static void s_uv_http_fs_close(struct uv_http_fs* self, void* fd)
{
    (void)self;
    fclose((FILE*)fd);
}

static int s_uv_http_fs_read(struct uv_http_fs* self, void* fd, void* buf, size_t size)
{
    (void)self;
    return (int)fread(buf, 1, size, (FILE*)fd);
}

static int s_uv_http_fs_write(struct uv_http_fs* self, void* fd, const void* buf, size_t size)
{
    (void)self;
    return (int)fwrite(buf, 1, size, (FILE*)fd);
}

static int s_uv_http_fs_seek(struct uv_http_fs* self, void* fd, size_t offset)
{
    (void)self;
    int errcode = 0;
    if (fseek(fd, (long)offset, SEEK_SET) != 0)
    {
        errcode = 0 - errno;
    }
    return errcode;
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

    size_t malloc_size = sizeof(ev_http_header_t) * (default_header_cap);
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

static void _ev_http_on_send(ev_tcp_write_req_t* req, size_t size, int stat)
{
    (void)size;
    ev_http_send_token_t* token = EV_CONTAINER_OF(req, ev_http_send_token_t, token);
    ev_http_conn_action_t* action = EV_CONTAINER_OF(token, ev_http_conn_action_t, as.send);
    ev_http_conn_t* conn = action->conn;

    free(token);

    if (stat != 0)
    {
        _ev_http_close_connection(conn, 1);
    }
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

ev_http_str_t* ev_http_get_header(ev_http_message_t* msg, const char* name)
{
    size_t i;
    size_t name_len = strlen(name);

    for (i = 0; i < msg->header_len; i++)
    {
        ev_http_header_t* hdr = &msg->headers[i];
        if (hdr->name.len == name_len && strncasecmp(hdr->name.ptr, name, name_len) == 0)
        {
            return &hdr->value;
        }
    }

    return NULL;
}

static int s_uv_http_parse_range(const ev_http_str_t* str, size_t size,
    size_t* beg, size_t* end)
{
    unsigned long long a, b;
    if (str->len < 6 || memcmp(str->ptr, "bytes=", 6) != 0)
    {
        return EV_ENOENT;
    }

    const char* p_beg = str->ptr + 6;
    const char* p_end = strstr(p_beg, ",");
    p_end = p_end != NULL ? p_end : str->ptr + str->len;

    const char* p_minus = strstr(p_beg, "-");

    /* last n bytes */
    if (p_minus == p_beg)
    {
        if (sscanf(p_beg, "-%llu", &a) != 1)
        {
            return EV_EINVAL;
        }

        if (a > size)
        {
            return EV_EINVAL;
        }

        *beg = size - a;
        *end = size;
        return 0;
    }

    /* start from n */
    if (p_minus == p_end)
    {
        if (sscanf(p_beg, "%llu-", &a) != 1)
        {
            return EV_EINVAL;
        }
        if (a > size)
        {
            return EV_EINVAL;
        }

        *beg = a;
        *end = size;
        return 0;
    }

    if (sscanf(p_beg, "%llu-%llu", &a, &b) != 2)
    {
        return EV_EINVAL;
    }
    if (a > b || b >= size)
    {
        return EV_EINVAL;
    }

    *beg = a;
    *end = b;
    return 0;
}

static int _ev_http_action_conn_send(ev_http_conn_t* conn, ev_http_conn_action_t* action)
{
    ev_buf_t buf = ev_buf_make(action->as.send.data.ptr, action->as.send.data.len);
    int ret = ev_tcp_write(&conn->client_sock, &action->as.send.token, &buf, 1, _ev_http_on_send);
    ev_list_erase(&conn->send_queue, &action->node);

    return ret;
}

static int _ev_http_action_conn_serve(ev_http_conn_t* conn, ev_http_conn_action_t* action)
{
    ev_http_serve_token_t* serve = &action->as.serve;

    
}

static int _ev_http_action_connection(ev_http_conn_t* conn)
{
    ev_http_conn_action_t* action = ev_list_begin(&conn->send_queue);
    if (action == NULL)
    {
        return 0;
    }

    if (action->type == EV_HTTP_CONN_ACTION_SEND)
    {
        return _ev_http_action_conn_send(conn, action);
    }

    return _ev_http_action_conn_serve(conn, action);
}

int ev_http_send(ev_http_conn_t* conn, const void* data, size_t size)
{
    size_t malloc_size = sizeof(ev_http_conn_action_t) + size;
    ev_http_conn_action_t* action = malloc(malloc_size);
    if (action == NULL)
    {
        return EV_ENOMEM;
    }

    action->conn = conn;
    action->type = EV_HTTP_CONN_ACTION_SEND;
    action->as.send.data.ptr = (char*)(action + 1);
    action->as.send.data.len = size;
    action->as.send.data.cap = 0;
    memcpy(action->as.send.data.ptr, data, size);

    ev_list_push_back(&conn->send_queue, &action->node);

    return _ev_http_action_connection(conn);
}

/**
 * @brief Generate serve file response message.
 * @param[in] conn  HTTP connection.
 * @param[in] msg   HTTP incoming message.
 * @param[in] cfg   Serve dir options.
 * @return          UV error code.
 */
int ev_http_serve_file(ev_http_conn_t* conn, ev_http_message_t* msg,
    ev_http_serve_cfg_t* cfg)
{
    static ev_http_fs_t s_builtin_fs = {
        s_uv_http_fs_release,
        s_uv_http_fs_stat,
        s_uv_http_fs_ls,
        s_uv_http_fs_open,
        s_uv_http_fs_close,
        s_uv_http_fs_read,
        s_uv_http_fs_write,
        s_uv_http_fs_seek,
    };

    ev_http_str_t* if_none_match = ev_http_get_header(msg, "If-None-Match");
    if_none_match = if_none_match != NULL ? if_none_match : &s_empty_str;
    ev_http_str_t* range = ev_http_get_header(msg, "Range");
    range = range != NULL ? range : &s_empty_str;

    size_t root_path_len = strlen(cfg->root_path);
    size_t ssi_pattern_len = cfg->ssi_pattern != NULL ? strlen(cfg->ssi_pattern) : 0;
    size_t extra_headers_len = cfg->extra_headers != NULL ? strlen(cfg->extra_headers) : 0;
    size_t mime_types_len = cfg->mime_types != NULL ? strlen(cfg->mime_types) : 0;
    size_t page404_len = cfg->page404 != NULL ? strlen(cfg->page404) : 0;
    size_t if_none_match_len = if_none_match->len;
    size_t range_len = range->len;

    size_t malloc_size = sizeof(ev_http_conn_action_t)
        + msg->method.len + 1
        + msg->url.len + 1
        + root_path_len + 1
        + ssi_pattern_len + 1
        + extra_headers_len + 1
        + mime_types_len + 1
        + page404_len + 1
        + if_none_match_len + 1
        + range_len + 1;
    ev_http_conn_action_t* action = malloc(malloc_size);
    if (action == NULL)
    {
        return EV_ENOMEM;
    }
    action->conn = conn;
    action->type = EV_HTTP_CONN_ACTION_SERVE;

    memset(&action->as.serve, 0, sizeof(action->as.serve));
    char* pos = (char*)(action + 1);

    action->as.serve.method.cap = 0;
    action->as.serve.method.len = msg->method.len;
    action->as.serve.method.ptr = pos;
    memcpy(action->as.serve.method.ptr, msg->method.ptr, msg->method.len);
    action->as.serve.method.ptr[action->as.serve.method.len] = '\0';
    pos += msg->method.len + 1;

    action->as.serve.url.cap = 0;
    action->as.serve.url.len = msg->url.len;
    action->as.serve.url.ptr = pos;
    memcpy(action->as.serve.url.ptr, msg->url.ptr, msg->url.len);
    action->as.serve.url.ptr[action->as.serve.url.len] = '\0';
    pos += msg->url.len + 1;

    action->as.serve.root_path.cap = 0;
    action->as.serve.root_path.len = root_path_len;
    action->as.serve.root_path.ptr = pos;
    memcpy(action->as.serve.root_path.ptr, cfg->root_path, root_path_len);
    action->as.serve.root_path.ptr[root_path_len] = '\0';
    pos += root_path_len + 1;

    action->as.serve.ssi_pattern.cap = 0;
    action->as.serve.ssi_pattern.len = ssi_pattern_len;
    action->as.serve.ssi_pattern.ptr = pos;
    memcpy(action->as.serve.ssi_pattern.ptr, cfg->ssi_pattern, ssi_pattern_len);
    action->as.serve.ssi_pattern.ptr[ssi_pattern_len] = '\0';
    pos += ssi_pattern_len + 1;

    action->as.serve.extra_headers.cap = 0;
    action->as.serve.extra_headers.len = extra_headers_len;
    action->as.serve.extra_headers.ptr = pos;
    memcpy(action->as.serve.extra_headers.ptr, cfg->extra_headers, extra_headers_len);
    action->as.serve.extra_headers.ptr[extra_headers_len] = '\0';
    pos += extra_headers_len + 1;

    action->as.serve.mime_types.cap = 0;
    action->as.serve.mime_types.len = mime_types_len;
    action->as.serve.mime_types.ptr = pos;
    memcpy(action->as.serve.mime_types.ptr, cfg->mime_types, mime_types_len);
    action->as.serve.mime_types.ptr[mime_types_len] = '\0';
    pos += mime_types_len + 1;

    action->as.serve.page404.cap = 0;
    action->as.serve.page404.len = page404_len;
    action->as.serve.page404.ptr = pos;
    memcpy(action->as.serve.page404.ptr, cfg->page404, page404_len);
    action->as.serve.page404.ptr[page404_len] = '\0';
    pos += page404_len + 1;

    action->as.serve.if_none_match.cap = 0;
    action->as.serve.if_none_match.len = if_none_match_len;
    action->as.serve.if_none_match.ptr = pos;
    memcpy(action->as.serve.if_none_match.ptr, if_none_match->ptr, if_none_match_len);
    action->as.serve.if_none_match.ptr[if_none_match_len] = '\0';
    pos += if_none_match_len + 1;

    action->as.serve.range.cap = 0;
    action->as.serve.range.len = range_len;
    action->as.serve.range.ptr = pos;
    memcpy(action->as.serve.range.ptr, range->ptr, range_len);
    action->as.serve.range.ptr[range_len] = '\0';
    pos += range_len + 1;

    action->as.serve.fs = cfg->fs != NULL ? cfg->fs : &s_builtin_fs;

    ev_list_push_back(&conn->send_queue, &action->node);
    return _ev_http_action_connection(conn);
}
