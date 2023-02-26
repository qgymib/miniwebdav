#ifndef __EV_HTTP_H__
#define __EV_HTTP_H__

#include <ev.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ev_http_s ev_http_t;
typedef struct ev_http_conn_s ev_http_conn_t;

typedef enum ev_http_event
{
    EV_HTTP_ERROR,      /**< (const char*) Error. */
    EV_HTTP_CONNECT,    /**< Connection establish. */
    EV_HTTP_ACCEPT,     /**< Connection accept. */
    EV_HTTP_CLOSE,      /**< Connection closed. */
    EV_HTTP_MESSAGE,    /**< (#ev_http_message_t) HTTP request/response */
} ev_http_event_t;

typedef struct ev_http_str
{
    char*               ptr;            /**< String address. */
    size_t              len;            /**< String length, not including NULL terminator. */
    size_t              cap;            /**< String container capacity, not including NULL terminator. */
} ev_http_str_t;

typedef struct
{
    ev_http_str_t       name;           /**< Header name. */
    ev_http_str_t       value;          /**< Header value. */
} uv_http_header_t;

typedef struct ev_http_message_s
{
    ev_http_str_t       method;         /**< HTTP method. */
    ev_http_str_t       url;            /**< HTTP url. */
    ev_http_str_t       status;         /**< HTTP status. */
    ev_http_str_t       version;        /**< HTTP version. */

    uv_http_header_t*   headers;        /**< HTTP header array. */
    size_t              header_len;     /**< HTTP header array length. */
    size_t              header_cap;     /**< HTTP header array capacity. */

    ev_http_str_t       body;           /**< HTTP body. */
} ev_http_message_t;

/**
 * @brief HTTP event callback.
 * @param[in] conn      Connection.
 * @param[in] evt       #ev_http_event_t.
 * @param[in] evt_data  Event data.
 * @param[in] arg       User defined argument.
 */
typedef void (*ev_http_cb)(ev_http_conn_t* conn, int evt, void* evt_data, void* arg);

/**
 * @brief HTTP close callback.
 * @param[in] http  HTTP component.
 */
typedef void (*ev_http_close_cb)(ev_http_t* http);

struct ev_http_s
{
    ev_loop_t*          loop;           /**< Event loop. */

    ev_tcp_t            listen_sock;    /**< Listening socket. */
    ev_list_t           client_table;   /**< (#ev_http_conn_t) Connection table. */

    ev_http_cb          evt_cb;
    void*               evt_arg;

    ev_http_close_cb    close_cb;
};

/**
 * @brief Create HTTP component.
 * @param[in] loop  Event loop.
 * @param[out] http Http Component
 * @return          0 if success, otherwise failure.
 */
int ev_http_init(ev_loop_t* loop, ev_http_t* http);

/**
 * @brief Close HTTP component.
 * @param[in] http  HTTP Component instance.
 * @param[in] cb    Close callback.
 */
void ev_http_exit(ev_http_t* http, ev_http_close_cb cb);

/**
 * @brief Do http listen.
 * @param[in] http  HTTP Component instance.
 * @param[in] url   Listen URL.
 * @param[in] cb    Event callback.
 * @param[in] arg   User defined data passed to callback.
 * @return          UV error code.
 */
int ev_http_listen(ev_http_t* http, const char* url, ev_http_cb cb, void* arg);

#ifdef __cplusplus
}
#endif

#endif
