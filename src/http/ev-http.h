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

typedef enum uv_http_fs_flag
{
    EV_HTTP_FS_READ     = 1,
    EV_HTTP_FS_WRITE    = 2,
    EV_HTTP_FS_DIR      = 4,
} uv_http_fs_flag_t;

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
} ev_http_header_t;

typedef struct ev_http_message_s
{
    ev_http_str_t       method;         /**< HTTP method. */
    ev_http_str_t       url;            /**< HTTP url. */
    ev_http_str_t       status;         /**< HTTP status. */
    ev_http_str_t       version;        /**< HTTP version. */

    ev_http_header_t*   headers;        /**< HTTP header array. */
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

typedef struct ev_http_fs
{
    /**
     * @brief This instance is no longer needed.
     * @param[in] self  Filesystem instance.
     */
    void (*release)(struct ev_http_fs* self);

    /**
     * @brief Stat path.
     * @param[in] self      This object.
     * @param[in] path      Path to file or directory.
     * @param[out] size     Size of file or directory.
     * @param[out] mtime    Modify time.
     * @return              Bit-OR of #ev_http_fs_flag_t.
     */
    int (*stat)(struct ev_http_fs* self, const char* path, size_t* size, time_t* mtime);

    /**
     * @brief List file and directory in \p path.
     * @param[in] self      This object.
     * @param[in] path      Path to directory.
     * @param[in] cb        Callback.
     * @param[in] arg       User defined argument passed to \p cb.
     */
    void (*ls)(struct ev_http_fs* self, const char* path, void (*cb)(const char* path, void* arg), void* arg);

    /**
     * @brief Open file.
     * @param[in] self      This object.
     * @param[in] path      File path.
     * @param[in] flags     Bit-OR of #ev_http_fs_flag_t.
     * @return              File handle.
     */
    void* (*open)(struct ev_http_fs* self, const char* path, int flags);

    /**
     * @brief Close file.
     * @param[in] self      This object.
     * @param[in] fd        File handle.
     */
    void (*close)(struct ev_http_fs* self, void* fd);

    /**
     * @brief Read file.
     * @param[in] self      This object.
     * @param[in] fd        File handle.
     * @param[in] buf       Buffer to store file content.
     * @param[in] size      Buffer size.
     * @return              The number of bytes read, or UV error code.
     */
    int (*read)(struct ev_http_fs* self, void* fd, void* buf, size_t size);

    /**
     * @brief Write file.
     * @param[in] self      This object.
     * @param[in] fd        File handle.
     * @param[in] buf       Buffer to write.
     * @param[in] size      Buffer size.
     * @return              The number of bytes write, or UV error code.
     */
    int (*write)(struct ev_http_fs* self, void* fd, const void* buf, size_t size);

    /**
     * @brief Seek file.
     * @param[in] self      This object.
     * @param[in] fd        File handle.
     * @param[in] offset    Offset from file begining.
     * @return              UV error code.
     */
    int (*seek)(struct ev_http_fs* self, void* fd, size_t offset);
} ev_http_fs_t;

typedef struct ev_http_serve_cfg
{
    const char*     root_path;          /**< Web root directory, must be non-NULL. */
    const char*     ssi_pattern;        /**< (Optional) SSI file name pattern. */
    const char*     extra_headers;      /**< (Optional) Extra HTTP headers to add in responses. */
    const char*     mime_types;         /**< (Optional) Extra mime types */
    const char*     page404;            /**< (Optional) Path to the 404 page. */
    ev_http_fs_t*   fs;                 /**< (Optional) Filesystem instance. */
} ev_http_serve_cfg_t;

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

/**
 * @brief Close HTTP connection.
 * @param[in] conn  HTTP connection.
 * @return          UV error code.
 */
int ev_http_close(ev_http_conn_t* conn);

/**
 * @brief Get header value.
 * @param[in] msg   HTTP message.
 * @param[in] name  Field name
 * @return          Field value.
 */
ev_http_str_t* ev_http_get_header(ev_http_message_t* msg, const char* name);

/**
 * @brief Send data on http connection.
 * @param[in] conn  HTTP connection.
 * @param[in] data  Data.
 * @param[in] size  Data size.
 * @return          UV error code.
 */
int ev_http_send(ev_http_conn_t* conn, const void* data, size_t size);

/**
 * @brief Generate serve file response message.
 * @param[in] conn  HTTP connection.
 * @param[in] msg   HTTP incoming message.
 * @param[in] cfg   Serve dir options.
 * @return          UV error code.
 */
int ev_http_serve_file(ev_http_conn_t* conn, ev_http_message_t* msg,
    ev_http_serve_cfg_t* cfg);

#ifdef __cplusplus
}
#endif

#endif
