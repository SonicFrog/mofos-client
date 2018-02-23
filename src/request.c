#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>

#include "debug.h"
#include "request.h"

#define INET6_MAX_MTU 1536

#define check_request(out, exp)                 \
    ((out)->request->type == (exp))

#define check_response(out, exp)                \
    ((out)->response->type == (exp))

#define generate_case_check_type(msg, req, tpe, field)  \
    case ##tpe:                                         \
    if (msg->##req->##field != NULL)                    \
        return msg;                                     \
    break;


#define CHECK_AND_RETURN_PERR(expr, rc, pfunc) \
    if ((rc = (expr)) < 0) {                   \
        func(#expr);                           \
        return rc;                             \
    }

#define CHECK_AND_RETURN(expr, rc)                 \
    if ((rc = (expr)) < 0) return rc;

static inline FSMessage
new_message(bool request, FSReqRespType type)
{
    static uint64_t id = 0;
    FSMessage out;

    //out = FSMESSAGE__INIT;

    id = __sync_fetch_and_add(&id, 1);

    if (request)
        out.request = zalloc(sizeof(FSRequest));
    else
        out.response = zalloc(sizeof(FSResponse));

    out.request->id = id;

    return out;
}

static inline FSMessage*
unpack_and_check(uint8_t *bytes, size_t len, FSReqRespType tp)
{
    FSMessage* msg = fsmessage__unpack(NULL, len, bytes);

    if (!msg)
        return NULL;

    if (!check_request(msg, tp)) {
        fsmessage__free_unpacked(msg, NULL);
        return NULL;
    }

    switch(msg->request->type) {
    case FSREQ_RESP_TYPE__TYPE_READ:
        if (msg->request->read != NULL)
            return msg;
        break;

    case FSREQ_RESP_TYPE__TYPE_WRITE:
        if (msg->request->write != NULL)
            return msg;
        break;

    case FSREQ_RESP_TYPE__TYPE_ATTR:
        if (msg->request->getattr != NULL)
            return msg;
        break;

    case FSREQ_RESP_TYPE__TYPE_READDIR:
        if (msg->request->readdir != NULL)
            return msg;
        break;

    case FSREQ_RESP_TYPE__TYPE_CREATE:
        if (msg->request->readdir != NULL)
            return msg;
        break;

    case FSREQ_RESP_TYPE__TYPE_UNLINK:
        if (msg->request->unlink != NULL)
            return msg;
        break;

    default:
        debug("invalid request type!");
    }

    fsmessage__free_unpacked(msg, NULL);
    return NULL;
}

static inline void
mofos_free_message(FSMessage **ptr)
{
    if (!ptr || !*ptr)
        return;

    fsmessage__free_unpacked(*ptr, NULL);

    *ptr = NULL;
}

#define mofos_new_request(type) new_message(true, type)
#define mofos_new_response(type) new_message(false, type)

int mofos_read_response_marshaler(uint8_t *bytes, size_t buf_len, const char* file,
                                  size_t len, off_t offset)
{
    int rc = 0;
    FSMessage msg;

    msg = mofos_new_request(FSREQ_RESP_TYPE__TYPE_READ);

    if (fsmessage__get_packed_size(&msg) > buf_len) {
        return -ENOBUFS;
    }

    return rc;
}

int mofos_read_response_unmarshaler(const uint8_t *bytes,
                                    const size_t len,
                                    char **file,
                                    char** buf,
                                    size_t *req_len)
{
    int rc = -1;
    _cleanup_(mofos_free_message) FSMessage *msg;

    msg = fsmessage__unpack(NULL, len, bytes);

    if (!msg || !check_request(msg, FSREQ_RESP_TYPE__TYPE_READ)) {
        /* either case is a malformed request */
        return -1;
    }

    *req_len = msg->response->read->content.len;
    *buf = strndup(msg->response->read->content.data, *req_len);

    return rc;
}

int mofos_write_request_marshaler(uint8_t *bytes, size_t len, const char* file,
                                  const void* buf, size_t req_len, off_t offset)
{
    int rc = -1;
    FSMessage msg;

    msg = mofos_new_request(FSREQ_RESP_TYPE__TYPE_WRITE);

    if (fsmessage__get_packed_size (&msg) > len)
        /* buffer is too small to store message */
        return -ENOBUFS;

    fsmessage__pack(&msg, bytes);

    return rc;
}

int mofos_attr_response_unmarshaler(uint8_t *bytes, size_t len, struct stat *st)
{
    _cleanup_(mofos_free_message) FSMessage *out = fsmessage__unpack(NULL,
                                                                     len,
                                                                     bytes);

    if (!out || !check_response(out, FSREQ_RESP_TYPE__TYPE_ATTR)) {
        /* FIXME: meaningful error */
        return -EINVAL;
    }

    if (out->response->getattr == NULL)
        /* request is of type attr but contains no data */
        return -EINVAL;

    return -1;
}

int mofos_attr_request_marshaler(uint8_t *bytes, size_t len, const char* file)
{
    int rc = -1;
    FSMessage out;

    out = mofos_new_request(FSREQ_RESP_TYPE__TYPE_ATTR);

    return rc;
}

int mofos_readdir_request_marshaler(uint8_t *bytes, size_t len, const char* path,
                                    const size_t sz, const off_t offset)
{
    int rc = -1;
    FSMessage msg;
    _cleanup_(freep) char *path_cpy;

    msg = mofos_new_request(FSREQ_RESP_TYPE__TYPE_ATTR);

    path_cpy = strdup(path);
    msg.request->readdir = NULL;
    msg.request->readdir->path = path_cpy;

    return rc;
}

int mofos_readdir_response_unmarshaler(const uint8_t *bytes, const size_t in_len,
                                       char **path, size_t *sz, off_t *offset)
{
    int rc = -1;

    unimplemented;

    return rc;
}

FSMessage* mofos_message_from_bytes(const uint8_t *data, const size_t len)
{
    return fsmessage__unpack(NULL, len, data);
}

FSMessage* mofos_message_from_fd(void *from, mofos_reader reader)
{
    uint8_t buf[INET6_MAX_MTU];
    int rc;

    rc = reader(buf, INET6_MAX_MTU, from);

    if (rc < 0) {
        warn ("failed to read message: %s", strerror(errno));
        return NULL;
    }

    return fsmessage__unpack(NULL, rc, buf);
}

const struct mofos_request_marshaler mofos_request_marshaler = {
    .read = NULL,
    .write = NULL,
    .attr = NULL,
    .readdir = NULL,
};

const struct mofos_response_unmarshaler mofos_response_unmarshaler = {
    .read = NULL,
    .write = NULL,
    .attr = NULL,
    .readdir = NULL,
};
