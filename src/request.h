#pragma once

#include <stdio.h>
#include <dirent.h>
#include <fcntl.h>

#include <proto/request.pb-c.h>

enum mofos_error {
    ERROR_NO_ERROR,
    ERROR_NO_PERMS,
    ERROR_NOTFOUND,
    ERROR_EOF,
    ERROR_EBIG,
    ERROR_OTHER,
};

/**
 * Read related (un)marshalers
 **/
typedef int (*read_marshaler) (FSMessage *out,
                               const char* path,
                               const size_t len,
                               const off_t off);

typedef int (*read_unmarshaler) (const uint8_t *in,
                                 const size_t in_len,
                                 char **path,
                                 void *buf,
                                 size_t buf_len,
                                 off_t* offs,
                                 enum mofos_error *error);

/**
 * Write related (un)marshalers
 **/
typedef int (*write_marshaler) (uint8_t *out,
                                const size_t out_len,
                                const char* path,
                                const void* buf,
                                const size_t len,
                                const off_t offset,
                                enum mofos_error *error);

typedef int (*write_unmarshaler) (const FSMessage *in, char **path, void **buf,
                                  size_t *len, off_t *offset);

/**
 * attributes related (un)marshalers
 **/
typedef int (*attr_marshaler) (FSMessage *out, const char *path);
typedef int (*attr_unmarshaler) (FSMessage *in, struct stat *st);

/**
 * readdir related (un)marshalers
 **/
typedef int (*readdir_marshaler) (uint8_t *bytes,
                                  size_t len,
                                  const char* dir,
                                  const size_t dir_len,
                                  const off_t off,
                                  enum mofos_error *error);

typedef int (*readdir_unmarshaler) (const uint8_t *bytes,
                                    const size_t len,
                                    char** dir,
                                    size_t *dir_len,
                                    off_t *off,
                                    enum mofos_error *error);

typedef int (*mofos_reader) (uint8_t *buf, size_t len, void *useradata);

struct mofos_request_marshaler {
    read_marshaler read;
    write_marshaler write;
    attr_marshaler attr;
    readdir_marshaler readdir;
};

typedef int (*write_response_unmarshaler) (const uint8_t *bytes,
                                           const size_t len,
                                           char **path,
                                           enum mofos_error *error);

typedef int (*read_response_unmarshaler) (const uint8_t *bytes,
                                          const size_t len,
                                          char **path,
                                          void *buf,
                                          size_t *buf_len,
                                          off_t offset,
                                          enum mofos_error *error);

typedef int (*attr_response_unmarshaler) (const uint8_t *bytes,
                                          const size_t len,
                                          struct stat *st,
                                          enum mofos_error *error);

typedef int (*readdir_response_unmarshaler) (const uint8_t *bytes,
                                             const size_t len,
                                             struct dirent* dirs,
                                             enum mofos_error *error);

typedef int (*generic_response_unmarshaler) (const uint8_t *bytes,
                                             const size_t len,
                                             enum mofos_error *error);

typedef generic_response_unmarshaler unlink_response_unmarshaler;
typedef generic_response_unmarshaler open_response_unmarshaler;

struct mofos_response_unmarshaler {
    read_response_unmarshaler read;
    write_response_unmarshaler write;
    attr_response_unmarshaler attr;
    readdir_response_unmarshaler readdir;
    unlink_response_unmarshaler unlink;
    open_response_unmarshaler open;
};

/**
 * Marshals a read request into a FSMessage structure
 **/
int mofos_read_request_marshaler(uint8_t *bytes,
                                 size_t buf_len,
                                 const char* path,
                                 size_t len,
                                 off_t offset);

/**
 * Marshals a readdir request into an array of bytes
 **/
int mofos_readdir_request_marshaler();

/**
 * Unmarshals a read response from a FSMessage structure
 **/
int mofos_read_response_unmarshaler(const uint8_t *in,
                                    const size_t in_len,
                                    char **file,
                                    char **buf,
                                    size_t *len);

int mofos_readdir_response_unmarshaler(const uint8_t *in,
                                       const size_t in_len,
                                       char **dir,
                                       size_t *len,
                                       off_t *offset);

/**
 * Marshals a write request into a FSMessage
 **/
int mofos_write_request_marshaler(uint8_t *bytes, size_t len, const char* file,
                                  const void* buf, size_t req_len, off_t offset);

/**
 * Unmarshals a write response from a FSMessage
 **/
int mofos_write_unmarshaler(FSMessage *in, char* file, unsigned char* buf, size_t len,
                  off_t offset);


/**
 * creates a readdir request from parameters
 **/
int mofos_readdir_request_marshaler(uint8_t *bytes,
                                    size_t len,
                                    const char* path,
                                    const size_t sz,
                                    const off_t offset);

/**
 * creates a getattr request from parameters
 **/
int mofos_attr_request_marshaler(uint8_t *bytes,
                                 size_t len,
                                 const char* file);

/**
 * extracts parameters from a readdir request
 */
int mofos_readdir_request_unmarshaler(const FSMessage *in,
                                      char **path,
                                      size_t *sz,
                                      off_t *offset);

int mofos_attr_response_unmarshaler(uint8_t *bytes,
                                    size_t len,
                                    struct stat *st);

int mofos_attr_request_unmarshaler(const FSMessage *in,
                                   char **file,
                                   struct stat *st);

int mofos_attr_response_unmarshaler(uint8_t *bytes,
                                    size_t len,
                                    struct stat *st);

FSMessage* mofos_message_from_fd(void *from, mofos_reader reader);
FSMessage* mofos_message_from_bytes(const uint8_t *data, const size_t len);

extern const struct mofos_request_marshaler mofos_request_marshaler;
extern const struct mofos_response_unmarshaler mofos_response_unmarshaler;
