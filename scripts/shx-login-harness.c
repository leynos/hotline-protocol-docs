/* Host-only harness. The driver inserts unchanged historical callback/macros. */
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hotline.h"

#define memory_copy memcpy
#define INFOPREFIX ""
#define SIN_ADDR sin_addr
#define SIN_PORT sin_port
struct input_buffer { unsigned char *buf; uint32_t pos; };
struct htlc_conn {
    struct input_buffer in;
    struct sockaddr_in sockaddr;
    uint32_t uid;
};
static unsigned connected;
static void on_connect(struct htlc_conn *connection) {
    (void)connection;
    connected++;
}
static struct { void (*on_connect)(struct htlc_conn *); } hx_output = {on_connect};
static int snd_login;
static void hx_chat_new(struct htlc_conn *connection, unsigned cid) {
    (void)connection;
    (void)cid;
}
static void play_sound(int sound) { (void)sound; }
static void hx_printf_prefix(struct htlc_conn *connection, unsigned cid,
                             const char *prefix, const char *format, ...) {
    (void)connection; (void)cid; (void)prefix; (void)format;
}
static void inet_ntoa_r(struct in_addr address, char *output, size_t capacity) {
    (void)address;
    snprintf(output, capacity, "127.0.0.1");
}

/* INSERT_UNCHANGED_MACROS */
/* INSERT_UNCHANGED_CALLBACK */

static unsigned char frame[2048];
static uint16_t field_count;
static void put16(unsigned char *where, uint16_t value) {
    value = htons(value);
    memcpy(where, &value, sizeof(value));
}
static void put32(unsigned char *where, uint32_t value) {
    value = htonl(value);
    memcpy(where, &value, sizeof(value));
}
static void add_field(struct htlc_conn *connection, uint16_t id,
                      const unsigned char *bytes, uint16_t length) {
    size_t offset = connection->in.pos;
    if (offset + length + 4 >= sizeof(frame)) exit(2);
    put16(frame + offset, id);
    put16(frame + offset + 2, length);
    memcpy(frame + offset + 4, bytes, length);
    connection->in.pos += length + 4;
    put16(frame + 20, ++field_count);
}
static void extras(struct htlc_conn *connection) {
    const unsigned char version[] = {0, 190};
    const unsigned char identifier[] = {0, 0, 0, 7};
    const unsigned char name[] = "HLserver19";
    add_field(connection, 160, version, sizeof(version));
    add_field(connection, 161, identifier, sizeof(identifier));
    add_field(connection, 162, name, sizeof(name) - 1);
}
int main(void) {
    const char *names[] = {
        "empty_success", "native_extras", "uid_and_extras", "unknown_field",
        "status_one", "status_two_low_bit_clear", "repeated_uid"
    };
    for (unsigned test = 0; test < sizeof(names) / sizeof(names[0]); test++) {
        struct htlc_conn connection;
        memset(&connection, 0, sizeof(connection));
        memset(frame, 0, sizeof(frame));
        connected = 0;
        field_count = 0;
        connection.in.buf = frame;
        connection.in.pos = SIZEOF_HL_HDR;
        connection.uid = 7;
        put32(frame, HTLS_HDR_TASK);
        put32(frame + 4, 1);
        put32(frame + 8, test == 4 ? 1 : test == 5 ? 2 : 0);
        const unsigned char uid[] = {0, 42};
        if (test == 1 || test == 2 || test == 4 || test == 5) extras(&connection);
        if (test == 2 || test == 6) add_field(&connection, 103, uid, sizeof(uid));
        if (test == 3) {
            const unsigned char unknown[] = {255, 0, 201};
            add_field(&connection, 0x7fff, unknown, sizeof(unknown));
        }
        if (test == 6) {
            const unsigned char later_uid[] = {0, 43};
            add_field(&connection, 103, later_uid, sizeof(later_uid));
        }
        put32(frame + 12, connection.in.pos - 20);
        put32(frame + 16, connection.in.pos - 20);
        rcv_task_login(&connection, NULL);
        unsigned expected_uid = test == 2 ? 42 : test == 6 ? 43 : 7;
        unsigned expected_connected = test == 4 ? 0 : 1;
        int passed = connection.uid == expected_uid && connected == expected_connected;
        printf("{\"case\":\"%s\",\"uid\":%u,\"connect_calls\":%u,\"passed\":%s}\n",
               names[test], connection.uid, connected, passed ? "true" : "false");
        if (!passed) return 1;
    }
    return 0;
}
