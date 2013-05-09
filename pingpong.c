/*
 LibEV networking code example
 Talks to the satoshi (standard) bitcoin client

 Based on: 
   https://github.com/coolaj86/libev-examples
   https://github.com/MatthewLM/cbitcoin
   http://codefundas.blogspot.com/2010/09/create-tcp-echo-server-using-libev.html
 */

#include <ev.h>
#include <stdio.h>
#include <netinet/in.h>
#include <string.h>
#include <CBVersion.h>
#include <CBNetworkAddress.h>
#include <CBMessage.h>
#include <CBPeer.h>
#include <time.h>

// every watcher type has its own typedef'd struct
// with the name ev_<type>
ev_io stdin_watcher;
ev_io sock_watcher;
ev_timer timeout_watcher;

// We are going to connect to a single peer
CBPeer *peer = 0;
#define DEFAULT_IP      "127.0.0.1" // connect to local satoshi
#define DEFAULT_PORT    28333
#define BUF_SIZE        4096

#define NETMAGIC 0xffffffff // mainnet
//#define NETMAGIC 0x0709110B // testnet
#define NETMAGIC 0xd0b4bef9 // umdnet

// Socket to hold our connection to satoshi client
int sd;
struct sockaddr_in addr;
int addr_len = sizeof(addr);

typedef enum{
    CB_MESSAGE_HEADER_NETWORK_ID = 0, /**< The network identidier bytes */
    CB_MESSAGE_HEADER_TYPE = 4, /**< The 12 character string for the message type */
    CB_MESSAGE_HEADER_LENGTH = 16, /**< The length of the message */
    CB_MESSAGE_HEADER_CHECKSUM = 20, /**< The checksum of the message */
} CBMessageHeaderOffsets;

static void print_hex(CBByteArray *str) {
    int i = 0;
    uint8_t *ptr = str->sharedData->data;
    for (; i < str->length; i++) printf("%02x", ptr[str->offset + i]);
    printf("\n");
}


static void
send_version() 
{
    CBByteArray *ip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);
    CBByteArray *ua = CBNewByteArrayFromString("cmsc417versiona", '\00');
    CBNetworkAddress * sourceAddr = CBNewNetworkAddress(0, ip, 0, CB_SERVICE_FULL_BLOCKS, false);
    int32_t vers = 70001;
    int nonce = rand();
    CBVersion * version = CBNewVersion(vers, CB_SERVICE_FULL_BLOCKS, time(NULL), &peer->base, sourceAddr, nonce, ua, 0);
    CBMessage *message = CBGetMessage(version);
    char header[24];
    memcpy(header + CB_MESSAGE_HEADER_TYPE, "version\0\0\0\0\0", 12);

    /* Compute length, serialized, and checksum */
    uint32_t len = CBVersionCalculateLength(version);
    message->bytes = CBNewByteArrayOfSize(len);
    len = CBVersionSerialise(version, false);
    if (message->bytes) {
        // Make checksum
        uint8_t hash[32];
        uint8_t hash2[32];
        CBSha256(CBByteArrayGetData(message->bytes), message->bytes->length, hash);
        CBSha256(hash, 32, hash2);
        message->checksum[0] = hash2[0];
        message->checksum[1] = hash2[1];
        message->checksum[2] = hash2[2];
        message->checksum[3] = hash2[3];
    }
    CBInt32ToArray(header, CB_MESSAGE_HEADER_NETWORK_ID, NETMAGIC);
    CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, message->bytes->length);
    // Checksum
    memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, message->checksum, 4);

    // Send the header
    send(sd, header, 24, 0);
    
    // Send the message
    printf("message len: %d\n", message->bytes->length);
    printf("checksum: %x\n", *((uint32_t *) message->checksum));
    send(sd, message->bytes->sharedData->data+message->bytes->offset, message->bytes->length, 0);
    print_hex(message->bytes);
}

static void
sockread_cb (EV_P_ struct ev_io *w, int revents)
{
    // Read a header, then read the whole message
    char header[24];
    recv(sd, header, 24, 0);
    printf("received header\n");
    if (*((uint32_t *)(header + CB_MESSAGE_HEADER_NETWORK_ID)) != NETMAGIC) {
        printf("wrong netmagic\n");
        return;
    }

    // Read the payload
    unsigned int length = *((uint32_t *)(header + CB_MESSAGE_HEADER_LENGTH));
    char *payload = (char *) malloc(length);
    socklen_t nread = 0;
    if (length) nread = recv(sd, payload, length, 0);
    if (nread != length) {
        printf("incomplete read %u %u \n", nread, length);
    } else {
        printf("read payload of %u bytes\n", nread);
    }
    
    // Receive message dispatch
    if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "version\0\0\0\0\0", 12)) {
        printf("received version header\n");
    }
    if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "verack\0\0\0\0\0\0", 12)) {
        printf("received verack header\n");
    }
    if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "ping\0\0\0\0\0\0\0\0", 12)) {
        printf("received ping header\n");
    }
    if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "pong\0\0\0\0\0\0\0\0", 12)) {
        printf("received pong header\n");
    }
    if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "inv\0\0\0\0\0\0\0\0\0", 12)) {
        printf("received inv header\n");
    }
    if (!strncmp(header+CB_MESSAGE_HEADER_TYPE, "addr\0\0\0\0\0\0\0\0", 12)) {
        printf("received addr header\n");
    }

    // Clean up
    free(payload);
}


// all watcher callbacks have a similar signature
// this callback is called when data is readable on stdin
static void
stdin_cb (EV_P_ struct ev_io *w, int revents)
{
    // Read a line
    char *line = 0;
    unsigned int len = 0;
    getline(&line, &len, stdin);
    char cmd[64] = {0}; // this will crash if you enter bad strings in stdin!
    sscanf(line, " %s ", cmd);

    // Main interactive command dispatch
    if (!strcmp(cmd, "ping")) {
        printf("you said ping\n");
    } else if (!strcmp(cmd, "help")) {
        printf("Commands: [cmd] [argument] ... \n");
        printf(" help : shows this message\n");
        printf(" quit : quits\n");
        printf(" version : sends version message client\n");
        printf(" ping : sends ping message to connected client\n");
        printf("\n");
    } else if (!strcmp(cmd, "version")) {
        printf("sending version\n");
        send_version();
    } else if (!strcmp(cmd, "quit")) {
        printf("Quitting...\n");
        ev_unloop(EV_A_ EVUNLOOP_ALL);
    } else if (!strcmp(cmd, "")) {
    } else {
        printf("command not recognized: '%s'\n", cmd);
    }
}

// another callback, this time for a time-out
static void
timeout_cb (EV_P_ struct ev_timer *w, int revents)
{
    ev_timer_init (&timeout_watcher, timeout_cb, 1.0, 0.);
    ev_timer_start (EV_A_ &timeout_watcher);
}

int
main (void)
{
    // use the default event loop unless you have special needs
    struct ev_loop *loop = ev_default_loop (0);
    printf("Type help for a list of commands\n");

    CBByteArray *ip = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 128, 8, 126, 25}, 16);
    CBNetworkAddress *peeraddr = CBNewNetworkAddress(0, ip, DEFAULT_PORT, CB_SERVICE_FULL_BLOCKS, false);
    peer = CBNewPeerByTakingNetworkAddress(peeraddr);

    // Create client socket
    if( (sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        return -1;
    }
    memset(&addr, sizeof(addr), 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEFAULT_PORT);
    addr.sin_addr.s_addr = (((((25 << 8) | 126) << 8) | 8) << 8) | 128;

    // Connect to server socket
    if(connect(sd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("Connect error");
        return -1;
    }

    printf("Connected to %s:%d\n", DEFAULT_IP, DEFAULT_PORT);
    
    // initialise an io watcher, then start it
    // this one will watch for stdin to become readable
    ev_io_init (&stdin_watcher, stdin_cb, /*STDIN_FILENO*/ 0, EV_READ);
    ev_io_start (loop, &stdin_watcher);

    // io watcher for the socket
    ev_io_init (&sock_watcher, sockread_cb, sd, EV_READ);
    ev_io_start (loop, &sock_watcher);

    // initialise a timer watcher, then start it
    ev_timer_init (&timeout_watcher, timeout_cb, 2.0, 0.);
    ev_timer_start (loop, &timeout_watcher);

    // now wait for events to arrive
    ev_loop (loop, 0);

    // unloop was called, so exit
    return 0;
}
