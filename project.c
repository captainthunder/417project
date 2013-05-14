#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <CBVersion.h>

//#define NETMAGIC 0xffffffff // mainnet
//#define NETMAGIC 0x0709110B // testnet
#define NETMAGIC 0xd0b4bef9 // umdnet

#define HEADER_TYPE_VERSION "version\0\0\0\0\0"
#define HEADER_TYPE_VERACK "verack\0\0\0\0\0\0"
#define HEADER_TYPE_GETADDR "getaddr\0\0\0\0\0"
#define HEADER_TYPE_ADDR "addr\0\0\0\0\0\0\0\0"

typedef enum{
    CB_MESSAGE_HEADER_NETWORK_ID = 0, /**< The network identidier bytes */
    CB_MESSAGE_HEADER_TYPE = 4, /**< The 12 character string for the message type */
    CB_MESSAGE_HEADER_LENGTH = 16, /**< The length of the message */
    CB_MESSAGE_HEADER_CHECKSUM = 20, /**< The checksum of the message */
} CBMessageHeaderOffsets;

typedef struct
{
	char timestamp[4];
	char networkService[8];
	char ipAddress[16];
	char port[2];
} NetAddrMessage;

struct PeerNode
{
	int sockFd;
	NetAddrMessage* netAddr;
	struct PeerNode* next;
};

//TODO: Clean up memory for peerList
//TODO: Every time through the main loop, use getsockopt() to check if the
//sockets who are ready for writing are still alive?

typedef struct PeerNode PeerNode;
PeerNode* peerList = NULL;

fd_set readSockets;
fd_set writeSockets;
int maxFileDescriptor = 0; //The highest file descriptor across readSockets and writeSockets

void addToSets(int sockFd)
{
	FD_SET(sockFd, &readSockets);
	FD_SET(sockFd, &writeSockets);
	if (sockFd > maxFileDescriptor)
		maxFileDescriptor = sockFd;
}

void initPeer(PeerNode* peer, NetAddrMessage* netAddr)
{
	peer->netAddr = netAddr;
	peer->next = NULL;

	//Create a new non-blocking socket, add it to the read and write sets
	int sockFd;
	struct sockaddr_in sockAddr;
	sockFd = socket(PF_INET, SOCK_STREAM, 0);
	memset(&sockAddr, sizeof(sockAddr), 0);
	sockAddr.sin_family = AF_INET;
	unsigned short int portNum = (netAddr->port[0] << 8) | netAddr->port[1];
	sockAddr.sin_port = htons(portNum);
	sockAddr.sin_addr.s_addr = (((((netAddr->ipAddress[15] << 8) | netAddr->ipAddress[14]) << 8) | netAddr->ipAddress[13]) << 8) | 
					netAddr->ipAddress[12];
	int socketFlags = 0;
	socketFlags = fcntl(sockFd, F_GETFL, 0);
	fcntl(sockFd, F_SETFL, socketFlags | O_NONBLOCK);
	addToSets(sockFd);
	connect(sockFd, (struct sockaddr*) &sockAddr, sizeof(sockAddr)); //TODO: Check to make sure the only erorr is EINPROGRESS?
}

//Tests if two peers are equal by comparing IP address and port
bool peerEqual(PeerNode* p1, PeerNode* p2)
{
	return (memcmp(p1->netAddr->ipAddress, p2->netAddr->ipAddress, 16) == 0) &&
	       (memcmp(p1->netAddr->port, p2->netAddr->port, 2) == 0);
}

//Insert a peer into the global peerList
//TODO:  Limit on the number of peers we store?
void insertPeer(PeerNode* peer)
{
	if (peerList == NULL)
		peerList = peer;

	else
	{
		PeerNode* current = peerList;
		while (current->next != NULL)
		{
			//Can't insert duplicate peers
			if (peerEqual(current, peer))
				return;

			current = current->next;
		}

		if (peerEqual(current, peer))
			return;

		current->next = peer;
	}
}

//Finds a peer based on sockFD in the global peerList, returns NULL if
//not present.
//We might need this.
PeerNode* findPeer(int sockFd)
{
	PeerNode* current = peerList;
	while (current != NULL)
	{
		if (current->sockFd == sockFd)
			return current;

		current = current->next;
	}

	return NULL;
}

bool headerIsType(char* header, char* type)
{
	return !strncmp(header+CB_MESSAGE_HEADER_TYPE, type, 12);
}

unsigned int getMessageLengthFromHeader(char* header)
{
	return *((uint32_t *)(header + CB_MESSAGE_HEADER_LENGTH));
}

//Should probably be called before sending any bitcoin message
void buildHeaderAndChecksum(char* header, CBMessage* message, char* type)
{
	uint8_t hash[32];
	uint8_t hash2[32];
	memcpy(header + CB_MESSAGE_HEADER_TYPE, type, 12);
	CBInt32ToArray(header, CB_MESSAGE_HEADER_NETWORK_ID, NETMAGIC);
	if (message != NULL)
	{
		CBSha256(CBByteArrayGetData(message->bytes), message->bytes->length, hash);
        	CBSha256(hash, 32, hash2);
        	message->checksum[0] = hash2[0];
        	message->checksum[1] = hash2[1];
        	message->checksum[2] = hash2[2];
        	message->checksum[3] = hash2[3];
        	CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, message->bytes->length);
        	memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, message->checksum, 4);
	}

	else
	{
		CBSha256("", 0, hash);
		CBSha256(hash, 32, hash2);
		memcpy(header + CB_MESSAGE_HEADER_CHECKSUM, hash2, 4);
		CBInt32ToArray(header, CB_MESSAGE_HEADER_LENGTH, 0);
	}
}

bool validateMessageChecksum(char* header, char* messageData)
{
	bool retv;
	char newHeader[24];
	CBMessage* message = CBNewMessageByObject();
	CBByteArray* byteArray = CBNewByteArrayWithData((uint8_t*)messageData, getMessageLengthFromHeader(header));
	CBInitMessageByData(message, byteArray);
	buildHeaderAndChecksum(newHeader, message, HEADER_TYPE_VERACK);
	retv = (message->checksum[0] == (uint8_t)header[CB_MESSAGE_HEADER_CHECKSUM] &&
		message->checksum[1] == (uint8_t)header[CB_MESSAGE_HEADER_CHECKSUM+1] &&
		message->checksum[2] == (uint8_t)header[CB_MESSAGE_HEADER_CHECKSUM+2] &&
		message->checksum[3] == (uint8_t)header[CB_MESSAGE_HEADER_CHECKSUM+3]);
	CBFreeMessage(message);
	return retv;
}

// send a version message to sockFd
// TODO: should probably make this take a peer instead
void versionMessage(int sockFd)
{
	char header[24];

	// TODO: need to send our actual source IP address eventually
	CBByteArray* ipAddress = CBNewByteArrayWithDataCopy((uint8_t [16]) {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);

	// TODO: also need to send version messages to other ip addresses
	CBByteArray* ipAddressKale = CBNewByteArrayWithDataCopy((uint8_t [16]){0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 128, 8, 126, 25}, 16);
	CBByteArray* userAgent = CBNewByteArrayFromString("awesomebitcoin", '\00');
	CBNetworkAddress* sourceIpAddr = CBNewNetworkAddress(0, ipAddress, 0, CB_SERVICE_FULL_BLOCKS, false);
	CBNetworkAddress* destIpAddr = CBNewNetworkAddress(0, ipAddressKale, 28333, CB_SERVICE_FULL_BLOCKS, false);
	int32_t versionNumber = 70001;
	int nonce = rand();
	CBVersion* version = CBNewVersion(versionNumber, CB_SERVICE_FULL_BLOCKS, time(NULL), destIpAddr, sourceIpAddr, nonce, userAgent, 0);
	CBMessage* message = CBGetMessage(version);
	uint32_t len = CBVersionCalculateLength(version);
    	message->bytes = CBNewByteArrayOfSize(len);
    	len = CBVersionSerialise(version, false);
    	if (message->bytes) 
		buildHeaderAndChecksum(header, message, HEADER_TYPE_VERSION);

	send(sockFd, header, 24, 0);
	send(sockFd, message->bytes->sharedData->data + message->bytes->offset, message->bytes->length, 0);

	//Always remember to free your memory!
	//CBFreeByteArray(message->bytes); this segfaults, maybe CBFreeVersion()
	//handles it?
	CBFreeByteArray(ipAddress);
	CBFreeByteArray(ipAddressKale);
	CBFreeByteArray(userAgent);
	CBFreeNetworkAddress(sourceIpAddr);
	CBFreeNetworkAddress(destIpAddr);
	CBFreeVersion(version);
}

void getaddrMessage(int sockFd)
{
	char header[24];
	buildHeaderAndChecksum(header, NULL, HEADER_TYPE_GETADDR);
	send(sockFd, header, 24, 0);
}

void verackMessage(int sockFd)
{
	char header[24];
	buildHeaderAndChecksum(header, NULL, HEADER_TYPE_VERACK);
	send(sockFd, header, 24, 0);
}

//Read a bitcoin message from a socket
//Allocates memory for the payload that must be freed by the caller
void readFromSocketNew(int sockFd, char* header, char** payload)
{
	//Read the header
	recv(sockFd, header, 24, 0);

	//Read the payload
	unsigned int length = getMessageLengthFromHeader(header);
	*payload = (char*) malloc(length);
	socklen_t bytesRead = 0;
	if (length)
	{
		while (bytesRead != length)
			bytesRead += recv(sockFd, (*payload) + bytesRead, length, 0);
	}
}

void testVersionMessage(int sockFd)
{
	char header[24];
	char* payload;
	versionMessage(sockFd);
	readFromSocketNew(sockFd, header, &payload);
	if (headerIsType(header, HEADER_TYPE_VERSION))
	{
		printf("Version header received\n");
		if (validateMessageChecksum(header, payload))
			printf("validation passed!\n");
		else printf("validation failed...\n");
	}

	free(payload);
	readFromSocketNew(sockFd, header, &payload);
	if (headerIsType(header, HEADER_TYPE_VERACK)) {
        	printf("received verack header\n");
    	}

	free(payload);
	verackMessage(sockFd);
}

void testGetaddrMessage(int sockFd)
{
	char header[24];
	char* payload;
	getaddrMessage(sockFd);
	readFromSocketNew(sockFd, header, &payload);
	if (headerIsType(header, HEADER_TYPE_ADDR))
	{
		printf("addr header received\n");
		if (validateMessageChecksum(header, payload))
                	printf("validation passed!\n");
                else printf("validation failed...\n");
	}

	free(payload);
}

//Reads the payload of an addr message and creates new peers
void processAddrMessage(char* payload)
{
	//First figure out the number of addresses in the message
	uint16_t numAddr = 0x0000;
	if ((uint8_t)payload[0] == 0xFD)
	{
		numAddr = (payload[1] << 8) | payload[2];
		payload += 3;
	}

	else 
	{
		numAddr = (uint8_t)payload[0];
		payload++;
	}

	//Now add them to the list of peers
	for (uint16_t i = 0; i < numAddr; ++i)
	{
		//Allocating new memory because we're going to free the
		//payload at the end in order to not leak the length bytes
		NetAddrMessage* netAddr = malloc(sizeof(NetAddrMessage));
		PeerNode* peer = malloc(sizeof(PeerNode));
		//Deletion of both these allocations will be handled by some
		//function that cleans the peerList
		netAddr = (NetAddrMessage*)payload;
		initPeer(peer, netAddr);
		insertPeer(peer);
		payload += 30;
	}
}

//Might change from taking a socket to a CBPeer, or maybe it will take both
void processMessage(char* header, char* payload, int sockFd)
{
	if (!validateMessageChecksum(header, payload))
	{
		printf("VALIDATION FAILED\n");
		return;
	}

	if (headerIsType(header, HEADER_TYPE_VERSION))
	{
		printf("Received version message\n");
		verackMessage(sockFd);
	}

	else if (headerIsType(header, HEADER_TYPE_VERACK))
	{
		printf("Received verack message\n");
	}

	else if (headerIsType(header, HEADER_TYPE_ADDR))
	{
		printf("Received addr message\n");
		processAddrMessage(payload);
	}

	free(payload);
}

void runTests(int sockFd)
{
	char header[24];
	char* payload;
	versionMessage(sockFd);
	readFromSocketNew(sockFd, header, &payload);
	processMessage(header, payload, sockFd);
	readFromSocketNew(sockFd, header, &payload);
	processMessage(header, payload, sockFd);
	getaddrMessage(sockFd);
	readFromSocketNew(sockFd, header, &payload);
	processMessage(header, payload, sockFd);
}

int main()
{
	int sockFd;
	struct sockaddr_in sockAddr;
	FD_ZERO(&readSockets);
	FD_ZERO(&writeSockets);
	sockFd = socket(PF_INET, SOCK_STREAM, 0);
	memset(&sockAddr, sizeof(sockAddr), 0);
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = htons(28333);
	sockAddr.sin_addr.s_addr = (((((25 << 8) | 126) << 8) | 8) << 8) | 128;
	if (connect(sockFd, (struct sockaddr*) &sockAddr, sizeof sockAddr) <0)
	{
		printf("connect error\n");
		exit(0);
	}

	runTests(sockFd);
}
