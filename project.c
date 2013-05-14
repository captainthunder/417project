#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
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

bool headerIsType(char* header, char* type)
{
	return !strncmp(header+CB_MESSAGE_HEADER_TYPE, type, 12);
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

// send a version message to sockFd
// should probably make this take a CBPeer instead, and the function will
// make its own socket
void versionMessage(int sockFd)
{
	char header[24];

	// need to send our actual source IP address eventually
	CBByteArray* ipAddress = CBNewByteArrayWithDataCopy((uint8_t [16]) {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);

	// also need to send version messages to other ip addresses
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
	unsigned int length = *((uint32_t *)(header + CB_MESSAGE_HEADER_LENGTH));
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
		printf("Version header received\n");
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
		printf("addr header received\n");
	free(payload);
}

int main()
{
	int sockFd;
	struct sockaddr_in sockAddr;
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

	testVersionMessage(sockFd);
	testGetaddrMessage(sockFd);
}
