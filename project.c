#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <CBVersion.h>

//#define NETMAGIC 0xf9beb4d9 // mainnet
//#define NETMAGIC 0x0709110B // testnet
#define NETMAGIC 0xd0b4bef9 // umdnet

#define HEADER_TYPE_VERSION "version\0\0\0\0\0"
#define HEADER_TYPE_VERACK "verack\0\0\0\0\0\0"
#define HEADER_TYPE_GETADDR "getaddr\0\0\0\0\0"
#define HEADER_TYPE_ADDR "addr\0\0\0\0\0\0\0\0"
#define HEADER_TYPE_PING "ping\0\0\0\0\0\0\0\0"
#define HEADER_TYPE_PONG "pong\0\0\0\0\0\0\0\0"

typedef enum{
    CB_MESSAGE_HEADER_NETWORK_ID = 0, /**< The network identidier bytes */
    CB_MESSAGE_HEADER_TYPE = 4, /**< The 12 character string for the message type */
    CB_MESSAGE_HEADER_LENGTH = 16, /**< The length of the message */
    CB_MESSAGE_HEADER_CHECKSUM = 20, /**< The checksum of the message */
} CBMessageHeaderOffsets;

typedef struct
{
	unsigned char timestamp[4];
	unsigned char networkService[8];
	unsigned char ipAddress[16];
	unsigned char port[2];
} NetAddrMessage;

struct PeerNode
{
	int sockFd;
	int socketFlags;
	bool initiatedByMe;
	bool newConnection;
	bool gotVersion;
	bool readyToGo;
	bool remove;
	NetAddrMessage* netAddr;
	struct PeerNode* next;
};

typedef struct PeerNode PeerNode;
PeerNode* peerList = NULL;
int peerLen = 0;

fd_set readSockets;
fd_set writeSockets;
int maxFileDescriptor = 0; //The highest file descriptor across readSockets and writeSockets

bool quit = false;
unsigned char pingZeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
time_t prevTime;
int listeningSocket = 0;
struct sockaddr_in localName;

void addToSets(int sockFd)
{
	FD_SET(sockFd, &readSockets);
	FD_SET(sockFd, &writeSockets);
	if (sockFd > maxFileDescriptor)
		maxFileDescriptor = sockFd;
}

unsigned short int getPort(NetAddrMessage* netAddr)
{
	return (netAddr->port[0] << 8) | netAddr->port[1];
}

void printNetAddr(NetAddrMessage* netAddr)
{
	unsigned short int port = getPort(netAddr);
	printf("%u.%u.%u.%u:%u", netAddr->ipAddress[12],
				 netAddr->ipAddress[13],
				 netAddr->ipAddress[14],
				 netAddr->ipAddress[15],
				 port);
}

void initPeer(PeerNode* peer, NetAddrMessage* netAddr, bool initiatedByMe)
{
	peer->netAddr = netAddr;
	peer->initiatedByMe = initiatedByMe;
	peer->newConnection = true;
	peer->readyToGo = false;
	peer->remove = false;
	peer->gotVersion = false;
	peer->next = NULL;

	//Create a new non-blocking socket, add it to the read and write sets
	int sockFd;
	struct sockaddr_in sockAddr;
	sockFd = socket(PF_INET, SOCK_STREAM, 0);
	memset(&sockAddr, sizeof(sockAddr), 0);
	sockAddr.sin_family = AF_INET;
	unsigned short int portNum = getPort(netAddr);
	sockAddr.sin_port = htons(portNum);
	sockAddr.sin_addr.s_addr = (((((netAddr->ipAddress[15] << 8) | netAddr->ipAddress[14]) << 8) | netAddr->ipAddress[13]) << 8) | 
					netAddr->ipAddress[12];
	int socketFlags = 0;
	socketFlags = fcntl(sockFd, F_GETFL, 0);
	peer->socketFlags = socketFlags;
	fcntl(sockFd, F_SETFL, socketFlags | O_NONBLOCK);
	peer->sockFd = sockFd;
	connect(sockFd, (struct sockaddr*) &sockAddr, sizeof(sockAddr)); //TODO: Check to make sure the only erorr is EINPROGRESS?
	printf("Attempting to conect to ");
	printNetAddr(netAddr);
	printf("\n");
}

//Tests if two peers are equal by comparing IP address and port
bool peerEqual(PeerNode* p1, PeerNode* p2)
{
	return (memcmp(p1->netAddr->ipAddress, p2->netAddr->ipAddress, 16) == 0) &&
	       (memcmp(p1->netAddr->port, p2->netAddr->port, 2) == 0);
}

void destructPeer(PeerNode* peer)
{
	free(peer->netAddr);
	free(peer);
}

//Insert a peer into the global peerList
void insertPeer(PeerNode* peer)
{
	if (peerLen == 500) //Max number of peers we store is 500
	{
		destructPeer(peer);
		return;
	}

	if (peerList == NULL)
	{
		peerLen++;
		peerList = peer;
	}

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
		peerLen++;
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

void versionMessage(PeerNode* peer)
{
	char header[24];

	// TODO: need to send our actual source IP address eventually
	CBByteArray* ipAddress = CBNewByteArrayWithDataCopy((uint8_t [16]) {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1}, 16);
	CBByteArray* ipAddressDest = CBNewByteArrayWithDataCopy(peer->netAddr->ipAddress, 16);
	CBByteArray* userAgent = CBNewByteArrayFromString("awesomebitcoin", '\00');
	CBNetworkAddress* sourceIpAddr = CBNewNetworkAddress(0, ipAddress, 0, CB_SERVICE_FULL_BLOCKS, false); //TODO: add the port we're listening on
	CBNetworkAddress* destIpAddr = CBNewNetworkAddress(0, ipAddressDest, getPort(peer->netAddr), CB_SERVICE_FULL_BLOCKS, false);
	int32_t versionNumber = 70001;
	int nonce = rand();
	CBVersion* version = CBNewVersion(versionNumber, CB_SERVICE_FULL_BLOCKS, time(NULL), destIpAddr, sourceIpAddr, nonce, userAgent, 0);
	CBMessage* message = CBGetMessage(version);
	uint32_t len = CBVersionCalculateLength(version);
    	message->bytes = CBNewByteArrayOfSize(len);
    	len = CBVersionSerialise(version, false);
    	if (message->bytes) 
		buildHeaderAndChecksum(header, message, HEADER_TYPE_VERSION);

	send(peer->sockFd, header, 24, 0);
	send(peer->sockFd, message->bytes->sharedData->data + message->bytes->offset, message->bytes->length, 0);
	printf("Sent version message to ");
	printNetAddr(peer->netAddr);
	printf("\n");

	//Always remember to free your memory!
	//CBFreeByteArray(message->bytes); this segfaults, maybe CBFreeVersion()
	//handles it?
	CBFreeByteArray(ipAddress);
	CBFreeByteArray(ipAddressDest);
	CBFreeByteArray(userAgent);
	CBFreeNetworkAddress(sourceIpAddr);
	CBFreeNetworkAddress(destIpAddr);
	CBFreeVersion(version);
}

void pingMessage(PeerNode* peer, unsigned char* nonce)
{
	char header[24];
	CBByteArray* nonceArray = CBNewByteArrayWithDataCopy(nonce, 8);
	CBMessage* message = CBNewMessageByObject();
	CBInitMessageByData(message, nonceArray);
	buildHeaderAndChecksum(header, message, HEADER_TYPE_PING);
	send(peer->sockFd, header, 24, 0);
	send(peer->sockFd, message->bytes->sharedData->data + message->bytes->offset, message->bytes->length, 0);
	printf("Sent ping message to ");
	printNetAddr(peer->netAddr);
	printf("\n");
	CBFreeMessage(message);
}

void getaddrMessage(PeerNode* peer)
{
	char header[24];
	buildHeaderAndChecksum(header, NULL, HEADER_TYPE_GETADDR);
	send(peer->sockFd, header, 24, 0);
	printf("Sent getaddr message to ");
	printNetAddr(peer->netAddr);
	printf("\n");
}

void verackMessage(PeerNode* peer)
{
	char header[24];
	buildHeaderAndChecksum(header, NULL, HEADER_TYPE_VERACK);
	send(peer->sockFd, header, 24, 0);
	printf("Sent verack message to ");
	printNetAddr(peer->netAddr);
	printf("\n");
}

//Read a bitcoin message from a socket
//Allocates memory for the payload that must be freed by the caller
//TODO: Program might hang if client goes down after transmitting header
//but before transmitting payload
//TODO: This will definitely behave poorly if the peer has closed and there are 0 bytes to be read
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
		//initPeer(peer, netAddr);
		//insertPeer(peer);
		//TODO: Don't insert peers yet because they may be buggy
		payload += 30;
	}
}

//TODO: Tighten up handshake?
void processMessage(char* header, char* payload, PeerNode* peer)
{
	if (!validateMessageChecksum(header, payload))
	{
		printf("VALIDATION FAILED\n");
		return;
	}

	if (headerIsType(header, HEADER_TYPE_VERSION))
	{
		printf("Received version message from ");
		printNetAddr(peer->netAddr);
		printf("\n");
		peer->gotVersion = true;
		verackMessage(peer);
	}

	if (!peer->gotVersion)
	{
		free(payload);
		return;
	}

	if (headerIsType(header, HEADER_TYPE_VERACK))
	{
		printf("Received verack message from ");
		printNetAddr(peer->netAddr);
		printf("\n");
		peer->readyToGo = true;
	}

	if (!peer->readyToGo)
	{
		free(payload);
		return;
	}

	if (headerIsType(header, HEADER_TYPE_ADDR))
	{
		printf("Received addr message from ");
		printNetAddr(peer->netAddr);
		printf("\n");
		processAddrMessage(payload);
	}

	else if (headerIsType(header, HEADER_TYPE_PONG))
	{
		printf("Received pong message from ");
		printNetAddr(peer->netAddr);
		printf("\n");
	}

	free(payload);
}

void sendMessage(char* buffer)
{
	if (strcmp(buffer, "version") == 0)
		versionMessage(peerList);

	else if (strcmp(buffer, "verack") == 0)
		verackMessage(peerList);

	else if (strcmp(buffer, "getaddr") == 0)
		getaddrMessage(peerList);

	else if (strcmp(buffer, "ping") == 0)
		pingMessage(peerList, pingZeros);

	else if (strcmp(buffer, "quit") == 0)
		quit = true;

	else printf("Unrecognized message %s\n", buffer);
}

//TODO: Write cleanPeerList()
void mainLoop()
{
	while (!quit)
	{
		char buffer[90];

		time_t curTime = time(NULL);
		if (curTime - prevTime >= 60)
			prevTime = 0; //Used as a flag to send ping messages

		///Set up fd_sets
		PeerNode* currentNode = peerList;
		FD_ZERO(&readSockets);
		FD_ZERO(&writeSockets);
		while (currentNode != NULL)
		{
			addToSets(currentNode->sockFd);
			currentNode = currentNode->next;
		}

		FD_SET(0, &readSockets); //Watch stdin

		//Immediately poll which sockets are available for reading and writing
		struct timeval myAwesomeTimeval;
		myAwesomeTimeval.tv_sec = 0;
		myAwesomeTimeval.tv_usec = 0;
		int ret = select(maxFileDescriptor + 1, &readSockets, &writeSockets, NULL, &myAwesomeTimeval);
		if (ret > 0)
		{
			if (FD_ISSET(0, &readSockets))
			{
				char buffer[90];
				scanf("%s", buffer);
				if (FD_ISSET(peerList->sockFd, &writeSockets))
					sendMessage(buffer);
			}

			//Sockets are ready
			PeerNode* currentNode = peerList;
			while (currentNode != NULL)
			{
				//If ready for writing, check if it's a new peer
				if (FD_ISSET(currentNode->sockFd, &writeSockets))
				{
					if (currentNode->newConnection)
					{
						currentNode->newConnection = false;
						int errCode = 0;
						socklen_t errLen = sizeof(errCode);
						getsockopt(currentNode->sockFd, SOL_SOCKET, SO_ERROR, &errCode, &errLen);
						if (errCode != 0)
						{
							//Connection failed
							currentNode->remove = true;
							printf("Failed to connect to ");
							printNetAddr(currentNode->netAddr);
							printf("\n");
							continue;
						}

						printf("Connected to ");
						printNetAddr(currentNode->netAddr);
						printf("\n");

						//Make the socket blocking again
						fcntl(currentNode->sockFd, F_SETFL, currentNode->socketFlags);

						//If we initiated the connection, we need to start the handshake
						if (currentNode->initiatedByMe)
							versionMessage(currentNode);
					}

					if (prevTime == 0)
						pingMessage(currentNode, pingZeros);
				}

				if (FD_ISSET(currentNode->sockFd, &readSockets))
				{
					char header[24];
					char* payload;
					readFromSocketNew(currentNode->sockFd, header, &payload);
					processMessage(header, payload, currentNode);
				}

				currentNode = currentNode->next;
			}

			//TODO: Clean peer list here
		}

		if (prevTime == 0)
			prevTime = time(NULL);
	}
}		

int main()
{
	char result[90];
	prevTime = time(NULL);
	listeningSocket = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in testAddr;
	memset(&testAddr, 0, sizeof(testAddr));
	testAddr.sin_family = AF_INET;
	testAddr.sin_addr.s_addr = inet_addr("128.8.126.25");
	testAddr.sin_port = htons(28333);
	connect(listeningSocket, (struct sockaddr*) &testAddr, sizeof(testAddr));
	socklen_t localNameLen = sizeof(localName);
	getsockname(listeningSocket, (struct sockaddr*) &localName, &localNameLen);
	close(listeningSocket);
	//Connect to Kale
	char netAddrKale[30] = {0x0, 0x0, 0x0, 0x0, //Timestamp
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, //Network service
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 128, 8, 126, 25, //IP address
				0x6E, 0xAD};
	PeerNode* kale = malloc(sizeof(PeerNode));
	NetAddrMessage* netAddr = malloc(sizeof(NetAddrMessage));
	netAddr = (NetAddrMessage*) netAddrKale;
	initPeer(kale, netAddr, true);
	insertPeer(kale);
	mainLoop();
}
