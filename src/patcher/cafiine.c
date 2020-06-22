#include "dynamic_libs/socket_functions.h"
#include "dynamic_libs/os_functions.h"

#include "utils/logger.h"
// do this the other way
#include <string.h>

static int recvwait(int sock, void *buffer, int len);
static int recvbyte(int sock);
static int sendwait(int sock, const void *buffer, int len);
static int sendbyte(int sock, unsigned char value);

static int cafiine_handshake(int sock);

#define CHECK_ERROR(cond) if (cond) { goto error; }

#define BYTE_NORMAL         0xff
#define BYTE_SPECIAL        0xfe
#define BYTE_OPEN           0x00
#define BYTE_READ           0x01
#define BYTE_CLOSE          0x02
#define BYTE_OK             0x03
#define BYTE_SETPOS         0x04
#define BYTE_STATFILE       0x05
#define BYTE_EOF            0x06
#define BYTE_GETPOS         0x07
#define BYTE_REQUEST        0x08
#define BYTE_REQUEST_SLOW   0x09
#define BYTE_HANDLE         0x0A
#define BYTE_DUMP           0x0B
#define BYTE_PING           0x0C

#define MAX_CLIENT 32

struct bss_t {
	int socket_fsa[MAX_CLIENT];
	void *pClient_fs[MAX_CLIENT];
	int socket_fs[MAX_CLIENT];
	volatile int lock;
};
 // This reads a pointer from 0x100000e4 to a BSS section.
 #define bss_ptr (*(struct bss_t **)0x100000e4)
 #define bss (*bss_ptr)

void GX2WaitForVsync(void);

// When a new file client is created, connect to the server.
void cafiine_connect(int *psock) {
	log_init("192.168.1.195");
	log_printf("Connecting to Cafiine Server.");
	// The address of the server to connect to.
	struct sockaddr_in addr;
	int ret;

	socket_lib_init();

	// Init a new IPv4 streaming TCP socket.
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	// Check if returned error.
	CHECK_ERROR(sock == -1);

	// Set the domain as IPv4.
	addr.sin_family = AF_INET;
	// Set the socket port to connect to.
	addr.sin_port = 7332;
	// Set the server IP.
	addr.sin_addr.s_addr = 0xC0A801C3;

	// Connect to the server through the socket.
	ret = connect(sock, (void *)&addr, sizeof(addr));
	CHECK_ERROR(ret < 0);
	// Connect to the Cafiine server.
	log_printf("Doing handshake using socket %i.", sock);
	ret = cafiine_handshake(sock);
	CHECK_ERROR(ret < 0);
	// BYTE_NORMAL is sent when the server is not interested in the current TID
	CHECK_ERROR(ret == BYTE_NORMAL);

	// Return a pointer to the socket used to connect to the server.
	*psock = sock;
	log_printf("Successfully connected to Cafiine at socket %i! Socket address: %0X", *psock, psock);
	log_deinit();
	return;
error:
log_printf("error.");
	if (sock != -1)
		socketclose(sock);
	*psock = -1;
	return;
}

void cafiine_disconnect(int sock) {
	// Check if the socket wasn't already disconnected.
	CHECK_ERROR(sock == -1);
	// Close the socket.
	socketclose(sock);
	// TODO: socket_lib_finish?
error:
	return;
}

static int cafiine_handshake(int sock) {
	// Return code.
	int ret;
	// Create a buffer of chars, Title IDs are 16 bytes long.
	unsigned char buffer[16];

	// Get the current running Title ID.
	long long title_id = OSGetTitleID();
	// Copy the Title ID into our buffer.
	memcpy(buffer, &title_id, 16);

	log_printf("Sending Title ID to server at socket %i...", sock);
	// Send the buffer over the socket to the server.
	ret = sendwait(sock, buffer, sizeof(buffer));
	// If length sent was invalid.
	CHECK_ERROR(ret < 0);
	// Recieve a byte from the server.
	log_printf("Getting command from server...");
	ret = recvbyte(sock);
	log_printf("Recieved: %0X", ret);
	CHECK_ERROR(ret < 0);
	return ret;
error:
	log_printf("Handshake with Cafiine server failed.");
	return ret;
}

// Sends a file open command to the Cafiine server.
int cafiine_fopen(int sock, int *result, const char *path, const char *mode, int *handle) {
	log_init("192.168.1.195");
	log_printf("FOpen.");
	log_printf("Socket is  %i", sock);
	while (bss.lock) GX2WaitForVsync();
	bss.lock = 1;

	CHECK_ERROR(sock == -1);

	int final_ret = 0;
	int ret;
	int len_path = 0;
	// get the lengths of the mode / path. idk?
	// it might be possible to just use sizeof
	while (path[len_path++]);
	int len_mode = 0;
	while (mode[len_mode++]);

	{
		// Make a buffer to hold the command byte, length of the file path, length
		// of the mode, file path itself, and file mode itself.
		log_printf("File Path: %s. Length of file path: %i. File Mode: %s. Length of file mode: %i.", path, len_path, mode, len_mode);
		char buffer[1 + 8 + len_path + len_mode];
		// Set the request as a file open.
		buffer[0] = BYTE_OPEN;
		// Write the file path length as an int, to the 1st index of the buffer.
		*(int *)(buffer + 1) = len_path;
		// Write the file path length as an int, to the 5ft index of the buffer.
		*(int *)(buffer + 5) = len_mode;
		// For every index of the file path.
		for (ret = 0; ret < len_path; ret++)
			// Write the current index of the path to the ending of the lengths +
			// index.
			buffer[9 + ret] = path[ret];
		// For every index of the file mode.
		for (ret = 0; ret < len_mode; ret++)
			// Write the current index of the path to the ending of the lengths +
			// the length of the path section + index.
			buffer[9 + len_path + ret] = mode[ret];

		log_printf("Buffer ready, sending to socket %i...", sock);
		// Send the open request over the socket.
		ret = sendwait(sock, buffer, 1 + 8 + len_path + len_mode);
	}
	log_printf("Sent %i bytes.", ret);

	// Check if the send operation wasn't successful.
	CHECK_ERROR(ret < 0);
	log_printf("Getting command byte from server at sock %i...", sock);
	// Recieve a byte from the server.
	ret = recvbyte(sock);
	log_printf("Recieved: %0X.", ret);
	// Invalid command.
	CHECK_ERROR(ret < 0);
	// It should be BYTE_OPEN, NORMAL would mean the server never got our command.
	CHECK_ERROR(ret == BYTE_NORMAL);

	// If the server wants to dump the file.
	if (ret == BYTE_REQUEST)
  {
      // return now with 1 as we want to dump the file
      final_ret = 1;
      goto quit;
  }
	// If the server wants to dump the file, but slowly.
  if (ret == BYTE_REQUEST_SLOW)
  {
      // return now with 2 as we want to dump the file slowly
      final_ret = 2;
      goto quit;
  }

	// Read the first response from the server, should just be 0.
	ret = recvwait(sock, result, 4);
	log_printf("Result code: %i.", ret);
	CHECK_ERROR(ret < 0);
	// Read the second response, the new file handle.
	ret = recvwait(sock, handle, 4);
	log_printf("File handle: %0X.", ret);
	CHECK_ERROR(ret < 0);

	bss.lock = 0;
	log_deinit();
	return 0;
quit:
    bss.lock = 0;
    return final_ret;
error:
	log_printf("error.");
	bss.lock = 0;
	return -1;
}

void cafiine_send_handle(int sock, int client, const char *path, int handle)
{
    while (bss.lock) GX2WaitForVsync();
    bss.lock = 1;

    CHECK_ERROR(sock == -1);

    // create and send buffer with : [cmd id][handle][path length][path data ...]
    {
        int ret;
        int len_path = 0;
        while (path[len_path++]);
        char buffer[1 + 4 + 4 + len_path];

        buffer[0] = BYTE_HANDLE;
        *(int *)(buffer + 1) = handle;
        *(int *)(buffer + 5) = len_path;
        for (ret = 0; ret < len_path; ret++)
            buffer[9 + ret] = path[ret];

        // send buffer, wait for reply
        ret = sendwait(sock, buffer, 1 + 4 + 4 + len_path);
        CHECK_ERROR(ret < 0);

        // wait reply
        ret = recvbyte(sock);
        CHECK_ERROR(ret != BYTE_SPECIAL);
    }

error:
    bss.lock = 0;
    return;
}

void cafiine_send_file(int sock, char *file, int size, int fd) {
    while (bss.lock) GX2WaitForVsync();
    bss.lock = 1;

    CHECK_ERROR(sock == -1);

    int ret;

    // create and send buffer with : [cmd id][fd][size][buffer data ...]
    {
        char buffer[1 + 4 + 4 + size];

        buffer[0] = BYTE_DUMP;
        *(int *)(buffer + 1) = fd;
        *(int *)(buffer + 5) = size;
        for (ret = 0; ret < size; ret++)
            buffer[9 + ret] = file[ret];

        // send buffer, wait for reply
        ret = sendwait(sock, buffer, 1 + 4 + 4 + size);

        // wait reply
        ret = recvbyte(sock);
        CHECK_ERROR(ret != BYTE_SPECIAL);
    }

error:
    bss.lock = 0;
    return;
}

int cafiine_fread(int sock, int *result, void *ptr, int size, int count, int fd) {
	while (bss.lock) GX2WaitForVsync();
	bss.lock = 1;

	CHECK_ERROR(sock == -1);

	int ret;
	char buffer[1 + 12];
	buffer[0] = BYTE_READ;
	*(int *)(buffer + 1) = size;
	*(int *)(buffer + 5) = count;
	*(int *)(buffer + 9) = fd;
	ret = sendwait(sock, buffer, 1 + 12);
	CHECK_ERROR(ret < 0);
	ret = recvbyte(sock);
	CHECK_ERROR(ret < 0);
	CHECK_ERROR(ret == BYTE_NORMAL);
	ret = recvwait(sock, result, 4);
	CHECK_ERROR(ret < 0);
	int sz;
	ret = recvwait(sock, &sz, 4);
	CHECK_ERROR(ret < 0);
	ret = recvwait(sock, ptr, sz);
	CHECK_ERROR(ret < 0);
	ret = sendbyte(sock, BYTE_OK);
	CHECK_ERROR(ret < 0);

	bss.lock = 0;
	return 0;
error:
	bss.lock = 0;
	return -1;
}

int cafiine_fclose(int sock, int *result, int fd) {
	while (bss.lock) GX2WaitForVsync();
	bss.lock = 1;

	CHECK_ERROR(sock == -1);

	int ret;
	char buffer[1 + 4];
	buffer[0] = BYTE_CLOSE;
	*(int *)(buffer + 1) = fd;
	ret = sendwait(sock, buffer, 1 + 4);
	CHECK_ERROR(ret < 0);
	ret = recvbyte(sock);
	CHECK_ERROR(ret < 0);
	CHECK_ERROR(ret == BYTE_NORMAL);
	ret = recvwait(sock, result, 4);
	CHECK_ERROR(ret < 0);

	bss.lock = 0;
	return 0;
error:
	bss.lock = 0;
	return -1;
}

int cafiine_fsetpos(int sock, int *result, int fd, int set) {
	while (bss.lock) GX2WaitForVsync();
	bss.lock = 1;

	CHECK_ERROR(sock == -1);

	int ret;
	char buffer[1 + 8];
	buffer[0] = BYTE_SETPOS;
	*(int *)(buffer + 1) = fd;
	*(int *)(buffer + 5) = set;
	ret = sendwait(sock, buffer, 1 + 8);
	CHECK_ERROR(ret < 0);
	ret = recvbyte(sock);
	CHECK_ERROR(ret < 0);
	CHECK_ERROR(ret == BYTE_NORMAL);
	ret = recvwait(sock, result, 4);
	CHECK_ERROR(ret < 0);

	bss.lock = 0;
	return 0;
error:
	bss.lock = 0;
	return -1;
}

int cafiine_fgetpos(int sock, int *result, int fd, int *pos) {
	while (bss.lock) GX2WaitForVsync();
	bss.lock = 1;

	CHECK_ERROR(sock == -1);

	int ret;
	char buffer[1 + 4];
	buffer[0] = BYTE_GETPOS;
	*(int *)(buffer + 1) = fd;
	ret = sendwait(sock, buffer, 1 + 4);
	CHECK_ERROR(ret < 0);
	ret = recvbyte(sock);
	CHECK_ERROR(ret < 0);
	CHECK_ERROR(ret == BYTE_NORMAL);
	ret = recvwait(sock, result, 4);
	CHECK_ERROR(ret < 0);
	ret = recvwait(sock, pos, 4);
	CHECK_ERROR(ret < 0);

	bss.lock = 0;
	return 0;
error:
	bss.lock = 0;
	return -1;
}

int cafiine_fstat(int sock, int *result, int fd, void *ptr) {
	while (bss.lock) GX2WaitForVsync();
	bss.lock = 1;

	CHECK_ERROR(sock == -1);

	int ret;
	char buffer[1 + 4];
	buffer[0] = BYTE_STATFILE;
	*(int *)(buffer + 1) = fd;
	ret = sendwait(sock, buffer, 1 + 4);
	CHECK_ERROR(ret < 0);
	ret = recvbyte(sock);
	CHECK_ERROR(ret < 0);
	CHECK_ERROR(ret == BYTE_NORMAL);
	ret = recvwait(sock, result, 4);
	CHECK_ERROR(ret < 0);
	int sz;
	ret = recvwait(sock, &sz, 4);
	CHECK_ERROR(ret < 0);
	if (ptr) {
		ret = recvwait(sock, ptr, sz);
		CHECK_ERROR(ret < 0);
	}

	bss.lock = 0;
	return 0;
error:
	bss.lock = 0;
	return -1;
}

int cafiine_feof(int sock, int *result, int fd) {
	while (bss.lock) GX2WaitForVsync();
	bss.lock = 1;

	CHECK_ERROR(sock == -1);

	int ret;
	char buffer[1 + 4];
	buffer[0] = BYTE_EOF;
	*(int *)(buffer + 1) = fd;
	ret = sendwait(sock, buffer, 1 + 4);
	CHECK_ERROR(ret < 0);
	ret = recvbyte(sock);
	CHECK_ERROR(ret < 0);
	CHECK_ERROR(ret == BYTE_NORMAL);
	ret = recvwait(sock, result, 4);
	CHECK_ERROR(ret < 0);

	bss.lock = 0;
	return 0;
error:
	bss.lock = 0;
	return -1;
}

static int recvwait(int sock, void *buffer, int len) {
	int ret;
	while (len > 0) {
		ret = recv(sock, buffer, len, 0);
		CHECK_ERROR(ret < 0);
		len -= ret;
		buffer += ret;
	}
	return 0;
error:
	return ret;
}

static int recvbyte(int sock) {
	unsigned char buffer[1];
	int ret;

	ret = recvwait(sock, buffer, 1);
	if (ret < 0) return ret;
	return buffer[0];
}

static int sendwait(int sock, const void *buffer, int len) {
	int ret;
	log_printf("Sending buffer of length %i to socket %i", len, sock);
	while (len > 0) {
		// Send the buffer to the socket with no flags. Ret is the number of bytes
		// sent to the server.
		ret = send(sock, buffer, len, 0);
		CHECK_ERROR(ret < 0);
		len -= ret;
		buffer += ret;
	}
	return 0;
error:
	log_printf("Error %i", ret);
	return ret;
}

static int sendbyte(int sock, unsigned char byte) {
	unsigned char buffer[1];

	buffer[0] = byte;
	return sendwait(sock, buffer, 1);
}
