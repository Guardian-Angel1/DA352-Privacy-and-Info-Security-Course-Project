#include<pdcurses.h>
#include<iostream>
#include "diffie-hellman.h"
#include<readline/history.h>
#include<readline/readline.h>
#include<stdio.h>
#include<stdlib.h>
#include<sys/types.h>
#include<winsock2.h>
#include<ws2tcpip.h>
#include<openssl/sha.h>
#include<openssl/evp.h>
#include<openssl/hmac.h>
#include<string.h>
#include<getopt.h>
#include<string>
#include<openssl/rand.h>
#include<deque>
#include<pthread.h>
#include<utility>
#include<stdlib.h>
#include<random>
#include<cstring>
#include<openssl/aes.h>
#include<openssl/err.h>
#include<openssl/pem.h>
#include<openssl/rsa.h>
#include<ctime>

using namespace std;

// public and secret keys for A and B
mpz_t A_pk;
mpz_t B_pk;
mpz_t A_sk;

// Diffie-Hellman 
char hmac_key[256+1]; // 1 is added to the end of the string for null termination
unsigned char aes_key[256+1]; // 1 is added to the end of the string for null termination
// IV (initialization vector) for AES encryption generated via SYN request
unsigned char iv_val[16+1]; // AES block size is 16 bytes


static pthread_t trecv; // wait for incoming messages and post to queue
void *recvMsg(void*); // thread function to receive messages
static pthread_t tcurses; // setup curses and draw messages from queue
void *cursesthread(void*); // for tcurses

/* tcurses will get a queue full of these and redraw the appropriate windows */
struct redraw_data{
    bool resize; // true if the window has been resized
    string msg; // message to display
    string sender; // sender of the message
    WINDOW* win; // window to draw in 
};

static deque<redraw_data> mq; // messages and resizes yet to be drawn;
// manage access to message queue
static pthread_mutex_t qmx = PTHREAD_MUTEX_INITIALIZER; // mutex for message queue
static pthread_cond_t qcv = PTHREAD_COND_INITIALIZER; // condition variable for message queue

// different colors for different senders





// generate IV from SYN request
unsigned char* ivgen(unsigned long input){
    std::mt19937_64 rng(input); // seed the random number generator with the input
    std::uniform_int_distribution<unsigned char> dist(0,35); // distribution for bytes
    unsigned char* iv = new unsigned char[17]; // allocate memory for the IV

    for(int i=0;i<16;i++){
        int randomNum = dist(rng);
        if(randomNum < 10){
            iv[i] = '0' + randomNum; // convert to ASCII character
        }
        else{
            iv[i] = 'a' + (randomNum - 10); // convert to ASCII character
        }
    }
    return iv;

}

// record chat history as deque of strings
static deque<string> transcript; // chat history

#define max(a,b) ({typeof(a) _a = (a); type of(b) _b = (b); _a > _b ? _a : _b;}) // max macro for integers

// network stuff
int listensock; // listening socket
int sockfd; // socket for sending and receiving messages


// function to initialize the server network
// returns the socket file descriptor for the server
// or empty string on error
// [[noreturn]] is used to indicate that the function will not return normally
[[noreturn]] static void fail_exit(const char* msg); // 

[[noreturn]] static void error(const char* msg) {
    std::cerr << msg << " Error code: " << WSAGetLastError() << std::endl;
    fail_exit("");
}

int initServerNet(int port) {
    WSADATA wsaData;
    int reuse = 1;
    struct sockaddr_in serv_addr;

    // Initialize Winsock
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        error("WSAStartup failed");
    }

    // Create socket
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    if (listensock == INVALID_SOCKET) {
        error("ERROR opening socket");
    }

    // Set socket options
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));

    // Clear the server address structure
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;  // Set address family to IPv4
    serv_addr.sin_addr.s_addr = INADDR_ANY;  // Set address to any address
    serv_addr.sin_port = htons(port);  // Set port number

    // Bind the socket to the address
    if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
        error("ERROR on binding");
    }

    std::cout << "Listening on port " << port << "....\n";

    // Listen for incoming connections
    if (listen(listensock, 1) == SOCKET_ERROR) {
        error("ERROR on listen");
    }

    struct sockaddr_in cli_addr;
    int clilen = sizeof(cli_addr);  // The length of the client address structure

    // Accept incoming connection
    sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
    if (sockfd == INVALID_SOCKET) {
        error("ERROR on accept");
    }

    closesocket(listensock);  // Close the listening socket
    std::cout << "Connection made, starting chat....\n";

    // at this point, we have a connection to the client
    // we should be able to send/rev on sockfd

    // HANDSHAKE SETUP
    // SENDING SYN+1, ACK
        // Server sends SYN+1, ACK back to Client when SYN is received
        char bufferSYN[11];
		recv(sockfd, bufferSYN, 10, 0);
		int bufferSYNp1 = atoi(bufferSYN) + 1;
		string bufferSYNp1_str = std::to_string(bufferSYNp1) + "ACK";
		const char *bufferSYNp1_char = bufferSYNp1_str.c_str();

		/* Generate the same iv from ISN seed passed over*/
		int bufferSYNiv = atoi(bufferSYN);
		unsigned char* iv_temp = ivgen(bufferSYNiv);
		memcpy(iv_val, iv_temp, 16);

		// SYN recived should be within 32bit unsigned range
		if (bufferSYNp1 >= 0 && bufferSYNp1 <= 4294967295)  {
			// send(sockfd, bufferSYN, 11, 0);
			send(sockfd, bufferSYNp1_char, bufferSYNp1_str.length(), 0);
		} else {
			error("Server failed to recieve SYN from client");
		}

		char buff[10];
		recv(sockfd, buff, 10, 0);

    // DIFFIE-HELLMAN SETUP 
        // genarate private and public keys
        init("dhparams.txt"); // initialize Diffie-Hellman parameters
        NEWZ(a);
        NEWZ(A);
        dhGen(a, A);

        // send public key to client
        char S[1024];
        mpz_get_str(S, 16, A); // convert public key to string
        send(sockfd, S, 1024, 0); // send public key to client

        mpz_set(A_pk,A); // set public key for A
        mpz_set(A_sk,a); // set secret key for A

        // receive public key from client
        char buf[1024];
        recv(sockfd, buf, 1024, 0); // receive public key from client
        mpz_set_str(B_pk,buf,16); // convert string to public key

        // compute shared secret key
        const size_t klen = 256;
        unsigned char kA[klen]; //  shared secret
        dhFinal(A_sk,A_pk,B_pk,kA,klen); // compute shared secret   
        char dhf[512+1];
        for(size_t i=0;i<256; i++){
            sprintf(&dhf[i*2],"%02x",kA[i]); // convert shared secret to string
        }

        // split 512 bit key into 256 bit AES and HMAC keys
        memcpy(hmac_key, dhf, 256); // copy first 256 bits to AES key
        memcpy(aes_key, dhf + 256, 256); // copy last 256 bits to HMAC key

    return 0;

        

}

