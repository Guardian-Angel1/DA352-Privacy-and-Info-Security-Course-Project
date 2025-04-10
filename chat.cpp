#include<pdcurses.h>
#include<iostream>
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
#include "diffie-hellman.h"
#include<stdlib.h>
#include<random>
#include<cstring>
#include<openssl/aes.h>
#include<openssl/err.h>
#include<openssl/pem.h>
#include<openssl/rsa.h>
#include<ctime>

using namespace std;
#pragma comment(lib, "ws2_32.lib")

#define HOST_NAME_MAX 255 // maximum length of hostname
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
    mt19937_64 rng(input); // seed the random number generator with the input
    uniform_int_distribution<unsigned char> dist(0,35); // distribution for bytes
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

template <typename T>
T max(T a, T b) { return (a > b) ? a : b; } // max macro for integers

// network stuff
int listensock; // listening socket
int sockfd; // socket for sending and receiving messages


// function to initialize the server network
// returns the socket file descriptor for the server
// or empty string on error
// [[noreturn]] is used to indicate that the function will not return normally
[[noreturn]] static void fail_exit(const char* msg); // 

[[noreturn]] static void error(const char* msg) {
    cerr << msg << " Error code: " << WSAGetLastError() << endl;
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

    cout << "Listening on port " << port << "....\n";

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
    cout << "Connection made, starting chat....\n";

    // at this point, we have a connection to the client
    // we should be able to send/rev on sockfd

    // HANDSHAKE SETUP
    // SENDING SYN+1, ACK
        // Server sends SYN+1, ACK back to Client when SYN is received
        char bufferSYN[11];
		recv(sockfd, bufferSYN, 10, 0);
		int bufferSYNp1 = atoi(bufferSYN) + 1;
		string bufferSYNp1_str = to_string(bufferSYNp1) + "ACK";
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



int initClientNet(const char* hostname, int port) {
    WSADATA wsaData;
    struct sockaddr_in serv_addr;
    struct addrinfo hints, *res;
    int result;

    // Initialize Winsock
    result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        error("WSAStartup failed");
    }

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == INVALID_SOCKET) {
        error("ERROR opening socket");
    }

    // Set up the hints for address resolution
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // Get server address information
    result = getaddrinfo(hostname, to_string(port).c_str(), &hints, &res);
    if (result != 0) {
        error("ERROR resolving hostname");
    }

    // Copy the address into sockaddr_in structure
    memset(&serv_addr, 0, sizeof(serv_addr)); // clear the structure
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port); // Set the port number

    // Assuming that getaddrinfo returned IPv4 address
    memcpy(&serv_addr.sin_addr.s_addr, &((struct sockaddr_in*)res->ai_addr)->sin_addr, sizeof(serv_addr.sin_addr.s_addr));

    // Connect to the server
    result = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if (result < 0) {
        error("ERROR connecting");
    }

    // at this point, we should be able to send/recv on sockfd
    // HANDSHAKE SETUP
    // SENDING SYN
        //  ISN Generation - 32 bit unsigned max
        srand(time(0));
        unsigned long ISN = rand() % 4294967294 +0; // generate random number between 0 and 4294967295


        // ISN is used as seed to generate IV for AES
        unsigned char* iv_temp = ivgen(ISN);
        memcpy(iv_val, iv_temp, 16); // copy IV to global variable

        // Format the ISN as a string and send it to the server
        string ISN_str = to_string(ISN);
        char const *ISN_char = ISN_str.c_str();
        send(sockfd, ISN_char, ISN_str.length(), 0); // send ISN to server

    // SENDING ACK
        // Client sends ACK back to Server when SYN+1, ACK is received
        char bufferACK[14]; 
        recv(sockfd, bufferACK, 14, 0); // receive SYN+1, ACK from server
        string bfA_str(bufferACK); // convert to string

        size_t index = bfA_str.find("ACK"); // find the index of "ACK"
        while(index != string::npos){
            bfA_str.erase(index, 3); // erase "ACK" from the string
            index = bfA_str.find("ACK", index); // find the next index of "ACK"
        }

        unsigned long bufferACK_int = stoi(bfA_str)-1; // convert string to integer

        if(bufferACK_int == ISN){
            send(sockfd, "ACK", 3, 0);
        }
        else{
            error("Client failed to receive SYN+1, ACK from server");
        }

    // DIFFIE-HELLMAN SETUP

        // genarate private and public keys
        init("dhparams.txt"); // initialize Diffie-Hellman parameters
        NEWZ(a);
        NEWZ(A);
        dhGen(a, A); // generate private and public keys

        // receive public key from server
        char buf[1024];
        recv(sockfd, buf, 1024, 0); // receive public key from server
        mpz_set(A_pk,A); // convert string to public key
        mpz_set(A_sk,a); // set secret key for A
        mpz_set_str(B_pk,buf,16); // set public key for B

        // send public key 
        char S[1024];
        mpz_get_str(S, 16, A); // convert public key to string
        send(sockfd, S, 1024, 0); // send public key to server

        // compute shared secret key
        const size_t klen = 256;
        unsigned char kA[klen]; // shared secret
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

static int shutdownNetwork() {
    // Gracefully shut down the socket (both send and receive)
    int result = shutdown(sockfd, SD_BOTH);
    if (result == SOCKET_ERROR) {
        fprintf(stderr, "Shutdown failed with error: %d\n", WSAGetLastError());
        return -1;  // Error handling
    }

    // Drain any remaining data from the socket (if any)
    char dummy[64];
    ssize_t r;
    do {
        r = recv(sockfd, dummy, sizeof(dummy), 0);
    } while (r != 0 && r != -1);

    // Close the socket
    result = closesocket(sockfd);
    if (result == SOCKET_ERROR) {
        fprintf(stderr, "Close socket failed with error: %d\n", WSAGetLastError());
        return -1;  // Error handling
    }

    // Clean up Winsock
    WSACleanup();

    return 0;  // Successfully shutdown
}

// end network stuff

[[noreturn]] static void fail_exit(const char *msg) {
    // Perform Winsock cleanup before exiting if necessary
    if(!isendwin()) endwin(); // End curses mode 
    WSACleanup();  // Clean up Winsock (make sure WSACleanup() is called only once)

    // Print the error message
    fprintf(stderr, "%s\n", msg);

    // Exit the program with failure status
    exit(EXIT_FAILURE);
}

#define CHECK(fn, ...) \
        do \
        if (fn(__VA_ARGS__) == ERR) \
        fail_exit(#fn"("#__VA_ARGS__") failed"); \
        while (false)

static bool should_exit = false;

// Message window
static WINDOW* msg_win;// window for messages
//  Separator line above the command window
static WINDOW* sep_win; // window for separator line
// Command window
static WINDOW* cmd_win; // window for command line input

// Input chararcter for readline
static unsigned char input;

static int readline_getc(FILE *dummy){
    return input; // return the input character
}

// if batch is set, don't draw immediately to real screen (use wnoutrefresh instead of wrefresh)

static void msg_win_redisplay(bool batch, const string & newmsg="", const string & sender="") {
    if(batch){
        wnoutrefresh(msg_win); // refresh the message window
    }
    else{
        wattron(msg_win, COLOR_PAIR(2)); // set color pair for message window
        wprintw(msg_win, "%s: ", sender.c_str()); // print message to window
        wattroff(msg_win, COLOR_PAIR(2)); // turn off color pair for message window
        wprintw(msg_win, "%s\n", newmsg.c_str()); // print message to window
        wrefresh(msg_win); // refresh the message window
    }
}

// compute HMAC for message	
char* hmac(char* msg){  
	char hmackey[256+1]; 
	strcpy(hmackey, hmac_key); // copy HMAC key to local variable
	unsigned char mac[64]; // buffer for HMAC
	memset(mac,0,64);
	char* message = msg; // message to be hashed
	HMAC(EVP_sha512(),hmackey,strlen(hmackey),(unsigned char*)message,strlen(message),mac,0); // compute HMAC for message
	char* temp = (char*) malloc(129); 

	for (size_t i = 0; i < 64; i++) {
		sprintf(&temp[i*2],"%02x",mac[i]);
	}
	return strdup(temp); // return HMAC as string
}

// encrypt message using AES CTR mode
unsigned char* ctr_encrypt(char* message, unsigned char* key, unsigned char* iv){  
    // AES encryption in CTR mode
    unsigned char* ct = (unsigned char*) malloc(512);
    memset(ct, 0, 512);
    size_t len = strlen(message);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); // create new cipher context
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, key, iv)){
        ERR_print_errors_fp(stderr); // print error if encryption fails
    }
    int nWritten;
    if (1 != EVP_EncryptUpdate(ctx, ct, &nWritten, (unsigned char*) message, len)) 
        ERR_print_errors_fp(stderr); 
    EVP_CIPHER_CTX_free(ctx);

    return ct; // return ciphertext
}

// decrypt message using AES CTR mode
unsigned char* ctr_decrypt(unsigned char* ct, unsigned char* key, unsigned char* iv, size_t length){
	// AES decryption in CTR mode
	unsigned char* pt = (unsigned char*) malloc(512);
	memset(pt, 0, 512);
	size_t ctlen = length;


	int nWritten;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctlen))
		ERR_print_errors_fp(stderr);
	
	
	return pt; // return plaintext
}


// thread function to receive messages from the socket
static void msg_typed(char *line)
{
	string mymsg;
	unsigned char* cipher;
	if (!line) {
		// Ctrl-D pressed on empty line
		should_exit = true;
		/* XXX send a "goodbye" message so other end doesn't
		 * have to wait for timeout on recv()? */
	} else {
		if (*line) {
			add_history(line);
			mymsg = string(line);
			transcript.push_back("me: " + mymsg);
			ssize_t nbytes;
			
			char* hmac_str = hmac(line);
			char* buf = (char*)malloc(strlen(hmac_str) + strlen(line) + 1);
			strcpy(buf, hmac_str);
			strcat(buf, line);

			int bufsize = strlen(buf);

			cipher = ctr_encrypt(buf, aes_key, iv_val);

			if ((nbytes = send(sockfd, (char *)cipher, bufsize, 0)) == -1)
				error("send failed");
		}
		pthread_mutex_lock(&qmx);
		mq.push_back({false,mymsg,"me",msg_win});
		pthread_cond_signal(&qcv);
		pthread_mutex_unlock(&qmx);
	}
}

// if batch is set, dont draw immediately to real screen (use wnoutrefresh instead of wrefresh)
static void cmd_win_redisplay(bool batch)
{
	int prompt_width = strnlen(rl_display_prompt, 128);
	int cursor_col = prompt_width + strnlen(rl_line_buffer,rl_point);

	werase(cmd_win);
	mvwprintw(cmd_win, 0, 0, "%s%s", rl_display_prompt, rl_line_buffer);
	/* XXX deal with a longer message than the terminal window can show */
	if (cursor_col >= COLS) {
		// Hide the cursor if it lies outside the window. Otherwise it'll
		// appear on the very right.
		curs_set(0);
	} else {
		wmove(cmd_win,0,cursor_col);
		curs_set(1);
	}
	if (batch)
		wnoutrefresh(cmd_win);
	else
		wrefresh(cmd_win);
}

static void readline_redisplay(void)
{
	pthread_mutex_lock(&qmx);
	mq.push_back({false,"","",cmd_win});
	pthread_cond_signal(&qcv);
	pthread_mutex_unlock(&qmx);
}

static void resize(void)
{
	if (LINES >= 3) {
		wresize(msg_win,LINES-2,COLS);
		wresize(sep_win,1,COLS);
		wresize(cmd_win,1,COLS);
		/* now move bottom two to last lines: */
		mvwin(sep_win,LINES-2,0);
		mvwin(cmd_win,LINES-1,0);
	}

	/* Batch refreshes and commit them with doupdate() */
	msg_win_redisplay(true);
	wnoutrefresh(sep_win);
	cmd_win_redisplay(true);
	doupdate();
}

static void init_ncurses(void)
{
	if (!initscr())
		fail_exit("Failed to initialize ncurses");

	if (has_colors()) {
		CHECK(start_color);
		CHECK(use_default_colors);
	}
	CHECK(cbreak);
	CHECK(noecho);
	CHECK(nonl);
	CHECK(intrflush, NULL, FALSE);

	curs_set(1);

	if (LINES >= 3) {
		msg_win = newwin(LINES - 2, COLS, 0, 0);
		sep_win = newwin(1, COLS, LINES - 2, 0);
		cmd_win = newwin(1, COLS, LINES - 1, 0);
	} else {
		// Degenerate case. Give the windows the minimum workable size to
		// prevent errors from e.g. wmove().
		msg_win = newwin(1, COLS, 0, 0);
		sep_win = newwin(1, COLS, 0, 0);
		cmd_win = newwin(1, COLS, 0, 0);
	}
	if (!msg_win || !sep_win || !cmd_win)
		fail_exit("Failed to allocate windows");

	scrollok(msg_win,true);

	if (has_colors()) {
		// Use white-on-blue cells for the separator window...
		CHECK(init_pair, 1, COLOR_WHITE, COLOR_BLUE);
		CHECK(wbkgd, sep_win, COLOR_PAIR(1));
		/* NOTE: -1 is the default background color, which for me does
		 * not appear to be any of the normal colors curses defines. */
		CHECK(init_pair, 2, COLOR_MAGENTA, -1);
	}
	else {
		wbkgd(sep_win,A_STANDOUT); /* c.f. man curs_attr */
	}
	wrefresh(sep_win);
}


static void deinit_ncurses(void)
{
	delwin(msg_win);
	delwin(sep_win);
	delwin(cmd_win);
	endwin();
}

static void init_readline(void)
{
	// Let ncurses do all terminal and signal handling
	rl_catch_signals = 0;
	rl_catch_sigwinch = 0;
	rl_deprep_term_function = NULL;
	rl_prep_term_function = NULL;

	// Prevent readline from setting the LINES and COLUMNS environment
	// variables, which override dynamic size adjustments in ncurses. When
	// using the alternate readline interface (as we do here), LINES and
	// COLUMNS are not updated if the terminal is resized between two calls to
	// rl_callback_read_char() (which is almost always the case).
	rl_change_environment = 0;

	// Handle input by manually feeding characters to readline
	rl_getc_function = readline_getc;
	rl_redisplay_function = readline_redisplay;

	rl_callback_handler_install("> ", msg_typed);
}

static void deinit_readline(void)
{
	rl_callback_handler_remove();
}


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat for DA352.\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";


int main(int argc, char *argv[])
{
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 1337;
	char hostname[HOST_NAME_MAX+1] = "localhost";
	hostname[HOST_NAME_MAX] = 0;
	bool isclient = true;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = false;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* NOTE: these don't work if called from cursesthread */
	init_ncurses();
	init_readline();
	/* start curses thread */
	if (pthread_create(&tcurses,0,cursesthread,0)) {
		fprintf(stderr, "Failed to create curses thread.\n");
	}
	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

	/* put this in the queue to signal need for resize: */
	redraw_data rd = {false,"","",NULL};
	do {
		int c = wgetch(cmd_win);
		switch (c) {
			case KEY_RESIZE:
				pthread_mutex_lock(&qmx);
				mq.push_back(rd);
				pthread_cond_signal(&qcv);
				pthread_mutex_unlock(&qmx);
				break;
				// Ctrl-L -- redraw screen
			// case '\f':
			// 	// Makes the next refresh repaint the screen from scratch
			// 	/* XXX this needs to be done in the curses thread as well. */
			// 	clearok(curscr,true);
			// 	resize();
			// 	break;
			default:
				input = c;
				rl_callback_read_char();
		}
	} while (!should_exit);

	shutdownNetwork();
	deinit_ncurses();
	deinit_readline();
	return 0;
}


/* Let's have one thread responsible for all things curses.  It should
 * 1. Initialize the library
 * 2. Wait for messages (we'll need a mutex-protected queue)
 * 3. Restore terminal / end curses mode? */

/* We'll need yet another thread to listen for incoming messages and
 * post them to the queue. */


void* cursesthread(void* pData)
{
	/* NOTE: these calls only worked from the main thread... */
	// init_ncurses();
	// init_readline();
	while (true) {
		pthread_mutex_lock(&qmx);
		while (mq.empty()) {
			pthread_cond_wait(&qcv,&qmx);
			/* NOTE: pthread_cond_wait will release the mutex and block, then
			 * reaquire it before returning.  Given that only one thread (this
			 * one) consumes elements of the queue, we probably don't have to
			 * check in a loop like this, but in general this is the recommended
			 * way to do it.  See the man page for details. */
		}
		/* at this point, we have control of the queue, which is not empty,
		 * so write all the messages and then let go of the mutex. */
		while (!mq.empty()) {
			redraw_data m = mq.front();
			mq.pop_front();
			if (m.win == cmd_win) {
				cmd_win_redisplay(m.resize);
			} else if (m.resize) {
				resize();
			} else {
				msg_win_redisplay(false,m.msg,m.sender);
				/* Redraw input window to "focus" it (otherwise the cursor
				 * will appear in the transcript which is confusing). */
				cmd_win_redisplay(false);
			}
		}
		pthread_mutex_unlock(&qmx);
	}
	return 0;
}
void* recvMsg(void*)
{
    size_t maxlen = 512;
    char msg[maxlen + 1];
    ssize_t nbytes;

    while (true) {
        nbytes = recv(sockfd, msg, maxlen, 0);
        if (nbytes == SOCKET_ERROR) {
            int err = WSAGetLastError();
            cerr << "recv failed. Error code: " << err << endl;

            // Optionally push to UI for debugging
            pthread_mutex_lock(&qmx);
            mq.push_back({false, "recv failed. Exiting thread.", "System", msg_win});
            pthread_cond_signal(&qcv);
            pthread_mutex_unlock(&qmx);

            should_exit = true;
            break;
        }

        if (nbytes == 0) {
            // Graceful close
            pthread_mutex_lock(&qmx);
            mq.push_back({false, "Connection closed by peer.", "System", msg_win});
            pthread_cond_signal(&qcv);
            pthread_mutex_unlock(&qmx);

            should_exit = true;
            break;
        }

        msg[nbytes] = 0;  // Null-terminate the buffer

        unsigned char* plaintxt = ctr_decrypt((unsigned char*)msg, aes_key, iv_val, nbytes);
        size_t msg_size = strlen((char*)plaintxt) - 128;

        char B_hmac_str[129];
        strncpy(B_hmac_str, (char*)plaintxt, 128);
        B_hmac_str[128] = '\0';

        char* message = new char[msg_size + 1];
        strncpy(message, (char*)plaintxt + 128, msg_size);
        message[msg_size] = '\0';

        char* A_hmac_str = hmac(message);

        if (CRYPTO_memcmp(A_hmac_str, B_hmac_str, 128) == 0) {
            pthread_mutex_lock(&qmx);
            mq.push_back({false, message, "Incoming", msg_win});
            pthread_cond_signal(&qcv);
            pthread_mutex_unlock(&qmx);
        } else {
            pthread_mutex_lock(&qmx);
            mq.push_back({false, "HMAC does not match!!", "System", msg_win});
            pthread_cond_signal(&qcv);
            pthread_mutex_unlock(&qmx);
        }

        delete[] message;
        free(plaintxt);
        free(A_hmac_str);
    }

    return nullptr;
}
