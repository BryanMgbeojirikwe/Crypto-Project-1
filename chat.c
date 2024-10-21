//Authors: Bryan Mgbeojirikwe, Tanzila Tabassum, Maimouna Traore

#define MAX_MESSAGE_SIZE 65536 // 64 KB or another appropriate value
#define MAX_PLAINTEXT_LENGTH 65536 // or any appropriate value, similar to MAX_MESSAGE_SIZE
#define HASH_LEN 32  // SHA256 produces 32 bytes of output
#define MAX_TRANSCRIPT_LENGTH 1024  // or any appropriate value

#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include <openssl/rand.h>
#include <openssl/aes.h>
#include "util.h"
#include <string.h>

#define AES_KEY_LENGTH 32 // 256-bit AES key
#define AES_BLOCK_SIZE 16 // Block size for AES
#define HMAC_LENGTH 32    // Length of HMAC-SHA256
#ifndef PATH_MAX
#define PATH_MAX 1024


#endif


static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */
unsigned char sharedSecret[32];
static pthread_t trecv;     /* wait for incoming messagess and post to queue */
ssize_t recvAll(int sockfd, void* buffer, size_t length);
void* recvMsg(void*);       /* for trecv */
unsigned char encryptionKey[AES_KEY_LENGTH];  // 256-bit encryption key
unsigned char hmacKey[HMAC_LENGTH];           // HMAC key (256 bits for SHA256)
static void printerror(const char *msg);

//===============================================================================================

// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
void hkdf_extract(const unsigned char *salt, size_t salt_len, 
                  const unsigned char *ikm, size_t ikm_len, 
                  unsigned char *prk) {
    if (salt == NULL) {
        unsigned char default_salt[HASH_LEN] = {0};
        salt = default_salt;
        salt_len = HASH_LEN;
    }
    HMAC(EVP_sha256(), salt, salt_len, ikm, ikm_len, prk, NULL);
}

// HKDF-Expand: Output = T(1) | T(2) | ... | T(n) (up to L bytes of output)
void hkdf_expand(const unsigned char *prk, size_t prk_len, 
                 const unsigned char *info, size_t info_len, 
                 unsigned char *okm, size_t okm_len) {
    unsigned int hash_len = HASH_LEN;
    unsigned int n = (okm_len + hash_len - 1) / hash_len;  // Number of rounds
    unsigned char t[HASH_LEN];
    unsigned char previous_t[HASH_LEN];
    unsigned int previous_len = 0;

    for (unsigned int i = 1; i <= n; i++) {
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx) printerror("Failed to create HMAC context");

        HMAC_Init_ex(ctx, prk, prk_len, EVP_sha256(), NULL);
        if (previous_len > 0) {
            HMAC_Update(ctx, previous_t, previous_len);  // T(i-1)
        }
        if (info != NULL) {
            HMAC_Update(ctx, info, info_len);  // info
        }
        unsigned char c = (unsigned char)i;
        HMAC_Update(ctx, &c, 1);  // i as a single byte

        HMAC_Final(ctx, t, &hash_len);
        HMAC_CTX_free(ctx);

        // Copy the result to okm
        size_t copy_len = (i == n) ? (okm_len - (i - 1) * hash_len) : hash_len;
        memcpy(okm + (i - 1) * hash_len, t, copy_len);

        // Save T(i) for the next round
        memcpy(previous_t, t, hash_len);
        previous_len = hash_len;
    }
}

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void printerror(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}
//=======================================================================================================================
static int initServerNet(int port)
{
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listensock < 0) printerror("ERROR opening socket");

    bzero((char*)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        printerror("ERROR on binding");

    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr*)&cli_addr, &clilen);
    if (sockfd < 0) printerror("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");

    // Step 1: Generate long-term and ephemeral key pairs
    dhKey serverLongTermKey, serverEphemeralKey;
    initKey(&serverLongTermKey);
    initKey(&serverEphemeralKey);
    dhGenk(&serverLongTermKey); // Generate long-term key
    dhGenk(&serverEphemeralKey); // Generate ephemeral key

    // Step 2: Send the server's public keys to the client
    serialize_mpz(sockfd, serverLongTermKey.PK);    // Send long-term public key
    serialize_mpz(sockfd, serverEphemeralKey.PK);   // Send ephemeral public key

    // Step 3: Receive the client's public keys
    dhKey clientLongTermKey, clientEphemeralKey;
    initKey(&clientLongTermKey);
    initKey(&clientEphemeralKey);
    deserialize_mpz(clientLongTermKey.PK, sockfd);  // Receive client's long-term public key
    deserialize_mpz(clientEphemeralKey.PK, sockfd); // Receive client's ephemeral public key

    // Step 4: Compute the shared secret using dh3Final()
    const size_t sharedKeyLen = 32; // Length of the shared secret key in bytes
    unsigned char tempSharedSecret[sharedKeyLen];
    dh3Final(serverLongTermKey.SK, serverLongTermKey.PK, serverEphemeralKey.SK, serverEphemeralKey.PK,
             clientLongTermKey.PK, clientEphemeralKey.PK, tempSharedSecret, sharedKeyLen);

    // Copy the shared secret into the global sharedSecret variable
    memcpy(sharedSecret, tempSharedSecret, sharedKeyLen);

    // Step 5: Derive separate encryption and HMAC keys from the shared secret using HKDF
    unsigned char prk[HASH_LEN];  // Pseudorandom Key (PRK)

    // HKDF-Extract: Derive PRK from the shared secret
    hkdf_extract(NULL, 0, tempSharedSecret, sharedKeyLen, prk);

    // HKDF-Expand: Derive encryption key (for AES encryption)
    hkdf_expand(prk, HASH_LEN, (unsigned char *)"encryption", strlen("encryption"), encryptionKey, AES_KEY_LENGTH);

    // HKDF-Expand: Derive HMAC key (for message authentication)
    hkdf_expand(prk, HASH_LEN, (unsigned char *)"hmac", strlen("hmac"), hmacKey, HMAC_LENGTH);

    // Step 6: Clean up sensitive data
    OPENSSL_cleanse(tempSharedSecret, sharedKeyLen); // Erase temporary shared secret
    OPENSSL_cleanse(prk, HASH_LEN);                  // Erase PRK

    // Clean up keys
    shredKey(&serverLongTermKey);
    shredKey(&serverEphemeralKey);
    shredKey(&clientLongTermKey);
    shredKey(&clientEphemeralKey);

    /*
        HERE IS THE TEST TO CONFIRM DIFFIE-HELLMAN IS WORKING FOR THE SERVER
        Uncomment for testing purposes:

        // After computing the shared secret in initClientNet() or initServerNet()
        printf("Shared secret (hex): ");
        for (int i = 0; i < sharedKeyLen; i++) {
            printf("%02x", sharedSecret[i]);
        }
        printf("\n");
    */

    return 0;
}
//=================================================================================================================================
static int initClientNet(char* hostname, int port)
{
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0) printerror("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        printerror("ERROR connecting");
    
    fprintf(stderr, "Connected to server on port %i...\n", port);

    // Step 1: Generate long-term and ephemeral key pairs
    dhKey clientLongTermKey, clientEphemeralKey;
    initKey(&clientLongTermKey);
    initKey(&clientEphemeralKey);
    dhGenk(&clientLongTermKey); // Generate long-term key
    dhGenk(&clientEphemeralKey); // Generate ephemeral key

    // Step 2: Receive the server's public keys
    dhKey serverLongTermKey, serverEphemeralKey;
    initKey(&serverLongTermKey);
    initKey(&serverEphemeralKey);
    deserialize_mpz(serverLongTermKey.PK, sockfd); // Receive server's long-term public key
    deserialize_mpz(serverEphemeralKey.PK, sockfd); // Receive server's ephemeral public key

    // Step 3: Send the client's public keys to the server
    serialize_mpz(sockfd, clientLongTermKey.PK);    // Send long-term public key
    serialize_mpz(sockfd, clientEphemeralKey.PK);   // Send ephemeral public key

    // Step 4: Compute the shared secret using dh3Final()
    const size_t sharedKeyLen = 32; // Length of the shared secret key in bytes
    unsigned char tempSharedSecret[sharedKeyLen];
    dh3Final(clientLongTermKey.SK, clientLongTermKey.PK, clientEphemeralKey.SK, clientEphemeralKey.PK,
             serverLongTermKey.PK, serverEphemeralKey.PK, tempSharedSecret, sharedKeyLen);

    // Copy the shared secret into the global sharedSecret variable
    memcpy(sharedSecret, tempSharedSecret, sharedKeyLen);

    // Step 5: Derive separate encryption and HMAC keys from the shared secret using HKDF
    unsigned char prk[HASH_LEN];  // Pseudorandom Key (PRK)

    // HKDF-Extract: Derive PRK from the shared secret
    hkdf_extract(NULL, 0, tempSharedSecret, sharedKeyLen, prk);

    // HKDF-Expand: Derive encryption key (for AES encryption)
    hkdf_expand(prk, HASH_LEN, (unsigned char *)"encryption", strlen("encryption"), encryptionKey, AES_KEY_LENGTH);

    // HKDF-Expand: Derive HMAC key (for message authentication)
    hkdf_expand(prk, HASH_LEN, (unsigned char *)"hmac", strlen("hmac"), hmacKey, HMAC_LENGTH);

    // Step 6: Clean up sensitive data
    OPENSSL_cleanse(tempSharedSecret, sharedKeyLen); // Erase temporary shared secret
    OPENSSL_cleanse(prk, HASH_LEN);                  // Erase PRK

    // Clean up keys
    shredKey(&clientLongTermKey);
    shredKey(&clientEphemeralKey);
    shredKey(&serverLongTermKey);
    shredKey(&serverEphemeralKey);

    /*
        HERE IS THE TEST TO CONFIRM DIFFIE-HELLMAN IS WORKING FOR THE CLIENT
        Uncomment for testing purposes:

        // After computing the shared secret in initClientNet() or initServerNet()
        printf("Shared secret (hex): ");
        for (int i = 0; i < sharedKeyLen; i++) {
            printf("%02x", sharedSecret[i]);
        }
        printf("\n");
    */

    return 0;
}
//=====================================================================================================================
static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";
//=========================================================================================================================
/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

//=================================================================================================================================
static uint32_t sequenceNumber = 0; // Global variable for tracking sequence number

static void encryptAndSendMessage(const unsigned char* sharedSecret, const char* plaintext) {
    size_t plaintextLen = strlen(plaintext);

    // Check plaintext length validity
    if (plaintextLen == 0 || plaintextLen > MAX_PLAINTEXT_LENGTH) {
        fprintf(stderr, "Invalid plaintext length.\n");
        return;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char* ciphertext = NULL;
    unsigned char hmac[HMAC_LENGTH];
    int ciphertextLen;

    // Step 1: Generate random IV
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        printerror("IV generation failed");
    }

    // Allocate memory for ciphertext and include sequence number
    size_t totalCiphertextSize = plaintextLen + sizeof(sequenceNumber); // Ensure space for sequence number
    ciphertext = malloc(totalCiphertextSize);
    if (!ciphertext) {
        printerror("Failed to allocate memory for ciphertext");
    }

    // Step 2: Add sequence number to the plaintext before encryption
    memcpy(ciphertext, &sequenceNumber, sizeof(sequenceNumber)); // Add sequence number
    memcpy(ciphertext + sizeof(sequenceNumber), plaintext, plaintextLen);
    plaintextLen += sizeof(sequenceNumber); // Update plaintext length to include sequence number

    // Step 3: Encrypt plaintext using AES in CTR mode
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(ciphertext);
        printerror("Failed to create encryption context");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, sharedSecret, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        printerror("Encryption initialization failed");
    }

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, ciphertext, plaintextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        printerror("Encryption failed");
    }
    ciphertextLen = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        printerror("Final encryption step failed");
    }
    ciphertextLen += len;
    EVP_CIPHER_CTX_free(ctx);

    // Step 4: Generate HMAC for the ciphertext
    HMAC(EVP_sha256(), sharedSecret, AES_KEY_LENGTH, ciphertext, ciphertextLen, hmac, NULL);

    // Step 5: Send message size, IV, ciphertext, and HMAC
    uint32_t netMessageSize = htonl(ciphertextLen);
    xwrite(sockfd, &netMessageSize, sizeof(netMessageSize)); // Send message size
    xwrite(sockfd, iv, AES_BLOCK_SIZE);                      // Send IV
    xwrite(sockfd, ciphertext, ciphertextLen);               // Send ciphertext
    xwrite(sockfd, hmac, HMAC_LENGTH);                       // Send HMAC

    // Increment sequence number for next message
    sequenceNumber++;

    // Clean up memory
    free(ciphertext);
}

//=================================================================================================================================

static void sendMessage(GtkWidget* w, gpointer data)
{
    char* tags[2] = {"self", NULL};
    tsappend("me: ", tags, 0);
    GtkTextIter mstart;
    GtkTextIter mend;
    gtk_text_buffer_get_start_iter(mbuf, &mstart);
    gtk_text_buffer_get_end_iter(mbuf, &mend);
    
    char* message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);

    // Check for NULL message
    if (message == NULL) {
        return;
    }

    size_t messageLen = strlen(message);
    
    // Ensure the message is within the valid length range
    if (messageLen == 0 || messageLen > MAX_PLAINTEXT_LENGTH) {
        fprintf(stderr, "Message is too long or empty.\n");
        free(message);
        return;
    }

    // Encrypt and send the message
    encryptAndSendMessage(sharedSecret, message);

    // Append the message to the transcript with a safety check
    if (messageLen <= MAX_TRANSCRIPT_LENGTH) {
        tsappend(message, NULL, 1);
    } else {
        fprintf(stderr, "Message too long to append to transcript.\n");
    }

    // Free the dynamically allocated message and reset the input buffer
    free(message);
    gtk_text_buffer_delete(mbuf, &mstart, &mend);
    gtk_widget_grab_focus(w);
}


static gboolean shownewmessage(gpointer msg)
{
    char* tags[2] = {"friend", NULL};
    char* friendname = "mr. friend: ";
    
    // Append the sender's name to the transcript
    tsappend(friendname, tags, 0);
    
    char* message = (char*)msg;
    size_t msgLen = strlen(message);

    // Check if the message length is within valid range
    if (msgLen > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "Received message is too long.\n");
        free(message);
        return FALSE;
    }

    // Append the received message to the transcript
    tsappend(message, NULL, 1);
    
    // Free the message as it's no longer needed
    free(message);
    
    return FALSE;
}


//==================================================================================================================================

static uint32_t lastSequenceNumber = 0; //Here we are tracking the last sequence received
static int decryptMessage(const unsigned char* sharedSecret, const unsigned char* iv, 
                          const unsigned char* ciphertext, size_t ciphertextLen, 
                          const unsigned char* receivedHmac, char* plaintext, size_t plaintextBufferSize) 
{
    // Step 1: Verify HMAC
    unsigned char computedHmac[HMAC_LENGTH];
    HMAC(EVP_sha256(), sharedSecret, AES_KEY_LENGTH, ciphertext, ciphertextLen, computedHmac, NULL);

    if (CRYPTO_memcmp(computedHmac, receivedHmac, HMAC_LENGTH) != 0) {
        fprintf(stderr, "HMAC verification failed.\n");
        return -1; // Integrity check failed
    }

    // Step 2: Decrypt the ciphertext using AES in CTR mode
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printerror("Failed to create decryption context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, sharedSecret, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        printerror("Decryption initialization failed");
    }

    int len;
    int plaintextLen = 0;
    unsigned char* fullPlaintext = malloc(ciphertextLen);
    if (!fullPlaintext) {
        printerror("Memory allocation for fullPlaintext failed");
    }

    if (EVP_DecryptUpdate(ctx, fullPlaintext, &len, ciphertext, ciphertextLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(fullPlaintext);
        printerror("Decryption failed");
    }
    plaintextLen += len;

    if (EVP_DecryptFinal_ex(ctx, fullPlaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(fullPlaintext);
        printerror("Final decryption step failed");
    }
    plaintextLen += len;
    EVP_CIPHER_CTX_free(ctx);

    // Step 3: Extract sequence number from decrypted message
    uint32_t receivedSequenceNumber;
    memcpy(&receivedSequenceNumber, fullPlaintext, sizeof(receivedSequenceNumber));

    // Step 4: Fix 1 - Allow the first message to go through if lastSequenceNumber is 0
    if (receivedSequenceNumber == 0 && lastSequenceNumber == 0) {
        lastSequenceNumber = receivedSequenceNumber;  // Allow first message, no replay check
    }
    // Step 5: Fix 2 - Regular replay attack check for subsequent messages
    else if (receivedSequenceNumber <= lastSequenceNumber) {
        fprintf(stderr, "Replay attack detected!\n");
        free(fullPlaintext);
        return -1;
    }

    // Update last valid sequence number
    lastSequenceNumber = receivedSequenceNumber;

    // Step 6: Copy decrypted message (without sequence number) to plaintext buffer
    size_t actualPlaintextLen = plaintextLen - sizeof(receivedSequenceNumber);
    if (actualPlaintextLen >= plaintextBufferSize) {
        fprintf(stderr, "Decrypted plaintext too large for buffer\n");
        free(fullPlaintext);
        return -1;
    }

    memcpy(plaintext, fullPlaintext + sizeof(receivedSequenceNumber), actualPlaintextLen);
    plaintext[actualPlaintextLen] = '\0';

    // Clean up
    free(fullPlaintext);
    return actualPlaintextLen; // Return length of decrypted message
}


    // if ((size_t)plaintextLen >= plaintextBufferSize) {
    //     EVP_CIPHER_CTX_free(ctx);
    //     fprintf(stderr, "Decrypted plaintext too large for buffer\n");
    //     return -1;
    // }

    // if (EVP_DecryptFinal_ex(ctx, (unsigned char*)plaintext + plaintextLen, &len) != 1) {
    //     EVP_CIPHER_CTX_free(ctx);
    //     printerror("Final decryption step failed");
    // }
    // plaintextLen += len;

    // if ((size_t)plaintextLen >= plaintextBufferSize) {
    //     EVP_CIPHER_CTX_free(ctx);
    //     fprintf(stderr, "Decrypted plaintext too large for buffer\n");
    //     return -1;
    // }

    // EVP_CIPHER_CTX_free(ctx);

    // // Null-terminate the plaintext
    // plaintext[plaintextLen] = '\0';

    // return plaintextLen; // Return the length of the decrypted message


//=============================================================================================================================

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
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

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
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
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}

    /* printf("Running Diffie-Hellman test...\n");
    test_diffie_hellman();

    printf("Running Encrypt/Decrypt test...\n");
    test_encrypt_decrypt();

    */ 

	gtk_main();

	shutdownNetwork();
	return 0;
}

//====================================================================================================================
/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void* arg) {
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char hmac[HMAC_LENGTH];
    ssize_t nbytes;
    uint32_t netMessageSize;
    size_t messageSize;

    while (1) {
        // Step 1: Receive the message size (always 4 bytes)
        nbytes = recvAll(sockfd, &netMessageSize, sizeof(netMessageSize));
        if (nbytes != sizeof(netMessageSize)) {
            printerror("Failed to receive message size");
            break;
        }

        // Convert messageSize from network byte order to host byte order
        messageSize = ntohl(netMessageSize);

        // Validate messageSize before allocating memory
        if (messageSize == 0 || messageSize > MAX_MESSAGE_SIZE) { // Define MAX_MESSAGE_SIZE appropriately
            fprintf(stderr, "Invalid message size: %zu bytes\n", messageSize);
            continue;
        }

        // Step 2: Receive the IV
        nbytes = recvAll(sockfd, iv, AES_BLOCK_SIZE);
        if (nbytes != AES_BLOCK_SIZE) {
            printerror("Failed to receive IV");
            break;
        }

        // Step 3: Allocate buffer for ciphertext based on message size
        unsigned char* ciphertext = malloc(messageSize);
        if (!ciphertext) {
            printerror("Failed to allocate memory for ciphertext");
            break;
        }

        // Step 4: Receive the ciphertext
        nbytes = recvAll(sockfd, ciphertext, messageSize);
        if (nbytes != (ssize_t)messageSize) {
            free(ciphertext);
            printerror("Failed to receive complete ciphertext");
            break;
        }

        // Step 5: Receive the HMAC
        nbytes = recvAll(sockfd, hmac, HMAC_LENGTH);
        if (nbytes != HMAC_LENGTH) {
            free(ciphertext);
            printerror("Failed to receive HMAC");
            break;
        }

        // Step 6: Allocate buffer for plaintext
        size_t plaintextBufferSize = messageSize + 1; // +1 for null terminator
        char* plaintext = malloc(plaintextBufferSize);
        if (!plaintext) {
            free(ciphertext);
            printerror("Failed to allocate memory for plaintext");
            break;
        }

        int plaintextLen = decryptMessage(sharedSecret, iv, ciphertext, messageSize, hmac, plaintext, plaintextBufferSize);
        if (plaintextLen < 0) {
            free(ciphertext);
            free(plaintext);
            fprintf(stderr, "Decryption failed or HMAC verification failed.\n");
            continue;
        }

        // Step 7: Null-terminate and display the message
        plaintext[plaintextLen] = '\0';
        g_main_context_invoke(NULL, shownewmessage, (gpointer)plaintext);

        free(ciphertext);
        // Note: Do not free plaintext here as it's passed to the GUI thread
    }
    return NULL;
}

// Implementation of recvAll function
ssize_t recvAll(int sockfd, void* buffer, size_t length) {
    size_t totalReceived = 0;
    ssize_t bytesReceived;

    while (totalReceived < length) {
        bytesReceived = recv(sockfd, (char*)buffer + totalReceived, length - totalReceived, 0);
        if (bytesReceived <= 0) {
            return bytesReceived; // Error or connection closed
        }
        totalReceived += bytesReceived;
    }
    return totalReceived;
}










//--------------------- TEST FUNCTIONS-------------------------------------------------------------

/*
void test_diffie_hellman()
{
    // Step 1: Generate long-term and ephemeral key pairs for both client and server
    dhKey clientLongTermKey, clientEphemeralKey;
    dhKey serverLongTermKey, serverEphemeralKey;

    initKey(&clientLongTermKey);
    initKey(&clientEphemeralKey);
    initKey(&serverLongTermKey);
    initKey(&serverEphemeralKey);

    dhGenk(&clientLongTermKey);  // Client long-term key
    dhGenk(&clientEphemeralKey); // Client ephemeral key
    dhGenk(&serverLongTermKey);  // Server long-term key
    dhGenk(&serverEphemeralKey); // Server ephemeral key

    // Step 2: Compute the shared secret for both client and server
    const size_t sharedKeyLen = 32; // Length of the shared secret key in bytes
    unsigned char clientSharedSecret[sharedKeyLen];
    unsigned char serverSharedSecret[sharedKeyLen];

    dh3Final(clientLongTermKey.SK, clientLongTermKey.PK, clientEphemeralKey.SK, clientEphemeralKey.PK,
             serverLongTermKey.PK, serverEphemeralKey.PK, clientSharedSecret, sharedKeyLen);

    dh3Final(serverLongTermKey.SK, serverLongTermKey.PK, serverEphemeralKey.SK, serverEphemeralKey.PK,
             clientLongTermKey.PK, clientEphemeralKey.PK, serverSharedSecret, sharedKeyLen);

    // Step 3: Compare the shared secrets
    if (memcmp(clientSharedSecret, serverSharedSecret, sharedKeyLen) == 0) {
        printf("Diffie-Hellman test passed. Both sides computed the same shared secret.\n");
    } else {
        printf("Diffie-Hellman test failed. Shared secrets do not match.\n");
    }

    // Clean up
    shredKey(&clientLongTermKey);
    shredKey(&clientEphemeralKey);
    shredKey(&serverLongTermKey);
    shredKey(&serverEphemeralKey);
}


//------------------------------------------------------------------------------------------------------------------


void test_encrypt_decrypt()
{
    // Sample plaintext
    const char *plaintext = "This is a test message.";
    size_t plaintextLen = strlen(plaintext);

    // Generate shared secret
    unsigned char sharedSecret[32] = {0x1, 0x2, 0x3, 0x4}; // Use a dummy shared secret for testing purposes

    // Encrypt the message
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char *ciphertext = malloc(plaintextLen + AES_BLOCK_SIZE); // Allocate enough space
    unsigned char hmac[HMAC_LENGTH];
    int ciphertextLen;

    // Step 1: Generate a random IV
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        printf("IV generation failed\n");
        return;
    }

    // Step 2: Encrypt the message
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create encryption context\n");
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, sharedSecret, iv) != 1) {
        printf("Encryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, plaintextLen) != 1) {
        printf("Encryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertextLen = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        printf("Final encryption step failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertextLen += len;
    EVP_CIPHER_CTX_free(ctx);

    // Step 3: Generate HMAC
    HMAC(EVP_sha256(), sharedSecret, AES_KEY_LENGTH, ciphertext, ciphertextLen, hmac, NULL);

    // Decrypt the message
    char decryptedText[MAX_PLAINTEXT_LENGTH];
    int decryptedLen = decryptMessage(sharedSecret, iv, ciphertext, ciphertextLen, hmac, decryptedText, MAX_PLAINTEXT_LENGTH);

    if (decryptedLen >= 0) {
        printf("Decryption successful: %s\n", decryptedText);
    } else {
        printf("Decryption failed.\n");
    }

    free(ciphertext);
}---------------------------------------TEST FUNCTION REPLAY ATTACK --------------------------------------------------

void testReplayAttack() {
    const unsigned char sharedSecret[AES_KEY_LENGTH] = "0123456789abcdef0123456789abcdef";
    const char* message = "Hello, this is a test message.";

    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char ciphertext[MAX_PLAINTEXT_LENGTH + sizeof(uint32_t)];  // Account for sequence number
    unsigned char hmac[HMAC_LENGTH];
    char plaintext[MAX_PLAINTEXT_LENGTH];
    int ciphertextLen;

    encryptAndSendMessage(sharedSecret, message);

    ciphertextLen = strlen(message) + AES_BLOCK_SIZE + sizeof(uint32_t);  // Adjust for the sequence number
    if (decryptMessage(sharedSecret, iv, ciphertext, ciphertextLen, hmac, plaintext, MAX_PLAINTEXT_LENGTH) < 0) {
        printf("Decryption failed for the first message.\n");
        return;
    }

    //Replay the same message (now this should fail here)
    printf("Testing replay attack:\n");
    if (decryptMessage(sharedSecret, iv, ciphertext, ciphertextLen, hmac, plaintext, MAX_PLAINTEXT_LENGTH) < 0) {
        printf("Replay attack successfully detected!\n");
    } else {
        printf("Replay attack failed to be detected!\n");
    }
}----------------------------------------TEST FUNCTION BUFFER OVERFLOW ------------------------------------------------------


void testBufferOverflow() {
    const unsigned char sharedSecret[AES_KEY_LENGTH] = "0123456789abcdef0123456789abcdef";
    char longMessage[MAX_PLAINTEXT_LENGTH + 10]; // here, this is longer than the allowed length
    memset(longMessage, 'A', sizeof(longMessage) - 1);
    longMessage[sizeof(longMessage) - 1] = '\0'; // Null-terminate

    printf("Testing buffer overflow prevention:\n");

    if (encryptAndSendMessage(sharedSecret, longMessage) < 0) {
        printf("Buffer overflow successfully prevented!\n");
    } else {
        printf("Buffer overflow failed to be detected!\n");
    }
}


*/
