/*******************************************************************
 * Author: Brenden Smith
 * Description: Client program that sends the passed text and key
 *    to enc_server to be encrypted. This client recieves the
 *    cyphertext.
 * ****************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()

#define BUFF_SIZE 100000

// Error function used for reporting issues
void error(const char *msg) { 
   perror(msg); 
   exit(1); 
} 

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, int portNumber, 
      char* hostname){

   // Clear out the address struct
   memset((char*) address, '\0', sizeof(*address)); 

   // The address should be network capable
   address->sin_family = AF_INET;
   // Store the port number
   address->sin_port = htons(portNumber);

   // Get the DNS entry for this host name
   struct hostent* hostInfo = gethostbyname(hostname); 
   if (hostInfo == NULL) { 
      fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
      exit(0); 
   }
   // Copy the first IP address from the DNS entry to sin_addr.s_addr
   memcpy((char*) &address->sin_addr.s_addr, 
	 hostInfo->h_addr_list[0],
	 hostInfo->h_length);
}

/****************************************************************
 * Description: Sends plaintext and key to be encrypted. Recieves
 * 	the cipher from the server.
 * Parameters: Plain Text, Key, Destination Socket, Port Number
 * **************************************************************/
void sendText(char* plain, char* key, int socketFD, char* port) {
   int n;
   int dataSent;
   int dataRec;
   char* verify = malloc(sizeof(char));
   char* result = malloc(sizeof(char) * strlen(plain));
   
   //Send handshake to server
   dataSent = write(socketFD, "e", 1);
   if (dataSent < 1) {
      error("CLIENT: error verifying with server.");
   }

   dataRec = read(socketFD, verify, 1);
   if (dataRec < 0) {
      error("CLIENT: no handshake response from server.");
   }

   //Client not permitted access
   if (verify[0] != 'e') {
      fprintf(stderr, "Client not accepted by dec_server\n");
      exit(2);
   }

   //Send plaintext to server
   dataSent = write(socketFD, plain, strlen(plain));
   if (dataSent < strlen(plain)) {
      error("CLIENT: Plaintext was not sent.");
   }

   //Get verification that text is read
   memset(verify, 0, 1);
   dataRec = read(socketFD, verify, 1);
   if (dataRec < 0) {
      error("CLIENT: Did not recieve ping from server.");
   }

   //Send key to server
   dataSent = write(socketFD, key, strlen(key));
   if (dataSent < strlen(key)) {
      error("CLIENT: Failed to send key to server.");
   }

   //Get cyphertext from server
   dataRec = read(socketFD, result, strlen(plain));
   if (dataRec < 0) {
      error("CLIENT: Failed to receive cypher text");
   }
   
   // Cap the string for the betterment of man
   result[strlen(plain)] = '\0';
   printf("%s\n", result);
   return;

}

/***************************************************************
 * Description: Reads passed file into an array and sets length.
 * Parameters: File name, Result Length
 * *************************************************************/
char* processFile(char* file, int* length) {
   FILE *fp = fopen(file, "r+");
   char* buff = malloc(sizeof(char) * BUFF_SIZE);
   char* result;
   int i = 0;
   char ch;
   int ascii;
   if (fp == NULL) {
      error("CLIENT: Could not process file");
   }

   // Read until EOF or \n
   while ((ch = fgetc(fp)) != EOF) {
      
      if (ch == '\n') {
	 break;
      }

      if ((ch < 'A' || ch > 'Z') && ch != ' ') {
	 fprintf(stderr, "Bad character input.\n");
	 exit(1);
      }
      buff[i] = ch;
      i++;
   }

   //Cap the string to save the world
   buff[i] = '\0';
   fclose(fp);
   result = malloc(sizeof(char) * i);
   strncpy(result, buff, i);
   free(buff);

   *length = strlen(result);
   return result;
}

int main(int argc, char *argv[]) {
   int socketFD, charsWritten, charsRead;
   struct sockaddr_in serverAddress;
   char* plainText;
   char* key;
   char* portNumber;
   int textLen, keyLen;

   // Check usage & args
   if (argc < 4) { 
      fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); 
      exit(0); 
   } 

   portNumber = argv[4];

   // Create a socket
   socketFD = socket(AF_INET, SOCK_STREAM, 0); 
   if (socketFD < 0){
      error("CLIENT: ERROR opening socket");
   }

   // Set up the server address struct
   setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");

   // Connect to server
   if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){
      error("CLIENT: ERROR connecting");
   }

   // Process Files
   plainText = processFile(argv[1], &textLen);
   key = processFile(argv[2], &keyLen);

   // Check that key is adequate
   if (keyLen < textLen) {
      fprintf(stderr, "Key is shorter than plaintext.");
      exit(1);
   }
   // Start sending to server
   sendText(plainText, key, socketFD, portNumber);

   // Close the socket
   close(socketFD); 
   return 0;
}
