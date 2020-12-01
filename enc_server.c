/*****************************************************************
*Author: Brenden Smith
*Description: Daemon to monitor encoding requests from enc_client
* ***************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_SIZE 100000

// Error function used for reporting issues
void error(const char *msg) {
   perror(msg);
   exit(1);
} 

// Set up the address struct for the server socket
void setupAddressStruct(struct sockaddr_in* address, 
      int portNumber){

   // Clear out the address struct
   memset((char*) address, '\0', sizeof(*address)); 

   // The address should be network capable
   address->sin_family = AF_INET;
   // Store the port number
   address->sin_port = htons(portNumber);
   // Allow a client at any address to connect to this server
   address->sin_addr.s_addr = INADDR_ANY;
}


// Sends text of length len over the connected socket
void sendText(int sock, char* text, int len){
   int n;
   n = write(sock, text, len);
   if (n < 0) {
      error("SERVER: Error sending text.");
   }
}


/****************************************************************************
 * Description: Encrypts the passed text with the key and returns cyphertext.
 * Parameters: Plaintext, Cypher Key and length of plaintext
 * **************************************************************************/
char* encryptText(char* text, char* key, int len){
   int ascii;
   int textInt, keyInt;
   char *resultString = malloc(sizeof(char) * len);

   int i = 0;
   for (i; i < len; i++) {

      // Replace spaces to keep them included in the cypher
      if(text[i] == ' ') {
	 text[i] = '[';
      }
      if(key[i] == ' ') {
	 key[i] = '[';
      }      
      
      // Set A as the language's 0
      textInt = (int)text[i] - 'A';
      keyInt = (int)key[i] - 'A';

      // Create an encrypted character
      ascii = textInt + keyInt;
      ascii = ascii % 27;
      ascii += 65;

      // Put space back in or place encrypted character
      if (ascii == 91) {
	 resultString[i] = ' ';
      }else{
	 resultString[i] = ascii;
      }
   }
   // Cap the string
   resultString[len] = '\0';
   return resultString;
}




/*******************************************************************
 *Description: Recieves handshake, text and key from the client
 *Parameters: Connection socket, plaintext array, key array
 * ****************************************************************/
int getKeyAndText(int sock, char* text, char* key) {
   int len;
   char *verify = malloc(sizeof(char));
   int sent, rec;

   //Make sure that we are talking to enc_client
   rec = read(sock, verify, 1);
   if (rec < 0) {
      error("Error verifying response from client");
   }

   //Tell the client we are good to go
   sent = write(sock, "e", 1);
   if (sent < 0){ 
      error("SERVER: unable to handshake with client");
   }

   //Read plaintext from client
   len = read(sock, text, MAX_SIZE);
   if (len < 0) {
      error("ERROR: can't read plaintext");
   }

   //Tell client we are ready for key
   sent = write(sock, "e", 1);
   if (sent < 0) {
      error("SERVER: unable to talk with client.");
   }

   //Read key from client
   rec = read(sock, key, MAX_SIZE);
   if (rec < 0) {
      error("ERROR: can't read key");
   }
   return len;
}

int main(int argc, char *argv[]){
   int connectionSocket, charsRead;
   int port;
   int childPID;
   int dataSent;
   int plainTextLen;

   char *plainText = malloc(sizeof(char) * MAX_SIZE);
   char *key = malloc(sizeof(char) * MAX_SIZE);
   char* cypherText;
   char verify[1];

   struct sockaddr_in serverAddress, clientAddress;
   socklen_t sizeOfClientInfo = sizeof(clientAddress);

   // Check usage & args
   if (argc < 2) { 
      fprintf(stderr,"USAGE: %s port\n", argv[0]); 
      exit(1);
   } 

   // Create the socket that will listen for connections
   int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
   if (listenSocket < 0) {
      error("ERROR opening socket");
   }

   // Set up the address struct for the server socket
   setupAddressStruct(&serverAddress, atoi(argv[1]));

   // Associate the socket to the port
   if (bind(listenSocket, 
	    (struct sockaddr *)&serverAddress, 
	    sizeof(serverAddress)) < 0){
      error("ERROR on binding");
   }

   // Start listening for connetions. Allow up to 5 connections to queue up
   listen(listenSocket, 5); 

   // Accept a connection, blocking if one is not available until one connects
   while(1){
      // Accept the connection request which creates a connection socket
      connectionSocket = accept(listenSocket, 
	    (struct sockaddr *)&clientAddress, 
	    &sizeOfClientInfo); 
      if (connectionSocket < 0){
	 error("ERROR on accept");
      }

      //Fork a child process
      childPID = fork();

      if (childPID < 0) {
	 error("Fork failed");

      }else if (childPID == 0) {	//Child process
	 // Have server get text and key. Return text length.
	 plainTextLen = getKeyAndText(connectionSocket, plainText, key);

	 // Cypher the text
	 cypherText = encryptText(plainText, key, plainTextLen);

	 // Send the cyphertext back to the client
	 sendText(connectionSocket, cypherText, plainTextLen);

      }else{
	 //No need to fork
	 close(connectionSocket);
      }
   }
   // Close the listening socket
   close(listenSocket); 
   return 0;
}

