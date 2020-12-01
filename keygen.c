/****************************************************************
 * Author: Brenden Smith
 * Description: Creates key of passed size+1
 * *************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

int main(int argc, char **argv) {
   srand(time(0));
   char randChar = ' ';
   int randInt;
   char *buffer;


   if (argc < 2) {
      printf("Error. Please provide keylength as parameter.\n");
      return 1;
   }

   int keylength = atoi(argv[1]) + 1;       //Get key size
   buffer = (char*) malloc(keylength);
   memset(buffer, '\0', keylength);

   int i = 0;
   for (i; i < keylength; i++) {
      //Get random number
      randInt = 27 * (rand() / (RAND_MAX + 1.0));
      randInt += 65;                    //Cast to ASCII range equivelant
      randChar = (char) randInt;        //Type cast out

      if (randChar == '[')		//Make undesireable character a space
         buffer[i] =  ' ';
      else
         buffer[i] = randChar;
   }
   buffer[keylength - 1] = '\n';	//Insert \n and then cap the string
   buffer[keylength] = '\0';

   printf(buffer);
   free(buffer);
   return 0;
}
