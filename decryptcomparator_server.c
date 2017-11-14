//example: https://github.com/vedantk/gcrypt-example/blob/master/main.cc
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "decrypt.h"

#define ClientRandomLenght 64+1
#define ServerRandomLenght 64+1
#define MasterLength 96+1
#define CredentialSize 15
#define IVSize 32+1

struct credentials{
    char sClientRandom[ClientRandomLenght];
    char sServerRandom[ServerRandomLenght];
    char sMaster[MasterLength];
    char* sApplicationData[10];
    short sApplicationDataSize;
    char sIV[IVSize];
    int flag;
};


decryptcomparator_server(FILE* credentials_file,FILE* log_file )
{
    size_t i;
    char c;  // To store a character read from file
     // open the credentials in read-only mode
     credentials_file = fopen("/home/ssikder/qt/analyzer/branch1.0/analyzer/credentialsserver.txt","r");
    // open the log file
    log_file = fopen("/home/ssikder/java/Magenta_Cloud/src/main/java/my_logfile.log","r");
    // check whether the files exist or not
    if(credentials_file == NULL || log_file == NULL ){
        printf("%s","File Not Found");
        return -1;
    }

    int ret = EXIT_FAILURE;
    char buffer[500];
    int credIndex = 0;
    struct credentials cred[CredentialSize];

    for(int i =0;i<CredentialSize;i++){
        cred[i].sApplicationDataSize = 0;
        cred[i].flag = 0;

    }

    for(c = getc(credentials_file); c!=EOF;c=getc(credentials_file)){
        if (c == '\n') // Increment count if this character is newline
                    c = c + 1;
    }
    printf("The file %s has %d lines\n ", credentials_file, c);

    // extracting data from credentials.txt file and storing ClientRandom & Server Random in a char* string
    while(fscanf(credentials_file,"%s\n",buffer) != EOF)
    {
        if(!strcmp(buffer,"Client_Random")){
            fscanf(credentials_file,"%s\n",buffer);
            if(cred[credIndex].flag){
                cred[credIndex].flag = 1;
                credIndex++;
            }
            cred[credIndex].flag = 1;
            strncpy(cred[credIndex].sClientRandom,buffer,ClientRandomLenght);
        }
        else if(!strcmp(buffer,"Server_Random")){
            fscanf(credentials_file,"%s\n",buffer);
            strncpy(cred[credIndex].sServerRandom,buffer,ServerRandomLenght);
        }
        else if(!strcmp(buffer,"Application_Data")){
            char buf[1];
            int count = 0;
            while(fread(buf,1,1,credentials_file)){
                if(buf[0] == '\n' || buf[0] == ' ') break;
                else
                    count++;
            }
            fseek(credentials_file, -1*count, SEEK_CUR);
            cred[credIndex].sApplicationData[cred[credIndex].sApplicationDataSize] = (char*)malloc((sizeof(char)*count)+1);
            fscanf(credentials_file,"%s\n",cred[credIndex].sApplicationData[cred[credIndex].sApplicationDataSize]);
            //printf("AppData:%s\n",cred[credIndex].sApplicationData[cred[credIndex].sApplicationDataSize]);
            cred[credIndex].sApplicationData[cred[credIndex].sApplicationDataSize][count] = '\0';
            cred[credIndex].sApplicationDataSize++;
        }
        else if(!strcmp(buffer,"[CLIENT")){
            fscanf(credentials_file,"%s\n",buffer);
            fscanf(credentials_file,"%s\n",buffer);
            strncpy(cred[credIndex].sIV,buffer,IVSize);
        }
    }
    // extracting data from credentials.txt file and storing ClientRandom & Server Random in a char* string
//exit(1);
    int checkFlag = 0;
    for(int i = 0; i <= credIndex; i++){
        rewind(log_file);
        while(fscanf(log_file,"%s\n",buffer) != EOF)
        {
            if(!strcmp(buffer,cred[i].sClientRandom)){
                fscanf(log_file,"%s\n",buffer);
                strncpy(cred[i].sMaster,buffer,MasterLength);
                checkFlag = 1;

                break;
            }
        }
        if(checkFlag){
            credIndex = i;
            break;
        }
    }
        // close the both files
    fclose(credentials_file);
    fclose(log_file);

 int from_server = 1; //in case of server parameter should be 1 and for client decryption "0"

    char* sClientRandom = cred[credIndex].sClientRandom;

    char* sServerRandom = cred[credIndex].sServerRandom;
    char* sMaster = cred[credIndex].sMaster;
    char* sIV = cred[credIndex].sIV;
    //printf("sClientRandom: \n",cred[credIndex].sClientRandom);

    // Sample info in proper format
    char * master = NULL;
    char * client_random = NULL;
    char * server_random = NULL;
    char * iv = NULL;
    char * encrypted = NULL;
    char * decrypted = NULL;
    char* sEncryptedData = NULL;
    master = malloc(MASTER_SECRET_SIZE);
    client_random = malloc(CLIENT_RANDOM_SIZE);
    server_random = malloc(SERVER_RANDOM_SIZE);
    iv = malloc(strlen(sIV) / 2);


    for(int z=0;z<cred[credIndex].sApplicationDataSize;z++)
     //for(int z=0;z<cred[credIndex].sApplicationData[cred[credIndex].sApplicationDataSize];z++)
    {
        sEncryptedData = cred[credIndex].sApplicationData[z];
         //sEncryptedData =cred[credIndex].sApplicationData[cred[credIndex].sApplicationDataSize];
        size_t encrypted_size = strlen(sEncryptedData) / 2;
        size_t decrypted_size = encrypted_size;
        encrypted = malloc(encrypted_size);
        decrypted = malloc(decrypted_size);
        if( z == 0){
            printf("Application2:%s\n",cred[credIndex].sApplicationData[cred[credIndex].sApplicationDataSize]);
           // exit(1);
        }


       if(!master || !client_random || !server_random || !encrypted || !decrypted || !iv)
        {
            fprintf(stderr, "Memory allocation issues\n");
            goto failed;
         }



        if(from_hex(sMaster, master) == -1)
        {
            fprintf(stderr, "Failed from_hex sMaster\n");
            goto failed;
        }

        if(from_hex(sClientRandom, client_random) == -1)
    {
        fprintf(stderr, "Failed from_hex sClientRandom\n");
        goto failed;
    }

    if(from_hex(sServerRandom, server_random) == -1)
    {
        fprintf(stderr, "Failed from_hex sServerRandom\n");
        goto failed;
    }

    if(from_hex(sEncryptedData, encrypted) == -1)
    {
        fprintf(stderr, "Failed from_hex sEncryptedData");
       // goto failed;
    }

    if(from_hex(sIV, iv) == -1)
    {
        fprintf(stderr, "Failed from_hex sIV\n");
        goto failed;
    }


    printf("Info encrypted_size=%d\n", encrypted_size);
    int iRet = decrypt(from_server, master, client_random, server_random, iv, encrypted, encrypted_size, decrypted, &decrypted_size);
    if(iRet == -1)
    {
        fprintf(stderr, "Problem decrypting\n");
        goto failed;
    }

    printf("Decrypted (size=%d):\n", decrypted_size);
    printf("==========================================================\n");
    for(i=0; i<decrypted_size; i++)
        printf("%c", (unsigned char)decrypted[i]);
    printf("\n==========================================================\n");
    for(i=0; i<decrypted_size; i++)
        printf("%0x ", (unsigned char)decrypted[i]);
    printf("\n==========================================================\n");
}
    ret = EXIT_SUCCESS;


failed:
    if(master)
        free(master);
    if(client_random)
        free(client_random);
    if(server_random)
        free(server_random);
    if(iv)
        free(iv);
    if(encrypted)
        free(encrypted);
    if(decrypted)
        free(decrypted);

    return ret;
}
