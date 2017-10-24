/*
 * TLS parsing
 * author: Samsuddin Sikder
 * email: sadiksikder@gmail.com
 *
 * site documentation: http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session
 * FILE HELP: https://www.programiz.com/c-programming/c-file-input-output
 *              https://www.tutorialspoint.com/cprogramming/c_pointers.htm
 */

#ifndef COMPARISION_H
#define COMPARISION_H

#endif // COMPARISION_H
#include <pcap.h>



// dumps raw memory in hex byte and printable split format
void tlsparser(const unsigned char *data_buffer, const unsigned int length) {
    unsigned char *data, byte, s;
    int i, j, c, k;
    int tcp_header_length, total_header_size, pkt_data_len;
    int rest = 16; //i need to print last 16-bytes
    int print  = length-rest ;
    const struct tcp_hdr *tcp_header;
    unsigned short tcp_dest_port;  // destination TCP port
    unsigned char client[32], server[32], buffer[length];



    for(i=0; i < length; i++) {
        byte = data_buffer[i];
        FILE *file=fopen("/home/ssikder/qt/analyzer/credent.txt","a");
        if (file == NULL)
        {
            printf("Error opening file!\n");
            exit(1);
        }
        /*
        printf("%02x ", data_buffer[i]);  // display byte in hex
        printf(" INT:%d ", data_buffer[i]);
        if(((i%16)==15) || (i==length-1)) {
            for(j=0; j < 15-(i%16); j++)
                printf("   ");
/*
          /*
         * content type: HANDSHAKE 0X16 i=0
         * VERSION: TLS 1.0 0x0301 or TLS 1.2 0x0303  i=1,2
         * Handshake protocol: CLIENT HELLO 0x01 i.e. i =5
         * VERSION: TLS 1.0 0x0301 or TLS 1.2 0x0303  i=9,10
         *
         */
        if(data_buffer[i]== 0x16 && data_buffer[i+1]== 0x03  && (data_buffer[i+2]==0x01 ||data_buffer[i+2]==0x03) && data_buffer[i+5]==0x01 && data_buffer[i+9]==0x03 && (data_buffer[i+10]==0x01 || data_buffer[i+10]==0x03 )){
            printf("\nHandshake Type: CLIENT HELLO (0x%02x)\n", data_buffer[i+5]);
            //which TLS version is using
            if( data_buffer[i+10]==0x01) printf("VERSION: TLS 1.0 (0x0301) \n", data_buffer[i+10] );
            else printf("VERSION: TLS 1.2 (0x0303)\n",data_buffer[i+10] );
            printf("length: %4d \n",data_buffer[i+8]);
            //fprintf(file,"\nlength: %4d", data_buffer[i+8]);
            printf("Random(32-bytes): ");
            fprintf(file,"\nClient_Random ");
            for(c=11;c<43;c++){
                client[32]=data_buffer[i+c];
                printf("%02x", client[32]);
                fprintf(file,"%02x", client[32]);
            }
            printf("\n");
            //exit(1);

        }

        /*
       * content type: HANDSHAKE 0X16 i=0
       * VERSION: TLS 1.0 0x0301 or TLS 1.2 0x0303  i=1,2
       * Handshake protocol: SERVER HELLO 0x01 i.e. i =5
       * VERSION: TLS 1.0 0x0301 or TLS 1.2 0x0303  i=9,10
       *
       */
        if(data_buffer[i]== 0x16 && data_buffer[i+1]== 0x03  && (data_buffer[i+2]==0x01 ||data_buffer[i+2]==0x03) && data_buffer[i+5]==0x02 && data_buffer[i+9]==0x03 && (data_buffer[i+10]==0x01 || data_buffer[i+10]==0x03 )){
            printf("\nHandshake Type: SERVER HELLO (0x%02x)\n", data_buffer[i+5]);
            //which TLS version is using
            if( data_buffer[i+10]==0x01) printf("VERSION: TLS 1.0 (0x0301) \n", data_buffer[i+10] );
            else printf("VERSION: TLS 1.2 (0x0300)\n",data_buffer[i+10] );
            printf("length: %4d \n",data_buffer[i+8]);
            //fprintf(file,"\nlength: %4d", data_buffer[i+8]);              //to print length in file
            printf("Random(32-bytes): ");
            fprintf(file,"\nServer_Random ");
            for(s=11;s<43;s++){
                //printf("%02x ",data_buffer[i+s]);
                server[32]=data_buffer[i+s];
                printf("%02x", server[32]);
                fprintf(file,"%02x", server[32]);
            }
            printf("\n");
        }
        /*
       * content type: Change Cipher Spec 0X16 i=0
       * VERSION: TLS 1.0 0x0301 or TLS 1.2 0x0303  i=1,2
       * length: i= 3-4
       * change cipher spec message i = 01
       *
       */
        if(data_buffer[i]== 0x14 && data_buffer[i+1]== 0x03  && (data_buffer[i+2]==0x01 ||data_buffer[i+2]==0x03) && data_buffer[i+3]==0x00 && data_buffer[i+4]==0x01 && data_buffer[i+5]==0x01 ){

            //            printf("\n[CLIENT SIDE]\n");
            //            if(data_buffer[i==0x14])printf("Change Cipher Spec:  (0x%02x)\n", data_buffer[i]);
            //            //which TLS version is using
            //            if( data_buffer[i+2]==0x01) printf("VERSION: TLS 1.0 (0x0301) \n", data_buffer[i+2] );
            //            else printf("VERSION: TLS 1.2 (0x0303)\n",data_buffer[i+2] );
            //            printf("length: %d \n",data_buffer[i+4]);
        }

        //if(data_buffer[i]== 0x16 && data_buffer[i+1]== 0x03  && (data_buffer[i+2]==0x01 ||data_buffer[i+2]==0x03) && data_buffer[i+3]==0x00 ){
        if (data_buffer[i]==0x16 && data_buffer[i+1]== 0x03  && (data_buffer[i+2]==0x01 ||data_buffer[i+2]==0x03) && data_buffer[i+3]== 0x00 && (data_buffer[i+4]== 0x30|| data_buffer[i+4]== 0x28)){
            printf("\n[CLIENT SIDE]\n");
            printf("Handshake Type: Encrypted Handshake Message (0x%02x)\n", data_buffer[i]);
            if( data_buffer[i+2]==0x01) printf("VERSION: TLS 1.0 (0x0301) \n", data_buffer[i+2] );
            else printf("VERSION: TLS 1.2 (0x0303)\n",data_buffer[i+2] );
            printf("length: %d \n",data_buffer[i+4]);
            printf("Encrypted Handshake Message: ");
            if (data_buffer[i+print])fprintf(file, "\n[CLIENT SIDE]-->IV ");

            for(print;print<length; print++){   //length is right other bug forms
                printf("%02x ",data_buffer[i+print]);
                fprintf(file,"%02x", data_buffer[i+print] );
                //                random[32]=data_buffer[i+print];
                //                printf("%02x ", random[32]);
                //                fprintf(file,"Client_Random %02x ", random[32]);
            }

            printf("\n");
        }

        // Magenta cloud download

        /*        if( tcp_dest_port== 443 && data_buffer[i]== 0x14 && data_buffer[i+1]== 0x03  && (data_buffer[i+2]==0x01 ||data_buffer[i+2]==0x03) && data_buffer[i+3]==0x00 && data_buffer[i+4]==0x01 && data_buffer[i+5]==0x01 ){
            //if(pkt_data_len ==data_buffer== 6){
            printf("\n[CLIENT SIDE]\n");
            if(data_buffer[i==0x14])printf("Change Cipher Spec:  (0x%02x)\n", data_buffer[i]);
            //which TLS version is using
            if( data_buffer[i+2]==0x01) printf("VERSION: TLS 1.0 (0x0301) \n", data_buffer[i+2] );
            else printf("VERSION: TLS 1.2 (0x0303)\n",data_buffer[i+2] );
        }

       if( data_buffer[i]== 0x16 && data_buffer[i+1]== 0x03  && (data_buffer[i+2]==0x01 ||data_buffer[i+2]==0x03) && data_buffer[i+3]==0x00 ){
             printf("\n[CLIENT SIDE]\n");
            printf("Encrypted Handshake Message: ");
            for(print;print<pkt_data_len; print++){
                printf("%02x ",data_buffer[i+print]);
            }
            printf("\n\n");
            exit(1);

        }
*/


        /* SERVER SIDE Change Cipher Spec & Encrypted Handshake Message
           * content type: Change Cipher Spec 0X14 i=0
           * VERSION: TLS 1.0 0x0301 or TLS 1.2 0x0303  i=1,2
           * length: i= 3-4
           * change cipher spec message i = 5
           *
           */
//TLS 1.0
        if(data_buffer[i]== 0x14 && data_buffer[i+1]== 0x03  && data_buffer[i+2]==0x01 && data_buffer[i+3]==0x00 && data_buffer[i+4]==0x01 && data_buffer[i+5]==0x01 && data_buffer[i+6]==0x16 && data_buffer[i+7]==0x03 && data_buffer[i+8]==0x01 && data_buffer[i+9]==0x00){
            printf("\n[SERVER SIDE]\n");
            printf("Handshake Type: Encrypted Handshake Message (0x%02x)\n", data_buffer[i+6]);
            if( data_buffer[i+2]==0x01) printf("VERSION: TLS 1.0 (0x0301) \n", data_buffer[i+2] );
            else printf("VERSION: TLS 1.2 (0x0303)\n",data_buffer[i+2] );

            printf("length: %d \n",data_buffer[i+10]);
            printf("Encrypted Handshake Message: ");
            if(data_buffer[i+print])fprintf(file, "\n[SERVER SIDE]-->IV ");
            for(print;print<length; print++){
                printf("%02x ",data_buffer[i+print]);
                fprintf(file,"%02x", data_buffer[i+print] );
            }

            printf("\n");

        }

//TLS 1.2
      else  if(data_buffer[i]== 0x14 && data_buffer[i+1]== 0x03  && data_buffer[i+2]==0x03  && data_buffer[i+3]==0x00 && data_buffer[i+4]==0x01 && data_buffer[i+5]==0x01 && data_buffer[i+6]==0x16 && data_buffer[i+7]==0x03 && data_buffer[i+8]==0x01 && data_buffer[i+9]==0x00){
            printf("\n[SERVER SIDE]\n");
            printf("Handshake Type: Encrypted Handshake Message (0x%02x)\n", data_buffer[i+6]);
            if( data_buffer[i+2]==0x01) printf("VERSION: TLS 1.0 (0x0301) \n", data_buffer[i+2] );
            else printf("VERSION: TLS 1.2 (0x0303)\n",data_buffer[i+2] );

            printf("length: %d \n",data_buffer[i+10]);
            printf("Encrypted Handshake Message: ");
            if(data_buffer[i+print])fprintf(file, "\n[SERVER SIDE]-->IV ");
            for(print;print<length; print++){
                printf("%02x ",data_buffer[i+print]);
                fprintf(file,"%02x", data_buffer[i+print] );
            }

            printf("\n");

        }


        /* content type:Application data 0x17 i=0
       * VERSION: TLS 1.0 0x0301 or TLS 1.2 0x0303  i=1,2
       * length: i= 3-4
       * i=from 5... start application data
       *
       */
        if(data_buffer[i]==0x17 && data_buffer[i+1]== 0x03  && (data_buffer[i+2]==0x01 ||data_buffer[i+2]==0x03 )){
            printf("\nContent Type: Application Data (0x%02x)\n", data_buffer[i]);
            if( data_buffer[i+2]==0x01) printf("VERSION: TLS 1.0 (0x0301) \n", data_buffer[i+2] );
            else printf("VERSION: TLS 1.2 (0x0303)\n",data_buffer[i+2] );
            printf("length: %d%d \n",data_buffer[i+3],data_buffer[i+4]);
            //fprintf(file,"\nlength: %d%d", data_buffer[i+3],data_buffer[i+4]);
            printf("Application Data: ");
            fprintf(file,"\nApplication_Data ");
            for(int data =5;data<length; data++){
                buffer[length]=data_buffer[i+data];
                printf("%02x ",buffer[length]);
                fprintf(file,"%02x ", buffer[length]);
                //printf("%02x ",data_buffer[i+data]);
                //fprintf(file,"%02x ", data_buffer[i+data]);
                //if(data_buffer[i]==23 && data_buffer[i+1]== 0x03  && (data_buffer[i+2]==0x01 ||data_buffer[i+2]==0x03 )) break;
            }

            printf("\n");

        }


        fclose(file);
    }//END of FOR LOOP





}

