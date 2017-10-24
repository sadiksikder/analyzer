//example: https://github.com/vedantk/gcrypt-example/blob/master/main.cc
#include <stdio.h>
#include <string.h>

#include "decrypt.h"

int main()
{
    size_t i;

    int ret = EXIT_FAILURE;
/*
   //magenta cloud decryption
    char sMaster[] = "5ab6491e31fd204336c332a65b5865815ddb29116657994d67898fbef59e56073a875de89ce8e729d175957cf2351e9b";
    char sClientRandom[] = "59e605c1aadfec39e33caa0bec636f17cea4979a34327543af50a4f71c2191d6";
    char sServerRandom[] = "d34b8c8427c75dcaa5047fc3db5a30c345a93c17bb4f39216fb4f4a4db0bdef6";
    char sIV[] = "e5f7dbeb47f927f10141fd299fab2ac4";
    //char sIV[] =   "bd0274e64e157ffcf7bfeef33ab3f26f";
    char sEncryptedData[] = "000000000000000148bd02306672bc0edff44ad1eadad53bcfbee5e6457efef135648d8763d47b336a8cbf41d3d2b71e168479822d03bff65a77098fe6fa1651fac4ee1e79b4b8e0c85602ed8b685cff22dc39973fac9635f77b0c4d4385e87f3589ac03c261ad74263889636575cf0f395eedcc448845848ef3c6107af8c44d611494b689c7f9ebf8c632c26cc7578a190d5034381295ccd5b8916ae4dfbcefca5fd3229903f5fe11a115a6ab6942464bb950e10c278946856a43fd62e24e975bad1b66843f0707f32991fd07c12fb956638ed54128adbef8434c54c417a41c84dec421303b75514d60fe928e";
*/

   // Sample info
   char sMaster[] = "99664d0b6ac4406e504b7264df00311e8e931f16faa662bfe24dfca1c615a1311fa860f35c1e650ba9c6475113d33c0d"; //96 bytes of HEXA-Encoded Master secret;
    char sClientRandom[] = "59de37694a2d7d01c0ed87eff797447d8f4e842fb63152f8cbc7b2d2523ffa3c"; //64 bytes of hex encoded client_random
    char sServerRandom[] = "8538dd04470a22e85ac2a2ec6cec030224e3c48cf9021be837c31d7c24892060"; //96 bytes of hex encoded server_random
    char sIV[] = "865009bca6027baaca469efc74c71854"; //last 16 bytes of Encrypted Handshark Message
    //server handshake message
   //char sIV[] = "a6b05af17724b5d4d071c8b20f0ec9ea";
   //Client POST original
 char sEncryptedData[] = "20d29ba7e2a6088c1e585fcdf998bc4780b6c0dd8e5fe77d9853c0b0c2b9b427ce327a58b85adb08b8e2a03cc158d2c242865aa23af7e097578e808a05da07bd7add8dc8565c8d53989513c97e06d1e7f9c50fbf858188f116a04778f25facb667f446a94b84d694fbd5257285720707b0de8999c4831672aeb08358db94e0e030b67077648b5dc10cbf83c062ee4c6a022a7020712ae26e96d8d8a929270383989564d17f6cd2e92879de7fe0550dffff006ebe735d464eafabb4021248cd2074cb42b9608c2401485971828a012bf3c9a1360996d490e2d7aa1417ec2c290a2c3f8ad09b75766e40f2042f1a267d1acc22ffceda11a62d287546a0e59e9da395156c0a3bb71f8ea3f81159ec72aec09c9417be77bc13ccde06d65f785a0cb8df22bd5a912fa0e43e3fb5dcecda8e7f72f5ee9ffccfd3aed680152ec9887754414e9722a1b2e564f0786224190a7784f11a809d76e04fc0c4bff5a43d808934da435fd1a87d93479586ff0813aebf5e67ba3947f1953211ad36921bfcadedba59c01c39d357bd25e0e41bee3ce53c6b611183cdd3ee28e91066a219cc71b41a36577526b57b4e445da3cd1e41239dad544c922c1acc9a23c9de6556b8812e87";
   //char sEncryptedData[] =  "";
   //server data HTTP 200 OK: unable to decrypt on server side message
//   char sEncryptedData[] = "5d3a112014580c0aeb80c764016b077cf18d0384a8789724b446207dc431cfa529723e2a1dcceb7d5194ff978de38fe22d6fafc04ac377e7f4c3663bc56726f15deef875a29da356206f0d7ab26aa73d41fae9b181f0bd77e317e9521b884ecc2e473f98666f982ff58f6b018daae439c501e93b77ee97bf6a62e5b695f2810659570266a701879a37b40c38ed33c63264e4e75fcb75c49e28c7f4acb646cb3144e01a5436455a2ee2eb91e38d80726ccdc1aa2f180f673dbfa4e42b1eee1c114fbaacbd0c41f0fe6cdf2b9613fde730008e0137943ef73d4c54aa3bce02327d8fd8a4e5509b21fc9149a0db8ede7d9e9110c79c1ea79cee94ef9864dbd074c8bb259582a7ef79054ccc5adaea4883505c1def9c2cd82e338d5052cd335f8ae785335f201004fa60dc4e5d4f5a89036def2752b6cfd96f771c5a36e053d53337fc2c743b4699823d5b59f68c1dd9f70504ff442ff9cad5e8d954e0c924676840fe44b27372054a17a26fbf7a06237d06212766c349ca830b52a0537cfc04acb755f40030546ab353ce95f7e8ffa7bf3806bf155936897e4afe37c2c514812738f14b8ac8ed9123af371dc0ec9c4066f96b3241de16685647b2bcbb6766f42ae56447966fbecc19499f44f91a4b47ec600b45c275cdb0cabeb58183b5ec49dd3fd4d057909af28098c6cf1befda5cd153541792443fe831f006f65ee623554c973ded3436ab8c8d06604b6598d0b3adef3bbd3c96ccb20a1d55b4fed115c68f2f5691037cd570ea9d4b0d85cab4bc459dd4322ffa2dc2d2178a66c23fffdd09774220b2c8a0144dfc506cacb657137e9b4906fe8a4d6c7fc54586b4b1070bf56f75a3e97b3e33a7b27949d1449302b3fb395056191323867170037a8ab1b8a9eb79e7e2d9c469f7d143fcc90e317e54a347cd9c81e8243627e9b40b5a74c368458acbdb530803327c82387eb240e91ae25f537d4938d162fac381075f8f6c962fc2480452a25b9e2699ae257d7c48c69f9d2844efe0ba8c4df75e33a1e46202198f97fe33988f0e0a98dfcc8d5f557bb709e28709ff2fe9dc9e1eb9f981c544ac016d740d28f202ebd8e81d480010d542fbde9586ca578b482dba78f3834fa0968dd5fb395896c618a5b19f0a246958e07ecd442c394cd2049a05dae6de31e5d4ed5adf34531d0d73fd6ed51db0acfae9d867a1d8bd8c9edc2cfc996277ec41b36809597a794885bcd9e883bb24d9b0b8";



/************************************************
 *
 * test purpose of first client random
 *
 * **********************************************/
    //printf("ou===t \n", out);
/*

    char sMaster[] ="f59722f9ba6cce1f44e86028a6786bc0a9839789723a90393687b27542613e6e77307d545f60a36bcbd44475a314c8d4";
    char sClientRandom[] = "59b25d45cc36754f8ee36633a63ec5ecd2e866683b7ccb24164d30e36b8b7358";
    char sServerRandom[] = "943967e38f5f206b4052b5be8d839333bd5eb3662edafbc0567e5b31f65aa215";
    char sIV[] ="37d1e0b3c56b35ab756d3a9dbf625bbe"; // client side encrypted handshake message
    //char sIV[] ="bf23fffd96f2496eb47cc70ee11a467d";//server side encrypted handshake message
    //HTTP post client side
    //char sEncryptedData[] = "8ef9b57e32311034263557f47462021884a8a9139bf55d0ac65a0698ea0530a2dfdabdfbb833a7442833e31669fb30f42880e28ca72eef7bbf2d0a899f0f4e407f84eb57e5d98917b33446c645a25af69e066c63fcab928358e0bf95aaf376fbaefd9af591e684597f897654db698cc5324d10a5fb6ec1a4c56518fcc69906151a31ca2458de2a05bb050fe697f1e76268b887576f5c6e822c3184d1e77d45bd983f846f3942f835005c826f6fab21c1268e92401387371f05cfb112f28849524e171135348eb02a90efe6e15e4200bdd5e87abbce200d8522eb52e33fdb6aba5a25388177e18f89ca52969a816e762b098965e509e8f5fc5a5eb46ec481bc8e929a37f5d0949bf00386812501dfeb40354971b5506284f07e1f61a36bbb9d091c5a1ec01352eff51cbbbe54e7f2a7891acb876e1a138f287659fb9e554d41c429382c2b651e07dfb49a74a4272369c1c209c09815325572a956132fc08a0a1f1655c4d374456e211ab55e461fb022efa7863cd79c9cabf2147196bec1ede1cf20fefb8b34397b623d3cd83b063bf08fa8697815f64eacc05e9a911f402f298962006f3b667a1f427e436963716d81aa";
    //HTTP server side
    char sEncryptedData[] ="dd148d7dd927b95655ea4391b54b1362b1cf518a6d8a3b9ae28a34534b822e5d833ef01749eafefeae5bc4689ec4a2fae9da4bac679ca9421727dd6a7fe00cd27a4905cca62227ab66c14e425c1fa0e05d7c507368c33e89f1ecca85a2cb0c5c5dbb1bae061f5f9f3a2f21de4383b24ea8b9ce5e674c7b0fd104a1fe3cbe8f84d6acc3e590eb6fc5c484ed7c283f2cc113348a68f717dee38ddcac69fcbac9508e1ad448d7d96c8ca070679151768eeebaea27a394472070a3b9e3cc3cb45bd1c2d412935996630ec9e342a1d1ff18c234f899f6373791210a483e7f5a2d86432ea099cb6b885de0a1e83293a6a99ec3012e043a62db7a2fbad3f12475a7159c066235845fd8f28040237f98feac67844a088cc54e71bb4fca21c2e3746af6d95f8e10e2173e35b4c947b1ae53456f9958eb16df4135e30d6211a8564b3f542c49d4d2ee4614c28549482183eb223451f8f35d7d801a3adb416463ec6e11624ac97d86b09ca21a2a8b53607df385af0ebb3dbb835988dd5a8d73d3ca1b094dba9005afe3d2bfc30c9767b2b1da8da211964b025fac48b040ed9064739fc1ffd7445a4b43a677c229f644bede8b4b22f7a96f55a0543b4763a80515b0bad25b1de668d3c054a3fc2117f795ad02312bd62223f1656363f469885577731a51b7bc40e562ef2e4e495e7aed6cfd94e08097b98d3fde30a3ce55c02086a09b7f6f233e9dbd368cb212757fcc90f6ae1045cff09449fd35c5452c62f7219864276ac6d28c3555ce20869582a6bcb245f8f96729aa7a5d28d1759b1896697645aa9f1bae3bc941556ab56fc998594f5b7eaee22aed9b296389cea6197d719f0d6a1d290a68d623df844eac6a093fb57f9d0b8402bd4301c07a36b3cd20235aac7e401a4733f2d818a28d67ce186933bb9288c88e8674a9a3608ca07efb59f0e80ed402c1b1b91751a938e3ee64702997117d36239f4890423c93a867d11d6358246c256fd6d4601d2943bb55b20b838d0b184ac6dd3812222e8ca9ec9b85bba06df21a358489b011630a25b90c1c6b8c9f7f8a0893c60b08dbd41d6e97abb269af1aa760e141de469df3910f84222a24eb187144d9caf937c088da74c1d56a29e74c8a78b2638071db53d4e0031ef6702ba7e127f0f503aeaa7e8454804f8a115c8455811297cc314b1c41cb0cc6b8afbbcd8d77b8564e5825806966572e4ff4fbfc99140a48b9da85bfd31de2258ffd310b1e8e24dea41abeafebedd39270b5362333e026b5ed427484764da40e9573200910438a37d83c2793d33607485118011fbf964719bdb10fca466437bebcc2f5b2544c151cea238ecab38b3627b2e9137262a3358a88dd350e1fbf0f1d111fc6c235";
*/

//upload 1und1 test
/*
    char sMaster[] = "4e1d78a2cf062d557c8c8aea49c0962925e088be35c9b5b25ba1f9cdd9e07d5491841741fb27fdeeba60135140a7212f";
    char sClientRandom[] = "59e61bac496e201bde84bc9d95cd96e3585e6f69e97750b977abcf4f0edfbd48";
    char sServerRandom[] = "50e3c3682783a344afcb30ff5e842f86c68491182cdfee3844030c1c8bb44902";
    char sIV[] = "38737c7d7edf2080402763516b2147b4";
    //client encrypted application data
    char sEncryptedData[] = "c80e14f9adc5d067e551f266080045000137871a4000400626e6c0a8b24fd5a54323b82401bb37e8fb4327d7e0908018013f8cea00000101080adc604e5410f228c517030300fe0000000000000001adf6ca836f690f1ffec8e12acb5f510dbef197166b423f64e44a56fc914da0b8d01cb211ce3c0c0e52f41a93776c5290b268b4919f5e0ec9f09488c381e9c49540e5dd32ba53a880483172be94460cd6b97099672a8d7338a5402247c714d9f8055480abdac7e44b56983a177ebd3b0caabac8eac7ae23de3c0f6b3c4971f9bb664472138ea22e4977295155084e56421563fed5bd9cf7c505fb0e9097a5353ef9490f89424ca604d77c29df5aff0d6151678228e09f7b3ffc995c4f72043ee3d3d097b7cddcbb7caab4e4bd852c049d5d5c3d3d45a1f6472c1a78c9fd2b01713eec2148cd7066af3f1f8e67e6cf7873611b7b4585cd";
*/



int from_server = 0; //in case of server parameter should be 1 and for client decryption "0"

// Sample info in proper format
    char * master = NULL;
    char * client_random = NULL;
    char * server_random = NULL;
    char * iv = NULL;
    char * encrypted = NULL;
    char * decrypted = NULL;

    size_t encrypted_size = strlen(sEncryptedData) / 2;
    size_t decrypted_size = encrypted_size;

    master = malloc(MASTER_SECRET_SIZE);
    client_random = malloc(CLIENT_RANDOM_SIZE);
    server_random = malloc(SERVER_RANDOM_SIZE);
    iv = malloc(strlen(sIV) / 2);
    encrypted = malloc(encrypted_size);
    decrypted = malloc(decrypted_size);



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
        fprintf(stderr, "Failed from_hex sEncryptedData\n");
        goto failed;
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
