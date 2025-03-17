#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

#define NBIT 128

void printBN(char *msg, BIGNUM * a)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}

void hexToString(const char *hex, char *output) {
    if (hex == NULL || output == NULL) return; 

    size_t len = strlen(hex);
    if (len % 2 != 0) { 
        output[0] = '\0'; 
        return;
    }

    char temp[3] = {0}; 
    char *ptr = output;

    for (size_t i = 0; i < len; i += 2) {
        temp[0] = hex[i];
        temp[1] = hex[i + 1];
        *ptr = (char)strtol(temp, NULL, 16); 
        ptr++;
    }
    *ptr = '\0'; 
}

void stringToHex(const char *input, char *output) {
    while (*input) {
        sprintf(output, "%02X", (unsigned char)*input);
        input++;
        output += 2;
    }
    *output = '\0';
}

void task2(){
    //TASK 2
    char* plainText = "A top secret!";
    char hex_plainText[strlen(plainText)*2 + 1];
    stringToHex(plainText,hex_plainText);
    
    // printf("%s\n",hex_plainText);

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM* M = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* encrypted_m = BN_new();
    BIGNUM* check_message = BN_new();

    BN_hex2bn(&M, hex_plainText);
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_mod_exp(encrypted_m , M , e , n , ctx);
    printf("Task 2:\n");
    printBN("Encrypted message:" , encrypted_m);

    BN_mod_exp(check_message , encrypted_m , d , n , ctx);

    char* check_message_string = BN_bn2hex(check_message);
    char check_s[strlen(plainText)+1];

    hexToString(check_message_string,check_s);
    printf("check decrypting message: %s\n\n",check_s);

    OPENSSL_free(check_message_string);
    BN_CTX_free(ctx);
    BN_free(M);
    BN_free(e);
    BN_free(n);
    BN_free(d);
    BN_free(encrypted_m);
    BN_free(check_message);
}

void task3(){
    //TASK 3
    char *cipher_string = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F";
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* C = BN_new();
    BIGNUM* plainText_3 = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* d = BN_new();

    printf("Task 3:\n");
    BN_hex2bn(&C , cipher_string);
    BN_mod_exp(plainText_3 , C , d , n , ctx);
    printBN("Decrypt Message (Hex):",plainText_3);
    char* decrypt_hex = BN_bn2hex(plainText_3);
    char decrypt_message[strlen(decrypt_hex) + 1];
    hexToString(decrypt_hex,decrypt_message);
    printf("Decrypt message (string): %s\n",decrypt_message);

    BN_CTX_free(ctx);
    BN_free(C);
    BN_free(plainText_3);
    BN_free(n);
    BN_free(d);
    OPENSSL_free(decrypt_hex);


}

int main(){
    task2();
    task3();

    return 0;
}