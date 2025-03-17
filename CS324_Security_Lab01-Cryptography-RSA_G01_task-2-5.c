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
void task2();
void task3();
void task4();
void task5();


int main(){
    task2();
    printf("\n");
    task3();
    printf("\n");
    task4();
    printf("\n");
    task5();
    printf("\n");
    return 0;
}

void task2(){
    //TASK 2
    const char* plainText = "A top secret!";
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
    printf("check decrypting message: %s\n",check_s);

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
    const char *cipher_string = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F";
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* C = BN_new();
    BIGNUM* plainText_3 = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* d = BN_new();
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

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
void task4(){
    const char* message = "I owe you $2000.";
    char hex_message[strlen(message)*2 + 1];
    stringToHex(message,hex_message);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* M = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* signature_2000 = BN_new();
    BIGNUM* signature_3000 = BN_new();
    
    BN_hex2bn(&M , hex_message);
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    BN_mod_exp(signature_2000, M , d , n , ctx);

    const char* message_modify = "I owe you $3000.";
    stringToHex(message_modify,hex_message);
    BN_hex2bn(&M , hex_message);
    BN_mod_exp(signature_3000, M , d , n , ctx);

    printf("Task 4:\n");
    printf("Signature (owe 2000$): ");
    BN_print_fp(stdout , signature_2000);
    printf("\nModify Signature (owe 3000$): ");
    BN_print_fp(stdout , signature_3000);
    printf("\n");

    BN_CTX_free(ctx);
    BN_free(M);
    BN_free(e);
    BN_free(n);
    BN_free(d);
    BN_free(signature_2000);
    BN_free(signature_3000);
}
void task5(){
    const char* message = "Launch a missle.";
    const char* signature_message = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";

    char message_hex[strlen(message)*2 + 1];
    stringToHex(message,message_hex);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* S = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* result = BN_new();
    BIGNUM* corrupt_S = BN_new();
    BIGNUM* corrupt_res = BN_new();

    BN_hex2bn(&S,signature_message);
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001");
    BN_mod_exp(result, S , e , n , ctx);
    
    printf("Task 5:\n");
    printf("Message (hex): %s\n\n",message_hex);
    printf("Signature : %s\n" , signature_message);
    printf("Decrypt Signature: ");
    BN_print_fp(stdout ,result);
    printf("\n\n");

    const char* corrupt_signature = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F";
    BN_hex2bn(&corrupt_S,corrupt_signature);
    BN_mod_exp(corrupt_res , corrupt_S , e , n ,ctx);
    printf("Corrupt Signature: %s\n",corrupt_signature);
    printf("Decrypt Corrupt Signature: ");
    BN_print_fp(stdout ,corrupt_res);
    printf("\n");


}