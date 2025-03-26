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

    // Return if string is null
    if (hex == NULL || output == NULL) return; 

    // Return if character is not 8 bits
    size_t len = strlen(hex);
    if (len % 2 != 0) { 
        output[0] = '\0'; 
        return;
    }

    char temp[3] = {0}; 
    char *ptr = output;

    // Loop each pair of character in hex
    for (size_t i = 0; i < len; i += 2) {
        // Pick 2 character and convert to long
        temp[0] = hex[i];
        temp[1] = hex[i + 1];
        // Convert back to char
        *ptr = (char)strtol(temp, NULL, 16); 
        ptr++;
    }

    // End string
    *ptr = '\0'; 
}

void stringToHex(const char *input, char *output) {

    // Loop each character in string
    while (*input) {
        // print to character to hex using sprintf
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

    // Convert string to hex using stringToHex function (plaintext -> hex_plainText)
    const char* plainText = "A top secret!";
    char hex_plainText[strlen(plainText)*2 + 1];
    stringToHex(plainText,hex_plainText);
    
    // printf("%s\n",hex_plainText);


    // Create BIGNUM
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM* M = BN_new(); // message
    BIGNUM* n = BN_new(); // n
    BIGNUM* e = BN_new(); // e (public key)
    BIGNUM* d = BN_new(); // d (private key)
    BIGNUM* encrypted_m = BN_new(); // encrypted message
    BIGNUM* check_message = BN_new(); // confirmation message

    // Assign value to variables
    BN_hex2bn(&M, hex_plainText);
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    printf("Task 2:\n");

    //Encrypting Message
    BN_mod_exp(encrypted_m , M , e , n , ctx); // encrypted_m = M^e (mod n)
    printBN("Encrypted message:" , encrypted_m);


    //Validating by decrypt into plain text
    BN_mod_exp(check_message , encrypted_m , d , n , ctx); // check_message = C^d (mod n)

    char* check_message_string = BN_bn2hex(check_message);
    char check_s[strlen(plainText)+1];

    hexToString(check_message_string,check_s);
    printf("checking by decrypting to plain message: %s\n",check_s);

    //Free memory
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

    // Create and assign variables
    const char *cipher_string = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F";
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* C = BN_new();
    BIGNUM* plainText_3 = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* d = BN_new();
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&C , cipher_string);
    
    printf("Task 3:\n");

    //Decrypting Message
    BN_mod_exp(plainText_3 , C , d , n , ctx); // plainText_3 = C^d (mod n)
    printBN("Decrypted Message (Hex):",plainText_3);

    //Convert Hex to string form
    char* decrypt_hex = BN_bn2hex(plainText_3);
    char decrypt_message[strlen(decrypt_hex) + 1];
    hexToString(decrypt_hex,decrypt_message);
    printf("Decrypted message (string): %s\n",decrypt_message);

    //Free memory
    BN_CTX_free(ctx);
    BN_free(C);
    BN_free(plainText_3);
    BN_free(n);
    BN_free(d);
    OPENSSL_free(decrypt_hex);
}
void task4(){

    // Create variables
    const char* message = "I owe you $2000."; // Plaintext
    char hex_message[strlen(message)*2 + 1];
    stringToHex(message,hex_message); // Plaintext to hexadecimal
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* M = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* signature_2000 = BN_new();
    BIGNUM* signature_3000 = BN_new();
    
    // Assign variables
    BN_hex2bn(&M , hex_message);    // M
    BN_hex2bn(&e, "010001");        // E
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5"); // n
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D"); // d


    //Signing
    BN_mod_exp(signature_2000, M , d , n , ctx); // signature_2000 = M^d (mod n)

    //Create alternative Message and sign
    const char* message_modify = "I owe you $3000."; // new plaintext
    stringToHex(message_modify,hex_message); // new plaintext to hex
    BN_hex2bn(&M , hex_message); // M = new plaintext
    BN_mod_exp(signature_3000, M , d , n , ctx); // signature_3000 = M^d (mod n)

    printf("Task 4:\n");
    printf("Signature (I owe you 2000$): ");
    BN_print_fp(stdout , signature_2000);
    printf("\nModified Signature (I owe you 3000$): ");
    BN_print_fp(stdout , signature_3000);
    printf("\n");

    //Free memory
    BN_CTX_free(ctx);
    BN_free(M);
    BN_free(e);
    BN_free(n);
    BN_free(d);
    BN_free(signature_2000);
    BN_free(signature_3000);
}
void task5(){
    const char* message = "Launch a missle."; //  message M
    const char* signature_message = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F"; //  signature S

    char message_hex[strlen(message)*2 + 1];

    //convert plaintext to hex
    stringToHex(message,message_hex);
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM* S = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* result = BN_new();
    BIGNUM* corrupt_S = BN_new();
    BIGNUM* corrupt_res = BN_new();

    
    BN_hex2bn(&S,signature_message);
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115"); // given n
    BN_hex2bn(&e, "010001"); // given e

    //decrpyting signature
    BN_mod_exp(result, S , e , n , ctx); //result = S^e (mod n)
    
    printf("Task 5:\n");
    printf("Message: %s\n",message); // given message M
    printf("Message (hex): %s\n\n",message_hex); // M in hex
    printf("Signature : %s\n" , signature_message); // given signature
    printf("Decrypted Signature: "); 
    BN_print_fp(stdout ,result); // signature after decrypting
    printf("\n\n");

    //create alternative corrupt signature
    const char* corrupt_signature = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F"; // corrupted signature
    BN_hex2bn(&corrupt_S,corrupt_signature);
    BN_mod_exp(corrupt_res , corrupt_S , e , n ,ctx); // corrupt_res = corrupt_S^e (mod n)
    printf("Corrupt Signature: %s\n",corrupt_signature); // corrupted signature
    printf("Decrypted Corrupt Signature: "); 
    BN_print_fp(stdout ,corrupt_res); // decrypt corrupt signature
    printf("\n");

    //Free memory
    BN_CTX_free(ctx);
    BN_free(S);
    BN_free(n);
    BN_free(e);
    BN_free(result);
    BN_free(corrupt_res);
    BN_free(corrupt_S);
}