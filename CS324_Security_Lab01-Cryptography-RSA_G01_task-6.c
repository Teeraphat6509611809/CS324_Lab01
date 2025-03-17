#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

#define NBIT 128


//from reg.tu.ac.th
const char* signature = "28bf2f18cd0599b0a8673f8cec53f66452aed36c55ba4cb3e761c2d18c75c6532b34f27fbbade2a5eb18495aaf4ecea5ddb4732fa4ed4055c45a49723a3919a5d06a2f62e9af95dabbf4e8cc3c39f9bfef0567613eb0e04328f648d62aa4ec9a324354b74d5d7401a7ff9a32de01c04c9cf7ecf4ea5c91ca41d89117dd061873cea00151a65fb5f29f45e0738ac26b11658c28f6e9576dcfbedb8f4ac1fb28d503f6b01f1ed692ad783e654c64af082e329355a87663c6fe88f88c32814920148addc885f965a2567142967aad5fbb8d35ea85918d896e49f8fc37c5d1880c607444b93d5fbd244f79d807d773bc763c991c10b8daaadce4ef69e8dfb9354162";
const char* modulus = "C639E098F8557AD0B46FFA336D825DCCE054035B0CA20E3BD37D1C00FF8FDB700D50DF20AD71022FC3610C417817547DB4BD3063499CCC7691D1AEE561A9E5C6DC16A35B36B869E7C83B3A98E0ACEBA7B0DB0DD8113AFA4DBD78C608E9BB580616D01E7B06A290EF45B9DF21C462534B09FCC5E3647CA556A43D8BE2F14DDFA14D8317A294AE9A138CA4806033365A244E9EA134E2C06290F249D2C03CACEE25243B242119E8EF920CACB021D5CBA0C4E7A71B81286486F3C3564E8DC21C238699010289ADB2A9D3C38E02EA9C4898363C102FCB8CAA3F2B3AF94C82F88170703BC6DCBEEFFB982CDE994BB56AD7F17F95585539FE5E8FA8D976607CE6CCC56D";
const char* expo = "10001";

const char* bodycert_hash = "1752C78DDAC36AFCF357BA23160E193228519BA1E0FB0BDBA2DA3D858DF151DF"; //for checking

void printBN(char *msg, BIGNUM * a)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}

int main(){
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* S = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* n = BN_new();
    BIGNUM* result = BN_new();

    BN_hex2bn(&S , signature);
    BN_hex2bn(&e , expo);
    BN_hex2bn(&n , modulus);

    BN_mod_exp(result , S , e , n , ctx);
    

    //get only last 64 digit of result (get rid of padding and other)
    char decrypt_signature[65];
    char* res_string = BN_bn2hex(result);
    strncpy(decrypt_signature,res_string+strlen(res_string)-64, 64);

    printf("Decrypted Signature : %s\n",decrypt_signature);
    printf("Hashed cert : %s", bodycert_hash);

    //free memory
    OPENSSL_free(res_string);
    BN_CTX_free(ctx);
    BN_free(S);
    BN_free(e);
    BN_free(n);
    BN_free(result);
    return 0;
}