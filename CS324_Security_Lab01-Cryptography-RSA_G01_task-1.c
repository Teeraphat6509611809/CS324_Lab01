#include <stdio.h>
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


int main(){
    const char *P_STR = "F7E75FDC469067FFDC4E847C51F452DF";
    const char *Q_STR = "E85CED54AF57E53E092113E62F436F4F";
    const char *E_STR = "0D88C3";

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *phi_n = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *pkey = BN_new();
    BN_hex2bn(&one , "1");

    BN_hex2bn(&p , P_STR);
    BN_hex2bn(&q , Q_STR);
    BN_hex2bn(&e , E_STR);

    BN_sub(p ,p , one);
    BN_sub(q ,q , one);
    BN_mul(phi_n , p , q , ctx);
    
    BN_mod_inverse(pkey , e , phi_n , ctx);
    printBN("Private Keys :" , pkey);

    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(q);
    BN_free(phi_n);
    BN_free(e);
    BN_free(one);
    BN_free(pkey);

}