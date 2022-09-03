#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include<string.h>
#define NBITS 512
void printBN(char*msg, BIGNUM*a)
{
	/*Use BN_bn2hex(a) for hex string*
	 *Use BN_bn2dec(a) for decimal string*/
	char*number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}
char *convertStringtoHex(char *msg) {
  const int len = strlen(msg);
  char *hex = malloc((len+1)*sizeof(char)*2);

  for (int i = 0, j = 0; i < len; ++i, j += 2)
      sprintf(hex + j, "%02x", msg[i] & 0xff);

  //printf("'%s' in hex is %s.\n", msg, hex);
  return hex;
}

char *convertHexToString(char *hex) {
  const int len = strlen(hex);
  char *string = malloc((len/2+1)*sizeof(char));
    for (int i = 0, j = 0; j < len; ++i, j += 2) {
      int val[1];
      sscanf(hex + j, "%2x", val);
      string[i] = val[0];
      string[i + 1] = '\0';
    }
  return string;
}

int main()
{
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *n = BN_new();
	BIGNUM *m = BN_new();
	BIGNUM *res1 = BN_new();
	BIGNUM *res2 = BN_new();
	BIGNUM *res3 = BN_new();
	BIGNUM *one = BN_new();
	BIGNUM *enc = BN_new();
	BIGNUM *dec = BN_new();
	
	BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
	printBN("p = ",p);
	BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");
	printBN("q = ",q);
	BN_hex2bn(&e,"0D88C3");
	BN_dec2bn(&one,"1");
	BN_mul(n,p,q,ctx);
	printBN("n = ",n);
	BN_sub(res1,p,one);
	BN_sub(res2,q,one);
	BN_mul(res3,res1,res2,ctx);

	BN_mod_inverse(d, e, res3, ctx);
	printBN("d = ",d);
	
	//Converting String to hexadecimal Value
	char givenStr[100], hexStr[100];

    	int i, j = 0;

    	printf("Enter a string: ");
    	scanf("%[^\n]s", givenStr);
	

    	for (i = 0; i < strlen(givenStr); i++)
    	{
        	sprintf(hexStr + j, "%02X", givenStr[i]);
        	j += 2;
    	}

    	hexStr[j] = '\0';
	
	BN_hex2bn(&m,hexStr);
	//BN_hex2bn(&m,"4120746f702073656372657421");
	printBN("the plaintext message is: ", m);

	
	//Encryption: m^e Mod n
	BN_mod_exp(enc,m,e,n,ctx);
	printBN( "Encrypted Message = ", enc);
	//Decryption: enc^d Mod n
	BN_mod_exp(dec,enc,d,n,ctx);
	printBN("Decrypted Message = ", dec);
	
	char *string = BN_bn2hex(dec);
  	char *recovered_message = convertHexToString(string);
  	printf("The Decrypted message in Plaintext is: %s\n",recovered_message);
	
	
	return 0; 
}

 
