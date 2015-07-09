#include "Python.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>

static char *
to_hex(const void *bin, const size_t bin_len)
{
    char   *hex;
    size_t  hex_size;

    if (bin_len >= SIZE_MAX / 2) {
        abort();
    }
    hex_size = bin_len * 2 + 1;
    if ((hex = malloc(hex_size)) == NULL) {
        abort();
    }

    if (sodium_bin2hex(hex, hex_size, bin, bin_len) == NULL) {
        abort();
    }
    return hex;
}

int test_pow(char * pow){
  int n = (int)strtol(pow, NULL, 16);
  if (n <= 50)
    return 1;
  else return 0;
}

static char * createGUID()
{
  sodium_init();

  unsigned char out[crypto_hash_sha512_BYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  int valid_pow = 0;
  while (valid_pow == 0){

    //Generate a key pair
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    //Sign the public key
    const unsigned char * message = pk;
    int message_len = crypto_sign_PUBLICKEYBYTES;

    unsigned char signed_message[crypto_sign_BYTES + message_len];
    unsigned long long signed_message_len;

    crypto_sign(signed_message, &signed_message_len,
            message, message_len, sk);

    //Hash the signed key with sha512
    crypto_hash_sha512(out, signed_message, signed_message_len);
    char proof_of_work[32];
    memcpy(proof_of_work, &out[32], 32);
    char * pow = to_hex(proof_of_work, 3);
    valid_pow = test_pow(pow);
  }
  to_hex(sk, 32);
  return to_hex(sk, 32);
}

PyDoc_STRVAR(guidc__doc__,
"OpenBazaar GUID PoW calculator");

PyDoc_STRVAR(generate__doc__,
"Returns a private key which produces a vaild GUID");

static PyObject *
generate()
{
    return Py_BuildValue("s", createGUID());
}
static PyMethodDef guidc_methods[] = {
    {"generate",  generate, METH_VARARGS, generate__doc__},
    {NULL, NULL}      /* sentinel */
};

PyMODINIT_FUNC
initguidc(void)
{
    Py_InitModule3("guidc", guidc_methods,
                   guidc__doc__);
}