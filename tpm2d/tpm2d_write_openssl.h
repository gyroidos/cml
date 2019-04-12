#ifndef TPM2D_WRITE_OPENSSL_H
#define TPM2D_WRITE_OPENSSL_H
# include <openssl/safestack.h>

int
openssl_write_tpmfile(const char *file, BYTE *pubkey, int pubkey_len,
                      BYTE *privkey, int privkey_len, int empty_auth,
                      TPM_HANDLE parent, STACK_OF(TSSOPTPOLICY) *sk,
                      int version, TPM2B_ENCRYPTED_SECRET *secret);
#endif
