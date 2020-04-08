#if 0

#ifndef TOKEN_H
#define TOKEN_H

#include <stdbool.h>

#include "softtoken.h"
#include "usbtoken.h"

/**
 *  Generic token type
 */
typedef struct scd_token scd_token_t;

/**
 * Choice of supported token types.
 * Must be kept in sync with scd.proto
 */
typedef enum scd_tokentype { NONE, DEVICE, USB } scd_tokentype_t;


typedef union{
    softtoken_t *softtoken;
    usbtoken_t *usbtoken;
} int_token_t;

/**
 * TODO: create a unifying structure for scd_token
 */
struct scd_token {
    
    int_token_t int_token;
    scd_tokentype_t type;

//    int (*init) (scd_token_t *token);

    int (*lock) (scd_token_t *token);
    int (*unlock) (scd_token_t *token, char *passwd);

    bool (*is_locked) (scd_token_t *token);
    bool (*is_locked_till_reboot) (scd_token_t *token);

    int (*wrap_key) (scd_token_t *token, unsigned char *label, size_t label_len,
				  unsigned char *plain_key, size_t plain_key_len,
				  unsigned char **wrapped_key, int *wrapped_key_len);

    int (*unwrap_key) (scd_token_t *token, unsigned char *label, size_t label_len,
                       unsigned char *wrapped_key, size_t wrapped_key_len,
		               unsigned char **plain_key, int *plain_key_len);

//    void (*free) (scd_token_t *token);
};

/** 
 * Initializes a generic token
 * TODO: needs all the inputs to create any of the supported types
 */
scd_token_t *
scd_token_create(scd_tokentype_t type, const char *softtoken_dir);

scd_tokentype_t
scd_token_get_type(scd_token_t *token);

/**
 * frees a token structure
 */
void
scd_token_free(scd_token_t *token);

#endif
#endif