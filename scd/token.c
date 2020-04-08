/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#if 0
#include "token.h"
#include "softtoken.h"
#include "usbtoken.h"

#include "common/macro.h"
#include "common/mem.h"





/*****************************************************************************/
/******************* internal Helper functions *******************************/
/*****************************************************************************/

/**
 * TODO: investigate whether error handling and/or input sanitazion is needed
 */

int
int_lock_st(scd_token_t *token) {
    return softtoken_lock(token->int_token.softtoken);
}

int
int_unlock_st(scd_token_t *token, char *passwd) {
    return softtoken_unlock(token->int_token.softtoken, passwd);
}

bool
int_is_locked_st(scd_token_t *token) {
    return softtoken_is_locked(token->int_token.softtoken);
}

bool
int_is_locked_till_reboot_st(scd_token_t *token) {
    return softtoken_is_locked_till_reboot(token->int_token.softtoken);
}

int
int_wrap_st(scd_token_t *token, unsigned char *label, size_t label_len,
			unsigned char *plain_key, size_t plain_key_len,
			unsigned char **wrapped_key, int *wrapped_key_len)
{   
    ASSERT(label);
    ASSERT(label_len);

    return softtoken_wrap_key(token->int_token.softtoken, plain_key, plain_key_len,
                              wrapped_key, wrapped_key_len);
}

int
int_unwrap_st(scd_token_t *token, unsigned char *label, size_t label_len,
                unsigned char *wrapped_key, size_t wrapped_key_len,
		        unsigned char **plain_key, int *plain_key_len)
{  
    ASSERT(label);
    ASSERT(label_len);
    
    return softtoken_unwrap_key(token->int_token.softtoken, wrapped_key,
                                wrapped_key_len, plain_key, plain_key_len);
}

/*  -----------------------------------------------------------------------  */
int
int_lock_usb(scd_token_t *token) {
    return usbtoken_lock(token->int_token.usbtoken);
}

int
int_unlock_usb(scd_token_t *token, char *passwd) {
    DEBUG("1");
    return usbtoken_unlock(token->int_token.usbtoken, passwd);
}

bool
int_is_locked_usb(scd_token_t *token) {
    return usbtoken_is_locked(token->int_token.usbtoken);
}

bool
int_is_locked_till_reboot_usb(scd_token_t *token) {
    return usbtoken_is_locked_till_reboot(token->int_token.usbtoken);
}

int
int_wrap_usb(scd_token_t *token, unsigned char *label, size_t label_len,
			unsigned char *plain_key, size_t plain_key_len,
			unsigned char **wrapped_key, int *wrapped_key_len)
{   
    return usbtoken_wrap_key(token->int_token.usbtoken, label, label_len,
                            plain_key, plain_key_len,
                            wrapped_key, wrapped_key_len);
}

int
int_unwrap_usb(scd_token_t *token, unsigned char *label, size_t label_len,
                unsigned char *wrapped_key, size_t wrapped_key_len,
		        unsigned char **plain_key, int *plain_key_len)
{   
    return usbtoken_unwrap_key(token->int_token.usbtoken, label, label_len,
                                wrapped_key, wrapped_key_len,
                                plain_key, plain_key_len);
}


scd_tokentype_t
scd_token_get_type(scd_token_t *token) {
    return token->type;
}

/**
 * creates a new generic token
 * calls the respective create function for the selected type of token and
 * sets the function pointer appropriately
 */

scd_token_t *
scd_token_create(scd_tokentype_t type, const char *softtoken_dir) {

    // ASSERT(filename); // TODO: only needed if softtoken

    scd_token_t *new_token;
    int rc;


    new_token = mem_new0(scd_token_t, 1);
    if (!new_token) {
        ERROR("Could not allocate new scd_token_t");
        return NULL;
    }

    switch (type) {
        case (NONE): {
            WARN("Create scd_token with internal type 'NONE' selected");
            new_token->type       = NONE;
            break;
        }
        case (DEVICE): {
            DEBUG("Create scd_token with internal type 'DEVICE'");
            new_token->int_token.softtoken = softtoken_new_from_p12(filename);
            if (!new_token->int_token.softtoken) {
                ERROR("Creation of softtoken failed");
                mem_free(new_token);
                return NULL;
            }
            new_token->type       = DEVICE;
            new_token->lock       = int_lock_st;
            new_token->unlock     = int_unlock_st;
            new_token->is_locked  = int_is_locked_st;
            new_token->is_locked_till_reboot = int_is_locked_till_reboot_st;
            new_token->wrap_key   = int_wrap_st;
            new_token->unwrap_key  = int_unwrap_st;
            break;
        }
        case (USB): {
            DEBUG("Create scd_token with internal type 'USB'");
            new_token->int_token.usbtoken = usbtoken_init();
            ASSERT(new_token->int_token.usbtoken);
            if (NULL == new_token->int_token.usbtoken) {
                ERROR("Creation of usbtoken failed");
                mem_free(new_token);
                return NULL;
            }
            new_token->type       = USB;
            new_token->lock       = int_lock_usb;
            new_token->unlock     = int_unlock_usb;
            new_token->is_locked  = int_is_locked_usb;
            new_token->is_locked_till_reboot = int_is_locked_till_reboot_usb;
            new_token->wrap_key   = int_wrap_usb;
            new_token->unwrap_key  = int_unwrap_usb;
            break;
        }
        default: {
            ERROR("Unrecognized token type");
            mem_free(new_token);
            return NULL;
        }
    }
    return new_token;
}

void scd_token_free(scd_token_t *token) {

    /* TODO */
    switch (token->type) {
        case (NONE): break;
        case (DEVICE):
            softtoken_free(token->int_token.softtoken);
            break;
        case (USB):
            usbtoken_free(token->int_token.usbtoken);
            break;
        default:
            ERROR("Failed to determine token type. Cannot clean up");
            return;
    }
    mem_free(token);
}

#endif