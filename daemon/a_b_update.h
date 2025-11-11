#include "common/mem.h"

typedef enum {
	A_B_UPDATE_OPTION_A = 0,
	A_B_UPDATE_OPTION_B,
	A_B_UPDATE_UNDEFINED
} a_b_update_option_t;

#ifdef A_B_UPDATE
char *
a_b_update_get_path(char *base_path);

void
a_b_update_init(void);

void
a_b_update_set_boot_order(void);

char *
a_b_update_get_flash_path(const char *partition);

void
a_b_update_boot_new_once(void);
#else
static inline char *
a_b_update_get_path(char *base_path)
{
	return mem_strdup(base_path);
}

static inline void
a_b_update_init(void)
{
}

static inline void
a_b_update_set_boot_order(void)
{
}
#endif