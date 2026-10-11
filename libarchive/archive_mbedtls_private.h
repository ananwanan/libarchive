/* Public PSA adapter shared by the Mbed TLS 4 crypto implementations. */
#ifndef ARCHIVE_MBEDTLS_PRIVATE_H_INCLUDED
#define ARCHIVE_MBEDTLS_PRIVATE_H_INCLUDED
#ifndef __LIBARCHIVE_BUILD
#error This header is only to be used internally to libarchive.
#endif
#include <psa/crypto.h>
/* Serialize global PSA initialization and calls, including for crypto kits
 * built without MBEDTLS_THREADING_C. Independent operations own their contexts.
 * No library-wide cleanup is performed while another archive can use PSA. */
psa_status_t __archive_psa_begin(void);
void __archive_psa_end(void);
#endif
