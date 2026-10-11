/* Public PSA adapter for Mbed TLS 4 / TF-PSA-Crypto. */
#include "archive_platform.h"
#if defined(HAVE_LIBMBEDCRYPTO) && defined(ARCHIVE_CRYPTO_MBEDTLS_PSA)
#include "archive_mbedtls_private.h"
#if defined(_WIN32) && !defined(__CYGWIN__)
static SRWLOCK psa_mutex = SRWLOCK_INIT;
#define PSA_LOCK() AcquireSRWLockExclusive(&psa_mutex)
#define PSA_UNLOCK() ReleaseSRWLockExclusive(&psa_mutex)
#else
#include <pthread.h>
static pthread_mutex_t psa_mutex = PTHREAD_MUTEX_INITIALIZER;
#define PSA_LOCK() pthread_mutex_lock(&psa_mutex)
#define PSA_UNLOCK() pthread_mutex_unlock(&psa_mutex)
#endif

psa_status_t
__archive_psa_begin(void)
{
    static int initialized;
    psa_status_t status = PSA_SUCCESS;
    PSA_LOCK();
    if (!initialized) {
        status = psa_crypto_init();
        if (status == PSA_SUCCESS)
            initialized = 1;
    }
    if (status != PSA_SUCCESS)
        PSA_UNLOCK();
    return status;
}

void
__archive_psa_end(void)
{
    PSA_UNLOCK();
}
#endif
