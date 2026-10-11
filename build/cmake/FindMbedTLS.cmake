find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h)

find_library(MBEDTLS_LIBRARY mbedtls)
find_library(MBEDX509_LIBRARY mbedx509)
find_library(MBEDCRYPTO_LIBRARY NAMES tfpsacrypto mbedcrypto)

set(MBEDCRYPTO_LIBRARIES "${MBEDCRYPTO_LIBRARY}")
if(WIN32 AND NOT CYGWIN)
  # TF-PSA-Crypto uses the Windows system entropy and socket APIs even when
  # libarchive's separate CNG implementation is disabled.
  list(APPEND MBEDCRYPTO_LIBRARIES bcrypt ws2_32)
endif()

set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MbedTLS DEFAULT_MSG
    MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)

mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
