#ifndef CRYPTOPP_DLL_H
#define CRYPTOPP_DLL_H

#if !defined(CRYPTOPP_IMPORTS) && !defined(CRYPTOPP_EXPORTS) && !defined(CRYPTOPP_DEFAULT_NO_DLL)
#ifdef CRYPTOPP_CONFIG_H
#error To use the DLL version of Crypto++, this file must be included before any other Crypto++ header files.
#endif
#define CRYPTOPP_IMPORTS
#endif

#include "lmn_aes.h"
#include "lmn_cbcmac.h"
#include "lmn_ccm.h"
#include "lmn_cmac.h"
#include "lmn_channels.h"
#include "lmn_des.h"
#include "lmn_dh.h"
#include "lmn_dsa.h"
#include "lmn_ec2n.h"
#include "lmn_eccrypto.h"
#include "lmn_ecp.h"
#include "lmn_files.h"
#include "lmn_fips140.h"
#include "lmn_gcm.h"
#include "lmn_hex.h"
#include "lmn_hmac.h"
#include "lmn_modes.h"
#include "lmn_mqueue.h"
#include "lmn_nbtheory.h"
#include "lmn_osrng.h"
#include "lmn_pkcspad.h"
#include "lmn_pssr.h"
#include "lmn_randpool.h"
#include "lmn_rsa.h"
#include "lmn_rw.h"
#include "lmn_sha.h"
#include "lmn_skipjack.h"
#include "lmn_trdlocal.h"

#ifdef CRYPTOPP_IMPORTS

#ifdef _DLL
// cause CRT DLL to be initialized before Crypto++ so that we can use malloc and free during DllMain()
#ifdef NDEBUG
#pragma comment(lib, "msvcrt")
#else
#pragma comment(lib, "msvcrtd")
#endif
#endif

#pragma comment(lib, "cryptopp")

#endif		// #ifdef CRYPTOPP_IMPORTS

#include <new>	// for new_handler

NAMESPACE_BEGIN(CryptoPP)

#if !(defined(_MSC_VER) && (_MSC_VER < 1300))
using std::new_handler;
#endif

typedef void * (CRYPTOPP_API * PNew)(size_t);
typedef void (CRYPTOPP_API * PDelete)(void *);
typedef void (CRYPTOPP_API * PGetNewAndDelete)(PNew &, PDelete &);
typedef new_handler (CRYPTOPP_API * PSetNewHandler)(new_handler);
typedef void (CRYPTOPP_API * PSetNewAndDelete)(PNew, PDelete, PSetNewHandler);

NAMESPACE_END

#endif
