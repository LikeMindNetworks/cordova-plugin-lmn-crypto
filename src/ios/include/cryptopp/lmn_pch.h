#ifndef CRYPTOPP_PCH_H
#define CRYPTOPP_PCH_H

#ifdef CRYPTOPP_GENERATE_X64_MASM

	#include "lmn_cpu.h"

#else

	#include "lmn_config.h"

	#ifdef USE_PRECOMPILED_HEADERS
		#include "lmn_simple.h"
		#include "lmn_secblock.h"
		#include "lmn_misc.h"
		#include "lmn_smartptr.h"
	#endif

#endif

#endif
