
#include <algorithm>
#include <fstream>

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

#include <spdmcpp/common.hpp>

namespace spdmcpp
{
	
	
	ContextClass::ContextClass()
	{
		SupportedVersions.push_back(MessageVersionEnum::SPDM_1_0);
		SupportedVersions.push_back(MessageVersionEnum::SPDM_1_1);
		std::sort(SupportedVersions.begin(), SupportedVersions.end(), std::greater());
	}
}
