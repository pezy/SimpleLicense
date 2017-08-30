#pragma once

#include <string>
#include <iostream>
#include <chrono>
#include <memory>
#include <vector>

namespace PT // pezy tools
{

/**
@class PT::License provided in the file "simple_license.h"
@brief The class provides License generation and identification functions.
@author pezy
@date 2017-08-29
@sa
*/
class License {
	using days = std::chrono::duration<int, std::ratio_multiply<std::ratio<24>, std::chrono::hours::period>>;
	using years = std::chrono::duration<int, std::ratio_multiply<std::ratio<146097, 400>, days::period>>;
	using months = std::chrono::duration<int, std::ratio_divide<years::period, std::ratio<12>>>;

	std::string m_mac;
	std::chrono::system_clock::time_point m_expire;
public:
	License(const std::string& strMac, int month);
	License(std::istream& is);
	std::pair<bool, std::string> Check() const;
	//! @brief Output License object("MAC date time")
	friend std::ostream& operator<<(std::ostream& os, const License& license);
};

//! @brief Get local Netcard physical address.
std::string GetLocalMacAddr();

/**
@class LicenseCrypto provided in the file "simple_license.h"
@brief The class provides cryptogram for license.
@author pezy
@date 2017-08-29
@sa License AesProxy
*/
class LicenseCrypto {
	std::shared_ptr<License> m_pLic;
	constexpr static unsigned char gKey[] = "n#If^*:Y4;-xH&<Ozj/Zybq]~@%,JC'o"; // custom
public:
	LicenseCrypto(const std::shared_ptr<License>& pLic) : m_pLic(pLic) {}
	LicenseCrypto(std::istream& is);
	std::pair<bool, std::string> Check() const { return m_pLic->Check(); }
	//! @brief Output LicenseCrypto object("Passphrase")
	friend std::ostream& operator<<(std::ostream& os, const LicenseCrypto& licCrypto);
};
}
