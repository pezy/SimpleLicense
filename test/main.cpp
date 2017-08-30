#include "../simple_license.h"
#include <iostream>
#include <fstream>

int main()
{
	PT::License license(PT::GetLocalMacAddr(), -2);
	std::cout << license << std::endl;

	PT::LicenseCrypto licenseCrypto(std::make_shared<PT::License>(license));

	std::ofstream file("license.lic");
	file << licenseCrypto;
	file.close();

	std::ifstream rFile("license.lic");
	PT::LicenseCrypto rLicenseCrypto(rFile);
	auto result = rLicenseCrypto.Check();
	std::cout << std::boolalpha << result.first << ": " << result.second << std::endl;
}