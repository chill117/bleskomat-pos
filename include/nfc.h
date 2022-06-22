#ifndef BLESKOMAT_NFC_H
#define BLESKOMAT_NFC_H

#include "nfc/rc522.h"
#include "util.h"

#include <iomanip>
#include <map>
#include <sstream>
#include <vector>

namespace nfc {
	void init();
	void loop();
	bool available();
	std::string read();
}

#endif
