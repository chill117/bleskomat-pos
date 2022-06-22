#ifndef BLESKOMAT_NFC_RC522_H
#define BLESKOMAT_NFC_RC522_H

#include "config.h"
#include "logger.h"
#include "util.h"

#include <SPI.h>
#include <MFRC522.h>

#include <stdexcept>
#include <vector>

namespace nfc_rc522 {
	void init();
	void loop();
	bool available();
	std::vector<uint8_t> read();
}

#endif
