#include "nfc/rc522.h"

namespace {

	MFRC522 *rfid;
	unsigned short ssPin;
	unsigned short rstPin;

	enum class State {
		uninitialized,
		initialized,
		failed
	};
	State state = State::uninitialized;

	void dumpTagInfo() {
		Serial.print(F("Card UID:"));
		for (byte i = 0; i < rfid->uid.size; i++) {
			if (rfid->uid.uidByte[i] < 0x10)
				Serial.print(F(" 0"));
			else
				Serial.print(F(" "));
			Serial.print(rfid->uid.uidByte[i], HEX);
		} 
		Serial.println();
		// SAK
		Serial.print(F("Card SAK: "));
		if (rfid->uid.sak < 0x10)
			Serial.print(F("0"));
		Serial.println(rfid->uid.sak, HEX);
	}

	bool tryAuth(MFRC522::MIFARE_Key *key, uint8_t blockAddr = 0) {
		return rfid->PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, blockAddr, key, &(rfid->uid)) == MFRC522::STATUS_OK;
	}

	const uint8_t numKnownKeys = 8;
	const byte knownKeys[numKnownKeys][MFRC522::MF_KEY_SIZE] =  {
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // FF FF FF FF FF FF = factory default
		{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
		{0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
		{0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
		{0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
		{0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
		{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // AA BB CC DD EE FF
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  // 00 00 00 00 00 00
	};

	MFRC522::MIFARE_Key tryAuthWithKnownKeys() {
		MFRC522::MIFARE_Key key;
		logger::write("Attempting to start encrypted communication authentication with list of known keys...");
		for (byte k = 0; k < numKnownKeys; k++) {
			for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
				key.keyByte[i] = knownKeys[k][i];
			}
			if (tryAuth(&key)) {
				logger::write("Success with key: " + util::bytesToHex(key.keyByte, sizeof(key.keyByte)));
				break;
			}
			rfid->PICC_HaltA();
			rfid->PCD_StopCrypto1();
			if (!rfid->PICC_IsNewCardPresent() || !rfid->PICC_ReadCardSerial()) {
				break;
			}
		}
		return key;
	}

	std::vector<uint8_t> read_MifareClassicSector(const uint16_t &sector, MFRC522::MIFARE_Key *key) {
		std::vector<uint8_t> bytes;
		byte firstBlock;// Address of lowest address to dump actually last block dumped)
		uint8_t numBlocksInSector;// Number of blocks in sector
		// Determine position and size of sector.
		if (sector < 32) { // Sectors 0..31 has 4 blocks each
			numBlocksInSector = 4;
			firstBlock = sector * numBlocksInSector;
		} else if (sector < 40) { // Sectors 32-39 has 16 blocks each
			numBlocksInSector = 16;
			firstBlock = 128 + (sector - 32) * numBlocksInSector;
		} else { // Illegal input, no MIFARE Classic PICC has more than 40 sectors.
			return bytes;
		}
		// Dump blocks, highest address first.
		bool isSectorTrailer = true;
		for (int8_t blockOffset = numBlocksInSector - 1; blockOffset >= 0; blockOffset--) {
			byte blockAddr = firstBlock + blockOffset;
			if (isSectorTrailer && !tryAuth(key, blockAddr)) {
				// Auth failed.
				break;
			}
			byte buffer[18];
			byte numBytes = sizeof(buffer);
			MFRC522::StatusCode status = rfid->MIFARE_Read(blockAddr, buffer, &numBytes);
			if (status != MFRC522::STATUS_OK) {
				logger::write("MIFARE_Read() failed: " + std::string(String(rfid->GetStatusCodeName(status)).c_str()), "error");
				break;
			}
			isSectorTrailer = false;
			bytes.insert(bytes.end(), &buffer[0], &buffer[16]);
		}
		return bytes;
	}

	std::vector<uint8_t> read_MifareClassic1k() {
		std::vector<uint8_t> bytes;
		MFRC522::MIFARE_Key key = tryAuthWithKnownKeys();
		for (uint16_t sector = 0; sector < 5; sector++) {
			const std::vector<uint8_t> sectorBytes = read_MifareClassicSector(sector, &key);
			if (!(sectorBytes.size() > 0)) {
				break;
			}
			bytes.insert(bytes.end(), sectorBytes.begin(), sectorBytes.end());
		}
		return bytes;
	}

	std::vector<uint8_t> read_MifareUltralight() {
		std::vector<uint8_t> bytes;
		// MIFARE_Read returns data for 4 pages at a time.
		// Skip the first sector (4 pages) because it contains the UID.
		for (uint16_t page = 0; page < 45; page +=4) {
			uint8_t buffer[18];
			byte numBytes = sizeof(buffer);
			MFRC522::StatusCode status = rfid->MIFARE_Read(page, buffer, &numBytes);
			if (status != MFRC522::STATUS_OK) {
				logger::write("MIFARE_Read() failed: " + std::string(String(rfid->GetStatusCodeName(status)).c_str()), "error");
				break;
			}
			bytes.insert(bytes.end(), &buffer[0], &buffer[16]);
		}
		return bytes;
	}
}

namespace nfc_rc522 {

	void init() {
		ssPin = config::getUnsignedShort("nfcSSPin");
		rstPin = config::getUnsignedShort("nfcRSTPin");
	}

	void loop() {
		if (state == State::uninitialized) {
			logger::write("Initializing NFC module (RC522)...");
			if (!(ssPin > 0)) {
				logger::write("Cannot initialize NFC module: \"ssPin\" is not set", "warn");
				state = State::failed;
			} else if (!(rstPin > 0)) {
				logger::write("Cannot initialize NFC module: \"rstPin\" is not set", "warn");
				state = State::failed;
			} else {
				try {
					rfid = new MFRC522(ssPin, rstPin);
					SPI.begin();
					rfid->PCD_Init();
					state = State::initialized;
				} catch (const std::exception &e) {
					logger::write("Failed to initialize NFC module: " + std::string(e.what()), "error");
					state = State::failed;
				}
			}
		}
	}

	bool available() {
		return rfid->PICC_IsNewCardPresent();
	}

	std::vector<uint8_t> read() {
		std::vector<uint8_t> bytes;
		logger::write("Reading NFC tag...");
		if (rfid->PICC_ReadCardSerial()) {
			MFRC522::PICC_Type piccType = rfid->PICC_GetType(rfid->uid.sak);
			logger::write("NFC Tag Type = \"" + std::string(String(rfid->PICC_GetTypeName(piccType)).c_str()) + "\"");
			dumpTagInfo();
			if (piccType == MFRC522::PICC_TYPE_MIFARE_1K) {
				MFRC522::MIFARE_Key key;
				for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
					key.keyByte[i] = knownKeys[1][i];
				}
				rfid->PICC_DumpMifareClassicToSerial(&rfid->uid, piccType, &key);
				// bytes = read_MifareClassic1k();
			} else if (piccType == MFRC522::PICC_TYPE_MIFARE_UL) {
				bytes = read_MifareUltralight();
			} else {
				logger::write("Unsupported NFC tag type", "warn");
			}
			rfid->PICC_HaltA();
			rfid->PCD_StopCrypto1();
		} else {
			logger::write("Failed to read NFC tag", "warn");
		}
		return bytes;
	}
}
