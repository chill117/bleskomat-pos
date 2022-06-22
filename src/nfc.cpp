#include "nfc.h"

namespace {

	// https://learn.adafruit.com/adafruit-pn532-rfid-nfc/ndef
	const std::map<const uint8_t, const char*> uriIdentifierCodes = {
		{ 0x00, "" },// No prepending is done ... the entire URI is contained in the URI Field
		{ 0x01, "http://www." },
		{ 0x02, "https://www." },
		{ 0x03, "http://" },
		{ 0x04, "https://" }
	};

	std::string getUriIdentifier(const uint8_t &code) {
		if (uriIdentifierCodes.count(code) > 0) {
			return std::string(uriIdentifierCodes.at(code));
		}
		return std::string();
	}
}

namespace nfc {

	void init() {
		nfc_rc522::init();
	}

	void loop() {
		nfc_rc522::loop();
		if (nfc::available()) {
			const std::string messagePayload = nfc::read();
			if (messagePayload != "") {
				logger::write("NFC Message Payload = " + messagePayload);
			}
		}
	}

	bool available() {
		return nfc_rc522::available();
	}

	std::string read() {
		std::vector<uint8_t> tagData = nfc_rc522::read();
		if (tagData.size() > 0) {
			logger::write("Read data from NFC tag: " + util::bytesToHex(tagData.data(), tagData.size()));
		}
		// 01 (Tag: Lock Control TLV)
		// 03 (Length: 3 bytes)
		// A0 0C 44 (Value: Information on position and function of lock bytes)

		// 03 (Tag: NDEF Message TLV)
		// 15 (Length: 21 bytes)
		// D1 01 11 54 02 65 6E 33 34... (Value: NDEF message)

		// D1 (Header byte of record 1)
		// 	- Message begin is set (= first record of an NDEF message)
		// 	- Message end is set (= last record of an NDEF message)
		// 	- Short record flag is set (= Payload length field consists of 1 byte only)
		// 	- Type Name Format = 0x1 (= Type field contains an NFC Forum well-known type)
		// 01 (Type length: 1 byte)
		// 11 (Payload length: 17 bytes)
		// 54 (Type: "T")
		// 02656E3334... (Payload field)

		// 02 (Status byte: Text is UTF-8 encoded, Language code has a length of 2 bytes)
		// 656E (Language code: "en")
		// 3334... (Text: "34"...)
		uint16_t offset = 0;
		while (offset < tagData.size()) {
			uint8_t tag = tagData[offset++];
			uint16_t len = (tagData[offset++] & 0x0FF);
			if (len == 255) {
				len = ((tagData[offset++] & 0x0FF) << 8);
				len |= (tagData[offset++] & 0x0FF);
			}
			if (tag == 0x03) {// Message
				logger::write("NDEF Message found!");
				uint8_t buffer[len];
				for (uint16_t i = 0; i < len; i++) {
					buffer[i] = tagData[i + offset];
				}
				const uint8_t payloadLength = buffer[2];
				const uint8_t recordType = buffer[3];
				logger::write("Payload Length = " + std::to_string(payloadLength));
				if (recordType == 0x54) {// Text
					logger::write("Record Type = Text");
					const uint8_t status = buffer[4];
					const uint16_t lang = ((uint16_t)buffer[5] << 8) | buffer[6];
					logger::write("status = " + std::to_string(status) + "\nlang = " + std::to_string(lang));
					uint8_t payload[payloadLength - 3];
					for (uint16_t j = 0; j < payloadLength - 3; j++) {
						payload[j] = buffer[j + 7];
					}
					std::string messagePayload;
					messagePayload += std::string(reinterpret_cast<char const*>(payload), sizeof(payload));
					return messagePayload;
				} else if (recordType == 0x55) {// URI
					logger::write("Record Type = URI");
					const uint8_t uriIdentifier = buffer[4];
					uint8_t payload[payloadLength - 1];
					for (uint16_t j = 0; j < payloadLength - 1; j++) {
						payload[j] = buffer[j + 5];
					}
					std::string messagePayload;
					messagePayload += getUriIdentifier(uriIdentifier);
					messagePayload += std::string(reinterpret_cast<char const*>(payload), sizeof(payload));
					return messagePayload;
				} else {
					logger::write("Unknown record type");
				}
			} else if (tag == 0xFE) {// Terminator
				break;
			} else {
				// Ignore other tags.
			}
			offset += len;
		}
		return std::string();
	}
}
