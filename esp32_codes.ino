#include <Arduino.h>

const char CMD_PING = 'P';
const char CMD_GEN_KEY = 'K';

void generateHardwareSeed();

void setup()
{
  Serial.begin(115200);
  while (!Serial){;} // Spinlock
}

void loop() {
    if (Serial.available() > 0) {
        char incomingCommand = Serial.read();
        
        if (incomingCommand == CMD_PING)
            Serial.println("AUTHENTICATED_CONNECTED");
        else if (incomingCommand == CMD_GEN_KEY)
            generateHardwareSeed();
    }
}

/**
 * Collects 32 bytes of physical entropy from the ESP32 hardware TRNG 
 * and writes it to the serial port as a unified 64-character hex string.
 */
void generateHardwareSeed() {
    uint8_t keyBuffer[32];
    for (int i = 0; i < 32; i += 4) {
        uint32_t randomNum = esp_random();
        keyBuffer[i]     = (randomNum >> 24) & 0xFF;
        keyBuffer[i + 1] = (randomNum >> 16) & 0xFF;
        keyBuffer[i + 2] = (randomNum >> 8)  & 0xFF;
        keyBuffer[i + 3] = randomNum         & 0xFF;
    }
    for (int i = 0; i < 32; i++) {
        if (keyBuffer[i] < 0x10) {
            Serial.print("0");
        }
        Serial.print(keyBuffer[i], HEX);
    }
    Serial.println(); 
}