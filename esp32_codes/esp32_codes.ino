#include <WiFi.h>
#include <WiFiUdp.h>

// --- Network Node Configuration ---
const char* ssid     = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

const int TCP_PORT = 8888;
const int UDP_PORT = 8889;

WiFiServer tcpServer(TCP_PORT);
WiFiUDP udpServer;
char networkBuffer[128];

void generate_hardware_seed_hex(char* out_hex_buffer) {
    for (int i = 0; i < 8; i++) {
        uint32_t random_chunk = esp_random();
        sprintf(out_hex_buffer + (i * 8), "%08X", random_chunk);
    }
    out_hex_buffer[64] = '\0';
}

void setup() {
    Serial.begin(115200);
    
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    
    unsigned long start_attempt = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start_attempt < 8000) {
        delay(200);
    }

    if (WiFi.status() == WL_CONNECTED) {
        tcpServer.begin();
        udpServer.begin(UDP_PORT);
    }
}

void loop() {
    if (Serial.available() > 0) {
        char tracking_cmd = Serial.read();
        if (tracking_cmd == 'P') {
            Serial.println("PONG");
        } 
        else if (tracking_cmd == 'K') {
            char hex_seed[65];
            generate_hardware_seed_hex(hex_seed);
            Serial.println(hex_seed);
        }
    }

    if (WiFi.status() != WL_CONNECTED) return;
    int discoveryPacketSize = udpServer.parsePacket();
    if (discoveryPacketSize) {
        int bytes_read = udpServer.read(networkBuffer, sizeof(networkBuffer) - 1);
        if (bytes_read > 0) {
            networkBuffer[bytes_read] = '\0';
            
            if (strcmp(networkBuffer, "PING_OPENBOX_HSM") == 0) {
                udpServer.beginPacket(udpServer.remoteIP(), udpServer.remotePort());
                // Return unique discovery string incorporating hostname definition
                udpServer.print("RESP_OPENBOX_HSM:OpenBox-Wireless-HSM");
                udpServer.endPacket();
            }
        }
    }

    WiFiClient network_client = tcpServer.available();
    if (network_client) {
        while (network_client.connected()) {
            if (network_client.available() > 0) {
                char network_cmd = network_client.read();
                if (network_cmd == 'P') {
                    network_client.println("PONG");
                } 
                else if (network_cmd == 'K') {
                    char hex_seed[65];
                    generate_hardware_seed_hex(hex_seed);
                    network_client.println(hex_seed);
                }
            }
        }
        network_client.stop();
    }
}