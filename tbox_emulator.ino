#include <mcp_can.h>
#include <SPI.h>

// ─── hardware ────────────────────────────────────────────────────────────────
static const int PIN_CS = 10;
MCP_CAN CAN(PIN_CS);

// ─── CAN IDs ─────────────────────────────────────────────────────────────────
static const unsigned long ID_LOCK_REQ     = 0x208;
static const unsigned long ID_REMOTE_REQ   = 0x102;
static const unsigned long ID_LOCK_RESP    = 0x504;
static const unsigned long ID_REMOTE_RESP  = 0x505;

// ─── retry tuning ────────────────────────────────────────────────────────────
static const int   RETRY_COUNT    = 5;
static const unsigned long RETRY_INTERVAL_MS = 500;

// ─── crypto constants ────────────────────────────────────────────────────────
static const uint32_t LOWER_XOR_KEY   = 0x7869AABC;
static const uint32_t UPPER_M0_PRE    = 0xFA457812;
static const uint32_t UPPER_M0_POST   = 0x23AABE90;
static const uint32_t UPPER_M0_ROT    = 15;
static const uint32_t UPPER_M1_PRE    = 0x45AADCBA;
static const uint32_t UPPER_M1_POST   = 0xAAED90FA;
static const uint32_t UPPER_M1_ROT    = 12;

// ─── encrypted-payload pair ─────────────────────────────────────────────────
struct EncryptedPayload {
    uint32_t lo;
    uint32_t hi;
};

// ─── per-channel state ───────────────────────────────────────────────────────
struct Channel {
    unsigned long  respId;          // CAN ID to transmit on
    bool           pending;         // new frame waiting to be sent
    unsigned char  reqData[8];      // raw received request bytes
    int            retriesLeft;
    unsigned long  lastSendTime;
};

static Channel lockChannel   = { ID_LOCK_RESP,   false, {}, 0, 0 };
static Channel remoteChannel = { ID_REMOTE_RESP, false, {}, 0, 0 };

// ─── forward declarations ───────────────────────────────────────────────────
void          handleIncoming(unsigned long id, unsigned char buf[8]);
void          processPending(Channel &ch, unsigned long now);
void          sendRetry(Channel &ch, unsigned long now);
void          sendEncrypted(Channel &ch);
void          sendEmpty(unsigned long id);
EncryptedPayload scramble(unsigned char data[8], int mode);
uint32_t      rotateLeft(uint32_t value, int bits);


void setup() {
    Serial.begin(115200);
    delay(1000);

    if (CAN.begin(MCP_ANY, CAN_250KBPS, MCP_8MHZ) == CAN_OK) {
        Serial.println("CAN Init OK");
    } else {
        Serial.println("CAN Init Failed");
        while (1) delay(100);
    }

    CAN.setMode(MCP_NORMAL);
    Serial.println("=== T-BOX EMULATOR ACTIVE ===");
}


void loop() {
    unsigned long now = millis();

    // ── receive ──────────────────────────────────────────────────────────────
    if (CAN.checkReceive() == CAN_MSGAVAIL) {
        long unsigned int rxId;
        unsigned char len = 0, buf[8];
        CAN.readMsgBuf(&rxId, &len, buf);

        handleIncoming(rxId, buf);
    }

    // ── transmit / retry ─────────────────────────────────────────────────────
    processPending(lockChannel,   now);
    processPending(remoteChannel, now);
}

// ─────────────────────────────────────────────────────────────────────────────
// incoming-frame router
// ─────────────────────────────────────────────────────────────────────────────
void handleIncoming(unsigned long id, unsigned char buf[8]) {
    Channel *target = nullptr;

    if      (id == ID_LOCK_REQ)   target = &lockChannel;
    else if (id == ID_REMOTE_REQ) target = &remoteChannel;

    if (target) {
        memcpy(target->reqData, buf, 8);
        target->pending = true;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// channel processing  –  first send + scheduled retries
// ─────────────────────────────────────────────────────────────────────────────
void processPending(Channel &ch, unsigned long now) {
    if (ch.pending) {
        ch.pending = false;
        sendEncrypted(ch);
        ch.retriesLeft   = RETRY_COUNT;
        ch.lastSendTime  = now;
    }

    sendRetry(ch, now);
}

void sendRetry(Channel &ch, unsigned long now) {
    if (ch.retriesLeft > 0 && (now - ch.lastSendTime) > RETRY_INTERVAL_MS) {
        ch.retriesLeft--;
        ch.lastSendTime = now;
        sendEmpty(ch.respId);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CAN transmit helpers
// ─────────────────────────────────────────────────────────────────────────────
void sendEncrypted(Channel &ch) {
    EncryptedPayload ep = scramble(ch.reqData, 0);

    unsigned char buf[8];
    for (int i = 0; i < 4; i++) {
        buf[i]     = (ep.lo >> (24 - 8 * i)) & 0xFF;
        buf[i + 4] = (ep.hi >> (24 - 8 * i)) & 0xFF;
    }

    if (CAN.sendMsgBuf(ch.respId, 0, 8, buf) != CAN_OK) {
        Serial.print("Failed to send 0x");
        Serial.println(ch.respId, HEX);
    }
}

void sendEmpty(unsigned long id) {
    unsigned char buf[8] = {};

    if (CAN.sendMsgBuf(id, 0, 8, buf) != CAN_OK) {
        Serial.print("Failed to send empty 0x");
        Serial.println(id, HEX);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// crypto
// ─────────────────────────────────────────────────────────────────────────────
uint32_t rotateLeft(uint32_t value, int bits) {
    return (value << bits) | (value >> (32 - bits));
}

uint32_t bytesToU32(unsigned char data[8], int offset) {
    return ((uint32_t)data[offset]     << 24)
         | ((uint32_t)data[offset + 1] << 16)
         | ((uint32_t)data[offset + 2] <<  8)
         |  (uint32_t)data[offset + 3];
}

EncryptedPayload scramble(unsigned char data[8], int mode) {
    EncryptedPayload ep;

    uint32_t raw = bytesToU32(data, 0);
    ep.lo = raw ^ LOWER_XOR_KEY;

    if (mode == 1) {
        ep.hi = rotateLeft(raw ^ UPPER_M1_PRE, UPPER_M1_ROT) ^ UPPER_M1_POST;
    } else {
        ep.hi = rotateLeft(raw ^ UPPER_M0_PRE, UPPER_M0_ROT) ^ UPPER_M0_POST;
    }

    return ep;
}

