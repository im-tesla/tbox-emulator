#include <SPI.h>
#include <mcp_can.h>
#include <EEPROM.h>
#include <avr/wdt.h>

// ─────────────────────────────────────────────────────────────────────────────
// ROBUSTNESS NOTES
//
// Failure observed in the field: bike throws 05200 ("T-Box not detected") at a
// random distance (≈10–30 km, sometimes stationary). A bike power-cycle fixes it
// WITHOUT resetting the always-powered Arduino. That symptom means the recovery
// happens at the CAN layer when the bus goes idle — i.e. the MCP2515 was in an
// unrecoverable error state (bus-off / RX overflow) and the original firmware,
// which only initialised the controller once in setup(), never re-armed it.
//
// This build keeps the protocol behaviour identical but adds defence in depth:
//   1. Watchdog timer            → recovers a hung/EMI-glitched MCU.
//   2. CAN health monitor        → detects bus-off / RX overflow / sustained TX
//                                   failure and re-initialises the MCP2515 so the
//                                   bike never needs a manual power-cycle.
//   3. Drain ALL RX per loop     → prevents the MCP2515 RX buffers from
//                                   overflowing on a busy bus.
//   4. EEPROM fault log          → records WHAT went wrong + how often, surviving
//                                   even a watchdog reset, so we can confirm the
//                                   root cause from the bench.
//
// Library: coryjfowler MCP_CAN_lib (provides getError(), errorCountTX(),
// errorCountRX()). The same library the original sketch already used.
// ─────────────────────────────────────────────────────────────────────────────

// ─── config flags ────────────────────────────────────────────────────────────
#define USE_WATCHDOG 1            // set 0 if an old bootloader boot-loops on WDT reset
#define WDT_TIMEOUT WDTO_4S       // MCU watchdog window
#define HEALTH_CHECK_MS 20        // how often to poll the MCP2515 error registers
#define TXFAIL_REINIT_THRESHOLD 10  // consecutive failed sends before forcing re-init
#define RECOVER_COOLDOWN_MS 250   // min spacing between controller re-inits
#define STATUS_PRINT_MS 2000      // serial heartbeat for bench diagnostics

// ─── hardware ────────────────────────────────────────────────────────────────
static const int PIN_CS = 10;
MCP_CAN CAN(PIN_CS);

// ─── CAN IDs ─────────────────────────────────────────────────────────────────
static const unsigned long ID_LOCK_REQ = 0x206;
static const unsigned long ID_REMOTE_REQ = 0x208;
static const unsigned long ID_LOCK_RESP = 0x504;
static const unsigned long ID_REMOTE_RESP = 0x505;
static const unsigned long ID_CRYPTO_CMD = 0x506;
static const unsigned long ID_HEARTBEAT_TX = 0x503;

// ─── retry tuning ────────────────────────────────────────────────────────────
static const int RETRY_COUNT = 5;
static const unsigned long RETRY_INTERVAL_MS = 500;

// ─── crypto constants ────────────────────────────────────────────────────────
static int currentCryptoMode = 0;
static const uint32_t LOWER_XOR_KEY = 0x7869AABC;
static const uint32_t UPPER_M0_PRE = 0xFA457812;
static const uint32_t UPPER_M0_POST = 0x23AABE90;
static const uint32_t UPPER_M0_ROT = 15;
static const uint32_t UPPER_M1_PRE = 0x45AADCBA;
static const uint32_t UPPER_M1_POST = 0xAAED90FA;
static const uint32_t UPPER_M1_ROT = 12;

// ─── MCP2515 EFLG bit masks (datasheet §6.6) ─────────────────────────────────
static const uint8_t EFLG_RX1OVR = 0x80;
static const uint8_t EFLG_RX0OVR = 0x40;
static const uint8_t EFLG_TXBO = 0x20;  // bus-off
static const uint8_t EFLG_TXEP = 0x10;  // TX error-passive
static const uint8_t EFLG_RXEP = 0x08;  // RX error-passive
static const uint8_t EFLG_RXOVR_MASK = (EFLG_RX0OVR | EFLG_RX1OVR);
static const uint8_t EFLG_ERRPASS_MASK = (EFLG_TXEP | EFLG_RXEP);

// ─── fault codes (bitmask, stored in fault log) ──────────────────────────────
static const uint8_t FAULT_BUSOFF = 0x01;
static const uint8_t FAULT_RXOVR = 0x02;
static const uint8_t FAULT_TXFAIL = 0x04;
static const uint8_t FAULT_ERRPASS = 0x08;  // logged for visibility, no re-init

// ─── encrypted-payload pair ─────────────────────────────────────────────────
struct EncryptedPayload {
  uint32_t lo;
  uint32_t hi;
};

// ─── per-channel state ───────────────────────────────────────────────────────
struct Channel {
  unsigned long respId;
  bool pending;
  unsigned char reqData[8];
  int retriesLeft;
  unsigned long lastSendTime;
};

static Channel lockChannel = {ID_LOCK_RESP, false, {}, 0, 0};
static Channel remoteChannel = {ID_REMOTE_RESP, false, {}, 0, 0};

// ─── heartbeat state ─────────────────────────────────────────────────────────
static unsigned long lastHeartbeatTime = 0;
static const unsigned long HEARTBEAT_INTERVAL_MS = 200;

// ─── health / diagnostics state ──────────────────────────────────────────────
struct FaultLog {
  uint8_t magic;            // 0xA5 once initialised
  uint8_t lastFault;        // last FAULT_* that triggered a re-init
  uint16_t recoveryCount;   // total controller re-inits since EEPROM was cleared
  uint8_t maxTEC;           // worst transmit-error-counter ever seen
  uint8_t maxREC;           // worst receive-error-counter ever seen
  uint8_t lastEflg;         // EFLG snapshot at the last fault
};

static const int EEPROM_LOG_ADDR = 0;
static const uint8_t FAULTLOG_MAGIC = 0xA5;
static FaultLog g_log;

static unsigned long lastHealthCheck = 0;
static unsigned long lastRecoverTime = 0;
static unsigned long lastStatusPrint = 0;
static int consecutiveTxFail = 0;

// ─── forward declarations ───────────────────────────────────────────────────
void handleIncoming(unsigned long id, unsigned char buf[8]);
void processPending(Channel &ch, unsigned long now);
void sendRetry(Channel &ch, unsigned long now);
void sendEncrypted(Channel &ch);
void sendEmpty(unsigned long id);
EncryptedPayload scramble(unsigned char data[8], int mode);

void initCan();
void canHealthCheck(unsigned long now);
void recoverController(uint8_t faultMask, uint8_t eflg);
void drainReceive();
void noteTxResult(int result);
void loadFaultLog();
void saveFaultLog();
void printStatus(unsigned long now);

void setup() {
  // Disable the watchdog immediately on boot. If a WDT reset just brought us
  // here, MCUSR/WDTCSR may still be armed; clearing them first prevents a
  // boot-loop on bootloaders that don't do it for us.
  MCUSR = 0;
  wdt_disable();

  // NOTE: no onboard-LED status pin — on the Nano D13 is the SPI SCK line to the
  // MCP2515. Driving it as a GPIO would glitch the CAN clock. Diagnostics go out
  // over Serial + the EEPROM fault log instead.

  Serial.begin(115200);
  delay(1000);

  loadFaultLog();
  Serial.print("Boot. Persisted recoveries=");
  Serial.print(g_log.recoveryCount);
  Serial.print(" lastFault=0x");
  Serial.print(g_log.lastFault, HEX);
  Serial.print(" maxTEC=");
  Serial.print(g_log.maxTEC);
  Serial.print(" maxREC=");
  Serial.println(g_log.maxREC);

  initCan();
  Serial.println("=== T-BOX EMULATOR ACTIVE ===");

#if USE_WATCHDOG
  wdt_enable(WDT_TIMEOUT);
#endif
}

void loop() {
#if USE_WATCHDOG
  wdt_reset();
#endif

  unsigned long now = millis();

  // ── controller health (bus-off / overflow / sustained TX failure) ─────────
  canHealthCheck(now);

  // ── heartbeat ────────────────────────────────────────────────────────────
  if (now - lastHeartbeatTime >= HEARTBEAT_INTERVAL_MS) {
    lastHeartbeatTime = now;
    unsigned char hbData[8] = {0x00, 0x00, 0x00, 0x00, 0x82, 0x17, 0x27, 0x00};
    int r = CAN.sendMsgBuf(ID_HEARTBEAT_TX, 0, 8, hbData);
    noteTxResult(r);
    if (r != CAN_OK) {
      Serial.println("Failed to send Heartbeat 0x503");
    }
  }

  // ── receive (drain EVERY pending frame to avoid RX-buffer overflow) ────────
  drainReceive();

  // ── transmit / retry ─────────────────────────────────────────────────────
  processPending(lockChannel, now);
  processPending(remoteChannel, now);

  // ── bench diagnostics ──────────────────────────────────────────────────────
  printStatus(now);
}

// ─────────────────────────────────────────────────────────────────────────────
// CAN controller init / recovery
// ─────────────────────────────────────────────────────────────────────────────
void initCan() {
  // The old code did `while(1) delay(100)` on failure, which bricked the
  // emulator on a transient boot-time SPI/EMI glitch until a manual reset.
  // Retry a few times instead; if it still fails, proceed anyway — the runtime
  // health monitor / TX-failure detector will keep retrying via begin().
  for (int attempt = 0; attempt < 5; attempt++) {
    if (CAN.begin(MCP_ANY, CAN_250KBPS, MCP_8MHZ) == CAN_OK) {
      CAN.setMode(MCP_NORMAL);
      consecutiveTxFail = 0;
      Serial.println("CAN Init OK");
      return;
    }
    Serial.println("CAN Init Failed, retrying...");
    delay(200);
  }
  CAN.setMode(MCP_NORMAL);
  consecutiveTxFail = 0;
}

// Polls the MCP2515 error registers and re-initialises the controller when it is
// in (or heading toward) an unrecoverable state. This is the core fix for the
// 05200 dropouts.
void canHealthCheck(unsigned long now) {
  if (now - lastHealthCheck < HEALTH_CHECK_MS) return;
  lastHealthCheck = now;

  uint8_t eflg = CAN.getError();      // EFLG register
  uint8_t tec = CAN.errorCountTX();   // transmit error counter
  uint8_t rec = CAN.errorCountRX();   // receive error counter

  if (tec > g_log.maxTEC) g_log.maxTEC = tec;
  if (rec > g_log.maxREC) g_log.maxREC = rec;

  uint8_t fault = 0;
  if (eflg & EFLG_TXBO) fault |= FAULT_BUSOFF;
  if (eflg & EFLG_RXOVR_MASK) fault |= FAULT_RXOVR;
  if (consecutiveTxFail >= TXFAIL_REINIT_THRESHOLD) fault |= FAULT_TXFAIL;

  // Error-passive is a recoverable warning state — log it for visibility, but
  // don't re-init (the bus normally heals on its own).
  if ((eflg & EFLG_ERRPASS_MASK) && g_log.lastFault != FAULT_ERRPASS && fault == 0) {
    g_log.lastFault = FAULT_ERRPASS;
    g_log.lastEflg = eflg;
    saveFaultLog();
  }

  if (fault != 0) {
    recoverController(fault, eflg);
  }
}

void recoverController(uint8_t faultMask, uint8_t eflg) {
  unsigned long now = millis();
  // Debounce: give the controller a moment between re-inits so a persistent
  // condition doesn't spam SPI every loop.
  if (now - lastRecoverTime < RECOVER_COOLDOWN_MS && lastRecoverTime != 0) return;
  lastRecoverTime = now;

  Serial.print("RECOVER fault=0x");
  Serial.print(faultMask, HEX);
  Serial.print(" eflg=0x");
  Serial.println(eflg, HEX);

  // A full begin() resets the MCP2515, clearing bus-off, the error counters and
  // the RX overflow flags, then reconfigures bit timing.
  CAN.begin(MCP_ANY, CAN_250KBPS, MCP_8MHZ);
  CAN.setMode(MCP_NORMAL);
  consecutiveTxFail = 0;

  g_log.recoveryCount++;
  g_log.lastFault = faultMask;
  g_log.lastEflg = eflg;
  saveFaultLog();
}

void noteTxResult(int result) {
  if (result == CAN_OK) {
    consecutiveTxFail = 0;
  } else if (consecutiveTxFail < 1000) {
    consecutiveTxFail++;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// receive — drain all available frames (bounded) so RX buffers never overflow
// ─────────────────────────────────────────────────────────────────────────────
void drainReceive() {
  // A 250 kbps bus tops out around ~2300 frames/s; the loop runs far faster, so
  // a small per-iteration cap keeps up while bounding worst-case loop time.
  for (int i = 0; i < 16 && CAN.checkReceive() == CAN_MSGAVAIL; i++) {
    long unsigned int rxId;
    unsigned char len = 0, buf[8] = {};
    if (CAN.readMsgBuf(&rxId, &len, buf) != CAN_OK) break;
    handleIncoming(rxId, buf);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// incoming-frame router
// ─────────────────────────────────────────────────────────────────────────────
void handleIncoming(unsigned long id, unsigned char buf[8]) {
  Channel *target = nullptr;

  if (id == ID_LOCK_REQ)
    target = &lockChannel;
  else if (id == ID_REMOTE_REQ)
    target = &remoteChannel;
  else if (id == ID_CRYPTO_CMD) {
    if ((buf[1] & 1) == 1) {
      currentCryptoMode = buf[0] & 1;
    } else {
      currentCryptoMode = 0;
    }
    return;
  }

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
    ch.retriesLeft = RETRY_COUNT;
    ch.lastSendTime = now;
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
  EncryptedPayload ep = scramble(ch.reqData, currentCryptoMode);

  unsigned char buf[8];
  for (int i = 0; i < 4; i++) {
    buf[i] = (ep.lo >> (8 * i)) & 0xFF;
    buf[i + 4] = (ep.hi >> (8 * i)) & 0xFF;
  }

  int r = CAN.sendMsgBuf(ch.respId, 0, 8, buf);
  noteTxResult(r);
  if (r != CAN_OK) {
    Serial.print("Failed to send 0x");
    Serial.println(ch.respId, HEX);
  }
}

void sendEmpty(unsigned long id) {
  unsigned char buf[8] = {};

  int r = CAN.sendMsgBuf(id, 0, 8, buf);
  noteTxResult(r);
  if (r != CAN_OK) {
    Serial.print("Failed to send empty 0x");
    Serial.println(id, HEX);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// crypto
//
// VERIFIED bit-for-bit against the original T-Box firmware (STM32, fn @0x08012efc
// and sub-transforms @0x8011378 / @0x800f20c / @0x800f1e4). All constants, the
// mode 0/1 selection, the input (LE 32-bit word of the request), and the output
// byte order match the OEM module exactly.
//
// ⚠ The `(tmp << ROT) | (tmp >> ROT)` below is INTENTIONAL and is NOT a true
// 32-bit rotate (a real rotate would be `>> (32-ROT)`). The OEM firmware really
// does shift by the SAME amount in both directions. Do NOT "fix" this into a
// rotate — it would silently break response compatibility and the bike would
// reject lock/remote replies. (This is why there is no rotateLeft() helper.)
// ─────────────────────────────────────────────────────────────────────────────
uint32_t bytesToU32(unsigned char data[8], int offset) {
  return (uint32_t)data[offset] | ((uint32_t)data[offset + 1] << 8) |
         ((uint32_t)data[offset + 2] << 16) |
         ((uint32_t)data[offset + 3] << 24);
}

EncryptedPayload scramble(unsigned char data[8], int mode) {
  EncryptedPayload ep;

  uint32_t raw = bytesToU32(data, 0);
  ep.lo = raw ^ LOWER_XOR_KEY;

  if (mode == 1) {
    uint32_t tmp = ep.lo ^ UPPER_M1_PRE;
    ep.hi = ((tmp << UPPER_M1_ROT) | (tmp >> UPPER_M1_ROT)) ^ UPPER_M1_POST;
  } else {
    uint32_t tmp = ep.lo ^ UPPER_M0_PRE;
    ep.hi = ((tmp << UPPER_M0_ROT) | (tmp >> UPPER_M0_ROT)) ^ UPPER_M0_POST;
  }

  return ep;
}

// ─────────────────────────────────────────────────────────────────────────────
// fault log (internal ATmega328P EEPROM — no extra hardware needed)
// ─────────────────────────────────────────────────────────────────────────────
void loadFaultLog() {
  EEPROM.get(EEPROM_LOG_ADDR, g_log);
  if (g_log.magic != FAULTLOG_MAGIC) {
    g_log.magic = FAULTLOG_MAGIC;
    g_log.lastFault = 0;
    g_log.recoveryCount = 0;
    g_log.maxTEC = 0;
    g_log.maxREC = 0;
    g_log.lastEflg = 0;
    saveFaultLog();
  }
}

// EEPROM.put() uses update() internally, so unchanged bytes aren't rewritten —
// safe for the chip's ~100k-write endurance since we only call this on events.
void saveFaultLog() {
  EEPROM.put(EEPROM_LOG_ADDR, g_log);
}

void printStatus(unsigned long now) {
  if (now - lastStatusPrint < STATUS_PRINT_MS) return;
  lastStatusPrint = now;

  Serial.print("STATUS t=");
  Serial.print(now);
  Serial.print(" TEC=");
  Serial.print(CAN.errorCountTX());
  Serial.print(" REC=");
  Serial.print(CAN.errorCountRX());
  Serial.print(" EFLG=0x");
  Serial.print(CAN.getError(), HEX);
  Serial.print(" txfail=");
  Serial.print(consecutiveTxFail);
  Serial.print(" recov=");
  Serial.print(g_log.recoveryCount);
  Serial.print(" lastFault=0x");
  Serial.print(g_log.lastFault, HEX);
  Serial.print(" maxTEC=");
  Serial.print(g_log.maxTEC);
  Serial.print(" maxREC=");
  Serial.println(g_log.maxREC);
}
