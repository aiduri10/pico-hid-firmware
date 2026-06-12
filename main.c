#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "pico/btstack_cyw43.h"
#include "pico/rand.h"
#include "hardware/sync.h"
#include "btstack_event.h"
#include "btstack_run_loop.h"
#include "btstack_crypto.h"    // btstack_aes128_calc()
#include "btstack_tlv.h"
#include "btstack_tlv_flash_bank.h"
#include "pico/btstack_flash_bank.h"
#include "uECC.h"              // P-256 ECDH (compiled as part of pico_btstack_ble)
#include "gap.h"
#include "hci.h"
#include "l2cap.h"
#include "ble/sm.h"
#include "ble/att_server.h"
#include "ble/att_db.h"
#include "keyboard.h"
#include "tusb.h"

// ── Characteristic handle aliases ────────────────────────────────────────────
#define HID_REPORT_HANDLE \
    ATT_CHARACTERISTIC_12340002_0000_1000_8000_00805F9B34FB_01_VALUE_HANDLE
#define PICO_PUBKEY_HANDLE \
    ATT_CHARACTERISTIC_12340004_0000_1000_8000_00805F9B34FB_01_VALUE_HANDLE
#define HOST_PUBKEY_HANDLE \
    ATT_CHARACTERISTIC_12340005_0000_1000_8000_00805F9B34FB_01_VALUE_HANDLE

#define REPORT_SIZE      8
#define ENC_PAYLOAD_SIZE 20   // 4-byte counter + 16-byte AES-CTR (press+release combined)
#define QUEUE_SIZE       32   // 2 slots per BLE packet (press+release), doubled for headroom
#define PUBKEY_SIZE      64   // P-256 public key: raw X||Y (32+32 bytes)

// ── ECDH session state ────────────────────────────────────────────────────────
static uint8_t app_public_key[PUBKEY_SIZE];  // served to host via READ
static uint8_t app_private_key[32];          // kept in RAM, gone on power cycle

// Set by att_write_callback (IRQ), consumed by main loop
static uint8_t host_public_key[PUBKEY_SIZE];
static volatile bool host_pubkey_received = false;

// Session key derived from ECDH — replaces static PSK
static uint8_t session_aes_key[16];  // dhkey[0:16]
static uint8_t session_aes_iv[8];    // dhkey[16:24]
static volatile bool session_key_ready = false;

// ── HID ring buffer ───────────────────────────────────────────────────────────
static uint8_t  rq_buf[QUEUE_SIZE][REPORT_SIZE];
static uint8_t  rq_head  = 0;
static uint8_t  rq_tail  = 0;
static volatile uint8_t  rq_count   = 0;
static volatile uint32_t rx_counter = 0;

static btstack_packet_callback_registration_t hci_event_cb_reg;
static btstack_packet_callback_registration_t sm_event_cb_reg;
static btstack_tlv_flash_bank_t               tlv_flash_bank_context;
static hci_con_handle_t current_con_handle = HCI_CON_HANDLE_INVALID;

static const uint8_t adv_data[] = {
    0x02, 0x01, 0x06,
    0x08, 0x09, 'P','i','c','o','H','I','D',
};

// ── RNG for uECC ─────────────────────────────────────────────────────────────
static int uecc_rng(uint8_t *dest, unsigned size) {
    for (unsigned i = 0; i < size; ) {
        uint32_t r = get_rand_32();
        unsigned chunk = (size - i < 4u) ? (size - i) : 4u;
        memcpy(dest + i, &r, chunk);
        i += chunk;
    }
    return 1;
}

// ── AES-128-CTR decrypt 16 bytes (press+release pair) ────────────────────────
// One full AES block = press(8) + release(8). No keystream waste.
// Nonce block: session_aes_iv(8) || counter BE(4) || 0x00(4)
static void aes128_ctr_decrypt_pair(const uint8_t *ct, uint32_t counter, uint8_t *pt) {
    uint8_t nonce_block[16] = {0};
    uint8_t keystream[16];
    memcpy(nonce_block, session_aes_iv, 8);
    nonce_block[8]  = (uint8_t)(counter >> 24);
    nonce_block[9]  = (uint8_t)(counter >> 16);
    nonce_block[10] = (uint8_t)(counter >> 8);
    nonce_block[11] = (uint8_t)(counter);
    btstack_aes128_calc(session_aes_key, nonce_block, keystream);
    for (int i = 0; i < 16; i++) pt[i] = ct[i] ^ keystream[i];
}

// ── BTstack / SM event handler ────────────────────────────────────────────────
static void packet_handler(uint8_t packet_type, uint16_t channel,
                           uint8_t *packet, uint16_t size) {
    UNUSED(channel); UNUSED(size);
    if (packet_type != HCI_EVENT_PACKET) return;

    switch (hci_event_packet_get_type(packet)) {
        case BTSTACK_EVENT_STATE:
            if (btstack_event_state_get_state(packet) == HCI_STATE_WORKING) {
                gap_advertisements_set_data(sizeof(adv_data), (uint8_t *)adv_data);
                gap_advertisements_enable(1);
                printf("BLE ready — advertising as PicoHID\n");
            }
            break;

        case HCI_EVENT_LE_META:
            if (hci_event_le_meta_get_subevent_code(packet) ==
                    HCI_SUBEVENT_LE_CONNECTION_COMPLETE) {
                current_con_handle   = hci_subevent_le_connection_complete_get_connection_handle(packet);
                rx_counter           = 0;
                session_key_ready    = false;
                host_pubkey_received = false;
                printf("Host PC connected\n");
            }
            break;

        case HCI_EVENT_DISCONNECTION_COMPLETE:
            session_key_ready    = false;
            host_pubkey_received = false;
            rx_counter           = 0;
            gap_advertisements_enable(1);
            printf("Disconnected — re-advertising (ECDH handshake required on reconnect)\n");
            break;

        case SM_EVENT_JUST_WORKS_REQUEST:
            sm_just_works_confirm(sm_event_just_works_request_get_handle(packet));
            printf("LESC JustWorks: confirmed\n");
            break;

        case SM_EVENT_PAIRING_COMPLETE:
            if (sm_event_pairing_complete_get_status(packet) == ERROR_CODE_SUCCESS) {
                // Request shorter connection interval after pairing completes.
                // 6×1.25ms = 7.5ms min, 12×1.25ms = 15ms max → ~10× faster than default
                gap_request_connection_parameter_update(current_con_handle, 6, 12, 0, 200);
                printf("LESC pairing complete — requested 7.5ms connection interval\n");
            } else {
                printf("Pairing failed (0x%02x)\n",
                       sm_event_pairing_complete_get_status(packet));
            }
            break;

        case SM_EVENT_IDENTITY_CREATED:
            printf("Bonding saved to flash\n");
            break;

        case SM_EVENT_IDENTITY_RESOLVING_SUCCEEDED:
            gap_request_connection_parameter_update(current_con_handle, 6, 12, 0, 200);
            printf("Bonded device — link re-encrypting, requesting fast interval\n");
            break;
    }
}

// ── ATT callbacks ─────────────────────────────────────────────────────────────
static uint16_t att_read_callback(hci_con_handle_t con_handle, uint16_t att_handle,
                                   uint16_t offset, uint8_t *buffer, uint16_t buffer_size) {
    UNUSED(con_handle);

    if (att_handle == PICO_PUBKEY_HANDLE) {
        if (offset >= PUBKEY_SIZE) return 0;
        uint16_t remaining = PUBKEY_SIZE - offset;
        uint16_t to_copy   = remaining < buffer_size ? remaining : buffer_size;
        if (buffer) memcpy(buffer, app_public_key + offset, to_copy);
        return buffer ? to_copy : PUBKEY_SIZE;
    }
    return 0;
}

// Called from BTstack background IRQ context
static int att_write_callback(hci_con_handle_t con_handle, uint16_t att_handle,
                               uint16_t transaction_mode, uint16_t offset,
                               uint8_t *buffer, uint16_t buffer_size) {
    UNUSED(con_handle); UNUSED(transaction_mode); UNUSED(offset);

    if (att_handle == HOST_PUBKEY_HANDLE && buffer_size == PUBKEY_SIZE) {
        memcpy(host_public_key, buffer, PUBKEY_SIZE);
        host_pubkey_received = true;
        printf("Host pubkey received — computing DH\n");
        return 0;
    }

    if (att_handle == HID_REPORT_HANDLE &&
        buffer_size >= ENC_PAYLOAD_SIZE && session_key_ready) {

        uint32_t counter = ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
                           ((uint32_t)buffer[2] << 8)  |  (uint32_t)buffer[3];

        if (counter < rx_counter) return 0;
        rx_counter = counter + 1;

        // Decrypt 16 bytes: press(8) + release(8) combined in one AES block
        uint8_t pair[16];
        aes128_ctr_decrypt_pair(&buffer[4], counter, pair);

        uint32_t save = save_and_disable_interrupts();
        if (rq_count + 2 <= QUEUE_SIZE) {
            memcpy(rq_buf[rq_tail], pair,              REPORT_SIZE);  // press
            rq_tail = (rq_tail + 1) % QUEUE_SIZE;
            memcpy(rq_buf[rq_tail], pair + REPORT_SIZE, REPORT_SIZE); // release
            rq_tail = (rq_tail + 1) % QUEUE_SIZE;
            rq_count += 2;
        }
        restore_interrupts(save);
    }
    return 0;
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(void) {
    stdio_init_all();
    tusb_init();

    // Generate P-256 keypair before BTstack starts (synchronous, ~100ms on RP2040).
    // Key lives in RAM only — power cycle automatically regenerates it.
    uECC_set_rng(uecc_rng);
    if (!uECC_make_key(app_public_key, app_private_key)) {
        printf("ECDH key generation failed\n");
        return -1;
    }
    printf("P-256 keypair ready\n");

    if (cyw43_arch_init()) {
        printf("cyw43_arch_init failed\n");
        return -1;
    }

    btstack_cyw43_init(cyw43_arch_async_context());

    // Persistent bonding (flash TLV)
    const btstack_tlv_t *tlv_impl = btstack_tlv_flash_bank_init_instance(
        &tlv_flash_bank_context, pico_flash_bank_instance(), NULL);
    btstack_tlv_set_instance(tlv_impl, &tlv_flash_bank_context);

    l2cap_init();
    sm_init();
    att_server_init(profile_data, att_read_callback, att_write_callback);

    hci_event_cb_reg.callback = &packet_handler;
    hci_add_event_handler(&hci_event_cb_reg);

    sm_event_cb_reg.callback = &packet_handler;
    sm_add_event_handler(&sm_event_cb_reg);

    sm_set_io_capabilities(IO_CAPABILITY_NO_INPUT_NO_OUTPUT);
    sm_set_authentication_requirements(SM_AUTHREQ_SECURE_CONNECTION | SM_AUTHREQ_BONDING);

    hci_power_control(HCI_POWER_ON);
    printf("Pico BT HID Bridge started (LESC + ECDH + AES-128-CTR)\n");

    while (true) {
        tud_task();

        // Derive session key from ECDH (blocking ~100ms, done once per connection)
        if (host_pubkey_received && !session_key_ready) {
            host_pubkey_received = false;
            uint8_t dhkey[32];
            uECC_shared_secret(host_public_key, app_private_key, dhkey);
            memcpy(session_aes_key, dhkey, 16);
            memcpy(session_aes_iv,  dhkey + 16, 8);
            session_key_ready = true;
            printf("Session key derived — ready for HID data\n");
        }

        if (session_key_ready && tud_hid_ready() && rq_count > 0) {
            uint32_t save = save_and_disable_interrupts();
            uint8_t report[REPORT_SIZE];
            memcpy(report, rq_buf[rq_head], REPORT_SIZE);
            rq_head = (rq_head + 1) % QUEUE_SIZE;
            rq_count--;
            restore_interrupts(save);

            tud_hid_keyboard_report(0, report[0], &report[2]);
        }

        // Sleep until the next interrupt (BTstack alarm or USB).
        // Eliminates coil whine from the power regulator spinning at idle.
        __wfi();
    }
}
