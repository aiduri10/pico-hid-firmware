#ifndef BTSTACK_CONFIG_H
#define BTSTACK_CONFIG_H

// BLE peripheral only (no Classic BT, no Central role)
#define ENABLE_LE_PERIPHERAL
#define ENABLE_LOG_ERROR

// Buffer sizes for CYW43 shared bus stability
#define HCI_OUTGOING_PRE_BUFFER_SIZE      4
#define HCI_ACL_PAYLOAD_SIZE              256
#define HCI_ACL_CHUNK_SIZE_ALIGNMENT      4

// Connection/service limits
#define MAX_NR_HCI_CONNECTIONS            1
#define MAX_NR_L2CAP_CHANNELS             2
#define MAX_NR_L2CAP_SERVICES             1
#define MAX_NR_SM_LOOKUP_ENTRIES          2
#define MAX_NR_WHITELIST_ENTRIES          1
#define MAX_NR_LE_DEVICE_DB_ENTRIES       4
#define MAX_NR_GATT_CLIENTS               1
#define NVM_NUM_DEVICE_DB_ENTRIES         4
#define NVM_NUM_LINK_KEYS                 4
#define ENABLE_PRINTF_HEXDUMP

// Prevent CYW43 shared bus overrun
#define MAX_NR_CONTROLLER_ACL_BUFFERS     3
#define MAX_NR_CONTROLLER_SCO_PACKETS     3
#define ENABLE_HCI_CONTROLLER_TO_HOST_FLOW_CONTROL
#define HCI_HOST_ACL_PACKET_LEN           256
#define HCI_HOST_ACL_PACKET_NUM           3
#define HCI_HOST_SCO_PACKET_LEN           120
#define HCI_HOST_SCO_PACKET_NUM           3

// Fixed-size ATT DB (no malloc needed)
#define MAX_ATT_DB_SIZE                   512

// Required HAL
#define HAVE_EMBEDDED_TIME_MS
#define HAVE_ASSERT

#define HCI_RESET_RESEND_TIMEOUT_MS       1000
#define ENABLE_SOFTWARE_AES128
#define ENABLE_MICRO_ECC_FOR_LE_SECURE_CONNECTIONS

#endif
