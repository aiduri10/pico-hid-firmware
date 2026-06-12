cmake_minimum_required(VERSION 3.13)

set(PICO_BOARD pico_w)
include($ENV{PICO_SDK_PATH}/external/pico_sdk_import.cmake)

project(pico_bt_hid C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_bt_hid
    main.c
    usb_descriptors.c
)

# Generate keyboard.h from keyboard.gatt (defines profile_data and ATT handles)
# Must be called after add_executable
pico_btstack_make_gatt_header(pico_bt_hid PRIVATE "${CMAKE_CURRENT_LIST_DIR}/keyboard.gatt")

target_include_directories(pico_bt_hid PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}      # tusb_config.h
    ${CMAKE_CURRENT_BINARY_DIR}    # fallback for generated headers
)

target_link_libraries(pico_bt_hid
    pico_stdlib
    pico_cyw43_arch_none  # BT-only: sets CYW43_LWIP=0, internally uses threadsafe_background
    pico_btstack_ble
    pico_btstack_cyw43
    pico_btstack_flash_bank  # persistent bonding key storage (last 2 flash sectors)
    pico_rand                # hardware RNG for uECC P-256 key generation
    tinyusb_device
    tinyusb_board
)

pico_add_extra_outputs(pico_bt_hid)
pico_enable_stdio_usb(pico_bt_hid 0)   # USB used for HID, not stdio
pico_enable_stdio_uart(pico_bt_hid 1)  # Debug via UART (GPIO 0/1)
