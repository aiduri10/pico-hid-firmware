# pico-hid-firmware

Raspberry Pi Pico W BLE-to-USB HID keyboard bridge firmware.

Turns a Pico W into a wireless keyboard injector: a Linux/Windows host program
connects over BLE and sends keystrokes; the Pico relays them to the target PC
via USB HID — like a programmable hardware keyboard.

```
Host PC ──BLE──▶ Pico W ──USB HID──▶ Target PC
(python)                              (any OS)
```

## Features

- **LESC** (BLE LE Secure Connections) — AES-128-CCM link encryption
- **ECDH handshake** — P-256 ephemeral keypair, new session key every connection
- **AES-128-CTR** payload encryption — HID reports encrypted at app layer
- **Combined press+release** in one 20-byte BLE packet — fast keystroke delivery
- Write-Without-Response — no ATT ACK round-trips, ~1 keystroke/second throughput

## Host software

Get the host program (Linux/Windows) from the companion repo:
**[pico-hid-host](https://github.com/aiduri10/pico-hid-host)**

## Build

Requirements: [Pico SDK](https://github.com/raspberrypi/pico-sdk) with BTstack and TinyUSB.

```bash
export PICO_SDK_PATH=/path/to/pico-sdk

mkdir build && cd build
cmake ..
make -j$(nproc)
```

This produces `pico_bt_hid.uf2`.

## Flash

1. Hold BOOTSEL on the Pico W and connect USB → it mounts as a drive
2. Copy `build/pico_bt_hid.uf2` to the drive
3. Pico reboots and starts advertising as **PicoHID**

## Pairing

**Linux**: Run the host program — it calls `bluetoothctl pair` automatically.  
To re-pair from a different PC, remove the old bond first:
```bash
bluetoothctl remove <MAC>
```

**Windows**: Windows shows a pairing dialog on first connection.  
To re-pair, remove the device in Settings → Bluetooth first.

## Security

| Layer | Mechanism |
|-------|-----------|
| BLE link | LESC (ECDH + AES-128-CCM) |
| App layer | ECDH P-256 handshake → AES-128-CTR session key |

No static PSK — forward secrecy via ephemeral keypairs.

## Debug

UART debug output on GPIO 0 (TX) / GPIO 1 (RX) at 115200 baud.

```bash
minicom -b 115200 -D /dev/ttyUSB0
```
