#!/usr/bin/env python3

f = ""
try:
    f = open('debug.dmp', 'rb')
except FileNotFoundError:
    print("找不到转储文件")
    exit()

full_data = f.read()
f.close()

valid_signature = bytes([0x4d, 0x44, 0x4d, 0x50, 0x93, 0xa7, 0x00, 0x00])  # 有效的 minidump 签名字节
restored = valid_signature + full_data[8:]  # 恢复损坏的字节为有效的 minidump 签名

with open('debug.dmp', 'wb') as f:  # 写入可读数据
    f.write(restored)

print("文件签名已恢复")