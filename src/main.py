from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

import argparse

parser = argparse.ArgumentParser(description='Encrypt text with AES')
parser.add_argument('--text', help='enrypt text or decrypt text')
parser.add_argument('--mode', help='encrypt or decrypt', default='encrypt')
parser.add_argument('--key', help='encrypt key or decrypt key')
parser.add_argument('--size', help='aes encrypt segmentsize', default=128)
parser.add_argument('--iv', help='encrypt key or decrypt key', default='1234567890123456')
parser.add_argument('--style', help='padding style', default='pkcs7')
parser.add_argument('--encode', help='encode style', default='utf8')
args = parser.parse_args()


def cfb_encrypt(text: str, key: str, iv: str, encode: str, style: str, segment_size: int):
    """encrypt text with aes cfb mode

    Args:
        text (str): plain text
        key (str): aes key
        iv (str): offset
        encode (str): encrypt encode
        style (str): padding style
        segment_size (int): segment size

    Returns:
        str: return base64 text
    """
    cryptor = AES.new(key=key.encode(encode), mode=AES.MODE_CFB, iv=iv.encode(encode), segment_size=segment_size)
    text_bytes = text.encode(encode)
    padding_bytes = pad(text_bytes, AES.block_size, style=style)
    encrypt_bytes = cryptor.encrypt(padding_bytes)
    base64_text = b64encode(encrypt_bytes).decode(encode)
    return base64_text


def cfb_decrypt(text: str, key: str, iv: str, encode: str, style: str, segment_size: int):
    """decrypt text with aes cfb mode

    Args:
        text (str): plain text
        key (str): aes key
        iv (str): offset
        encode (str): encrypt encode
        style (str): padding style
        segment_size (int): segment size

    Returns:
        str: return plain text
    """
    cryptor = AES.new(key=key.encode(encode), mode=AES.MODE_CFB, iv=iv.encode(encode), segment_size=segment_size)
    base64_text = b64decode(text)
    padding_bytes = cryptor.decrypt(base64_text)
    text_bytes = unpad(padded_data=padding_bytes, block_size=AES.block_size, style=style)
    plain_text = text_bytes.decode(encode)
    return plain_text


if __name__ == '__main__':
    if args.mode == 'encrypt':
        base64_text = cfb_encrypt(text=args.text, key=args.key, iv=args.iv, encode=args.encode, style=args.style, segment_size=int(args.size))
        print(base64_text)
    if args.mode == 'decrypt':
        plain_text = cfb_decrypt(text=args.text, key=args.key, iv=args.iv, encode=args.encode, style=args.style, segment_size=int(args.size))
        print(plain_text)
