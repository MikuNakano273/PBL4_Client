from Crypto.Random import get_random_bytes
open("crypto_config.py", "wb").write(get_random_bytes(32))