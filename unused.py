
def get_blocks_from_text(message, block_size=128):
    message_bytes = message.encode('ascii')
    block_ints = []
    for block_start in range(0, len(message_bytes), block_size):
        block_int = 0
        for i in range(block_start, min(block_start + block_size, len(message_bytes))):
            block_int += message_bytes[i] * (256 ** (i % 256))
        block_ints.append(block_int)
    return block_ints

def get_text_from_blocks(block_ints, message_length, block_size=128):
    message = []
    for block_int in block_ints:
        block_message = []
        for i in range(block_size -1, -1, -1):
            if len(message) + i < message_length:
                ascii_num = block_int // (256 ** i)
                block_int = block_int % (256 ** i)
                block_message.insert(0, chr(ascii_num))
        message.extend(block_message)
    return ''.join(message)

def encrypt(message, e, n, block_size=128):
    encrypted_blocks = []
    for block in get_blocks_from_text(message, block_size):
        encrypted_blocks.append(pow(block, e, n))
    return encrypted_blocks

def decrypt(encrypted_blocks, message_length, d, n, block_size=128):
    decrypted_blocks = []
    for block in encrypted_blocks:
        decrypted_blocks.append(pow(block, d, n))
    return get_text_from_blocks(decrypted_blocks, message_length, block_size)


def sign(message, d, n):
    message_blocks = get_blocks_from_text(message)
    return (message_blocks**d) % n

def unsign(signature, e, n):
    message_blocks =  (signature**e) % n
    return get_text_from_blocks(message_blocks)

