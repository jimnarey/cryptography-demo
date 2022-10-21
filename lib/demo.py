#!/usr/bin/env python3

# https://www.geeksforgeeks.org/rsa-digital-signature-scheme-using-python/

import random
import lib.low_primes as low_primes

def rabin_miller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    for _ in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v**2) % num
    return True


def is_prime(num):
    if num < 2:
        return False
    if num in low_primes.LOW_PRIMES:
        return True
    for prime in low_primes.LOW_PRIMES:
        if num % prime == 0:
            return False
    return rabin_miller(num)


# Generate a prime number the specified number of bits in length
# E.g. 181 is 1011 0101, 137 is 1000 1001
def generate_prime(key_size, exclude=None):
    while True:
        num = random.randrange(2 ** (key_size - 1), 2 ** (key_size))
        if is_prime(num) and num != exclude:
            return num


# Find greatest common denominator of m & n
def euclid(m, n):
    if n == 0:
        return m
    else:
        r = m % n
        return euclid(n, r)


# TODO - explain this
def exteuclid(pn, e):

    r1 = pn
    r2 = e
    s1 = int(1)
    s2 = int(0)
    t1 = int(0)
    t2 = int(1)

    while r2 > 0:

        q = r1 // r2
        r = r1 - q * r2
        r1 = r2
        r2 = r
        s = s1 - q * s2
        s1 = s2
        s2 = s
        t = t1 - q * t2
        t1 = t2
        t2 = t

    if t1 < 0:
        t1 = t1 % pn

    return (r1, t1)


def get_keys(pn):
    keys = []
    for i in range(2, pn):
        gcd = euclid(pn, i)
        if gcd == 1:
            keys.append(i)
    return keys


def get_decryption_key(pn, e):
    r, d = exteuclid(pn, e)
    if r == 1:
        return d
    else:
        return None


def get_e_and_d(keys, pn):
    random.shuffle(keys)
    tried_keys = []
    for i in range(len(keys)):
        e = keys[i]
        tried_keys.append(e)
        d = get_decryption_key(pn, e)
        if d:
            return e, d, tried_keys



def rsa(message, key_unique_element, n):
    return pow(message, key_unique_element, n)


def encrypt(message, key_unique_element, n):
    encrypted_ints = []
    for char in message:
        int_ = ord(char)
        e_int = rsa(int_, key_unique_element, n)
        encrypted_ints.append(e_int)
    return encrypted_ints


def decrypt(encrypted_ints, key_unique_element, n):
    message = ""
    for e_int in encrypted_ints:
        int_ = rsa(e_int, key_unique_element, n)
        char = chr(int_)
        message = "{}{}".format(message, char)
    return message


def demo():
    key_size = 8
    p = generate_prime(key_size)
    q = generate_prime(key_size, exclude=p)
    n = p * q
    pn = (p - 1) * (q - 1)
    keys = get_keys(pn)
    e, d, tried_keys = get_e_and_d(keys, pn)
    print("Key size: ", key_size, " bits")
    print("Prime A (p): ", p)
    print("Prime B (q): ", q)
    print("A * B | (n): ", n)
    print("(A-1) * (B-1) | (pn): ", pn)
    print("List of possible keys where 1<key<pn has {} items".format(str(len(keys))))
    print("Tried the following possible keys to find one with a reciprocal of pn and e:")
    for i in range(len(tried_keys)):
        print("Key ", i + 1, ": ", tried_keys[i])
    print("Unique element of public key (e): ", e)
    print("Unique element of private key (d): ", d)
    message = "ABCDEFGHIJabcdefghij"
    print('Message to encrypt: ', message)
    m_enc = encrypt(message, e, n)
    print('Encrypted message: ', m_enc)
    m_dec = decrypt(m_enc, d, n)
    print('Decrypted message: ', m_dec)
