#!/usr/bin/env python3

# https://www.geeksforgeeks.org/rsa-digital-signature-scheme-using-python/

import random


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
                    v = (v ** 2) % num
    return True


def is_prime(num):
    if (num < 2):
        return False
    low_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]
    if num in low_primes:
        return True
    for prime in low_primes:
        if (num % prime == 0):
            return False
    return rabin_miller(num)


# Generate a prime number the specified number of bits in length
# E.g. 181 is 1011 0101, 137 is 1000 1001
def generate_prime(key_size):
    while True:
        num = random.randrange(2**(key_size-1), 2**(key_size))
        if is_prime(num):
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

        q = r1//r2
        r = r1-q * r2
        r1 = r2
        r2 = r
        s = s1-q * s2
        s1 = s2
        s2 = s
        t = t1-q * t2
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


def select_key_from_keys(keys):
    return keys[random.randint(0, len(keys))]


def get_decryption_key(pn, e):
    r, d = exteuclid(pn, e)
    if r == 1:
        return d
    else:
        return None


# TODO - Something sensible with this while loop
def get_e_and_d(keys, pn):
    tried_keys = []
    while 1:
        e = select_key_from_keys(keys)
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
    message = ''
    for e_int in encrypted_ints:
        int_ = rsa(e_int, key_unique_element, n)
        char = chr(int_)
        message = '{}{}'.format(message, char)
    return message


def loop_test():
    fails = 0
    for i in range(0, 255):
        s = rsa(i, d, n)
        u = rsa(s, e, n)
        if u != i:
            fails += 1
    print('Fails: ', fails)


def reverse_loop_test():
    fails = 0
    for i in range(0, 255):
        s = rsa(i, e, n)
        u = rsa(s, d, n)
        if u != i:
            fails += 1
    print('Fails: ', fails)

key_size=8

p = generate_prime(key_size)
q = generate_prime(key_size)
n = p * q
pn = (p-1)*(q-1)
keys = get_keys(pn)
e, d, tried_keys = get_e_and_d(keys, pn)

# private_key = [key_size, d, n]
# public_key = [key_size, e, n]

print('Key size: ', key_size, ' bits')
print('Prime A (p): ', p)
print('Prime B (q): ', q)
print('A * B | (n): ', n)
print('(A-1) * (B-1) | (pn): ', pn)
print('List of possible keys where 1<key<pn has {} items'.format(str(len(keys))))
print('Tried the following possible keys to find one with a reciprocal of pn and e:')
for i in range(len(tried_keys)):
    print('Key ', i+1, ': ', tried_keys[i])
print('Unique element of public key (e): ', e)
print('Unique element of private key (d): ', d)


message = 'ABCDEFGHIJabcdefghij'
print(message)
m_enc = encrypt(message, e, n)
print(m_enc)
m_dec = decrypt(m_enc, d, n)
print(m_dec)


loop_test()

reverse_loop_test()

