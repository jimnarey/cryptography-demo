#!/usr/bin/env python3

# https://www.geeksforgeeks.org/rsa-digital-signature-scheme-using-python/

import random
import lib.low_primes as low_primes

# The Rabin Miller algorithm for checking whether a number is
# prime. It's not fast, so call as a last resort
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


# Check whether a given number is a prime by:
# - checking against a list of known primes < 1000
# - checking whether input can be evenly divided by those primes
# - if in doubt, call rabin_miller
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


# Find greatest common divisor of m & n
def euclid(m, n):
    if n == 0:
        return m
    else:
        r = m % n
        return euclid(n, r)


# Generate a list of possible values for 'e', the unique part of the public key
# It must be greater than 1 and less than 'pn' which is (p-1) * (q -1)
# 'e' and 'pn' must be coprime
def get_potential_public_key_parts(pn):
    keys = []
    for i in range(2, pn):
        gcd = euclid(pn, i)
        if gcd == 1:
            keys.append(i)
    return keys


# A version of the extended Euclidean algorithm
# Return the gcd of a and b
# Return d where e * d % pn = 1
def get_ed_mod_pn_is_1(pn, e):

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

    gcd = r1
    d = t1

    return gcd, d

# Call the ext euclid algorithm and check there is a valid
# value for d (there may not be, for any given value of e)
# TODO - check validity of last statement
def get_private_key(pn, e):
    gcd, d = get_ed_mod_pn_is_1(pn, e)
    if gcd == 1:
        return d
    else:
        return None


# Get the unique part of the public key ('e') and the unique part of the private key ('d')
# Start with the list of potential values for e. Go through them one-by-one in random order
# and test whether there is a value (d) which satisfies
def find_valid_key_pair(keys, pn):
    random.shuffle(keys)
    tried_keys = []
    for i in range(len(keys)):
        e = keys[i]
        tried_keys.append(e)
        d = get_private_key(pn, e)
        if d:
            return e, d, tried_keys


# The rsa algorithm itself
def rsa(message, key_unique_element, n):
    return pow(message, key_unique_element, n)


# Converts a string into ints, encrypts it and generates a single, output string
def encrypt(message, key_unique_element, n):
    encrypted_ints = []
    for char in message:
        int_ = ord(char)
        e_int = rsa(int_, key_unique_element, n)
        encrypted_ints.append(e_int)
    return '-'.join([str(val) for val in encrypted_ints])

# Takes an encrypted string (from the encrypt function), turns the constituent string-type numbers
# into ints, decrypts and builds an output string
def decrypt(encrypted_message, key_unique_element, n):
    message = ""
    for e_int in [int(val) for val in encrypted_message.split('-')]:
        int_ = rsa(e_int, key_unique_element, n)
        char = chr(int_)
        message = "{}{}".format(message, char)
    return message


def generate_keys():
    key_size = 8
    p = generate_prime(key_size)
    q = generate_prime(key_size, exclude=p)
    n = p * q
    pn = (p - 1) * (q - 1)
    keys = get_potential_public_key_parts(pn)
    e, d, tried_keys = find_valid_key_pair(keys, pn)
    print("Key size: ", key_size, " bits")
    print("Prime A (p): ", p)
    print("Prime B (q): ", q)
    print("(A-1) * (B-1) | (pn): ", pn)
    print("List of possible keys where 1<key<pn and pn & key are coprime has {} items".format(str(len(keys))))
    print("Tried the following possible keys to find one with a valid value for d:")
    for i in range(len(tried_keys)):
        print("Key ", i + 1, ": ", tried_keys[i])
    print("Unique element of public key 'e'': ", e)
    print("Unique element of private key 'd': ", d)
    print("Shared element of public and private keys, p * q 'n': ", n)
