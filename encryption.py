from sympy import isprime
import random

# Source: https://www.math.brown.edu/johsilve/MathCrypto/SampleSections.pdf


def generate_large_prime(bits=1024):
    while True:
        # First, what we do is generate a random number with x bits
        # Here we use random module because it is easier than doing it ourselves
        num = random.getrandbits(bits)
        # Then, we force the number to be odd!
        num |= (1 << bits - 1) | 1
        # Finally, we check if the number is prime using sympy
        if isprime(num):
            return num


def generate_generator(prime):
    for i in range(2, prime):
        # For the generator to be valid, we have following conditions:
        # 1. 1 < generator < prime - 1
        # 2. generator ^ ((prime - 1) / 2) mod prime != 1
        # 3. generator ^ (prime - 1) mod prime == 1

        if pow(i, (prime - 1) // 2, prime) != 1 and pow(i, prime - 1, prime) == 1:
            return i


def generate_keys(prime, generator):
    # This one is mainly for Alice, she needs to generate a public and private key
    # Then for the keys:
    # For the private one, we generate a random number between 1 and prime - 1
    private_key = random.randint(1, prime - 1)
    # For the public one, we calculate the generator to the power of the private key mod prime
    # We can also write it as A = g^a mod p
    public_key = pow(generator, private_key, prime)
    return public_key, private_key


def encrypt(message, prime, generator, public_key):
    # This one is for Bob, he needs to encrypt the message using the public key of Alice
    r = random.randint(1, prime - 1)
    c1 = pow(generator, r, prime)
    c2 = (message * pow(public_key, r, prime)) % prime
    return c1, c2


def decrypt(c1, c2, prime, private_key):
    # This one is for Alice, she needs to decrypt the message from Bob using her private key
    message = (c2 * pow(c1, prime - 1 - private_key, prime)) % prime
    return message


def generate_shared_secret_key(prime, public_key, private_key):
    shared_secret_key = pow(public_key, private_key, prime)
    return shared_secret_key


def message_to_number(message):
    # Convert the message to its hexadecimal representation
    hex_message = message.encode('utf-8').hex()
    # Convert the hexadecimal string to an integer
    number = int(hex_message, 16)
    return number


def number_to_message(number):
    # Convert the number to its hexadecimal representation
    hex_message = hex(number)[2:]
    # Ensure the hexadecimal string has an even length
    if len(hex_message) % 2:
        hex_message = '0' + hex_message
    # Convert the hexadecimal string to bytes
    message_bytes = bytes.fromhex(hex_message)
    # Decode the bytes to a UTF-8 string
    message = message_bytes.decode('utf-8')
    return message
