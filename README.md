# Cryptography_RTU

## Overview
This project demonstrates the ElGamal encryption scheme using a Streamlit web application. The app guides users through generating keys, encrypting a message, and decrypting it.

## Features
- Key Generation
- Public and Private Keys
- Message Encryption
- Message Decryption
- Mathematical Explanation

## Installation
1. Clone the repository:
    ```sh
    git clone https://github.com/SolaZn/Cryptography_RTU.git
    cd Cryptography_RTU
    ```
2. Create a virtual environment and activate it:
    ```sh
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
3. Install the required packages:
    ```sh
    pip install -r requirements.txt
    ```

## Usage
1. Run the Streamlit application:
    ```sh
    streamlit run main.py
    ```
2. Follow the instructions on the web interface to generate keys, encrypt, and decrypt messages.

## Project Structure
- `main.py`: The main Streamlit application file.
- `encryption.py`: Functions for key generation, encryption, and decryption.
- `requirements.txt`: Required Python packages.

## Key Functions
- `generate_large_prime(bits)`: Generates a large prime number.
- `generate_generator(prime)`: Generates a generator for the prime number.
- `generate_keys(prime, generator)`: Generates a public and private key pair.
- `encrypt(message, prime, generator, public_key)`: Encrypts a message.
- `decrypt(c1, c2, prime, private_key)`: Decrypts a message.
- `message_to_number(message)`: Converts a message to a number.
- `number_to_message(number)`: Converts a number back to a message.

## References
- [ElGamal Encryption - Wikipedia](https://en.wikipedia.org/wiki/ElGamal_encryption)
- [An Introduction to Mathematical Cryptography](https://www.math.brown.edu/johsilve/MathCryptoHome.html)