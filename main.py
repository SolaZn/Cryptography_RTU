import inspect

import streamlit as st
from encryption import generate_large_prime, generate_generator, generate_keys, encrypt, decrypt, \
    message_to_number, number_to_message

st.set_page_config(
        page_title="El Gamal Encryption 101 - Anthony Zakani",
)

st.title('El Gamal Encryption 101')
st.caption("Anthony Zakani, 2024")
# Source: https://www.math.brown.edu/johsilve/MathCrypto/SampleSections.pdf

if "step" not in st.session_state:
    st.session_state.step = -1

if st.session_state.step == -1:
    st.subheader('👩‍🎤 Hey there, I am Alice, a very smart girl! I want to send a secret message to Bob. ', divider=True)
    st.subheader("👨‍🎤 Hey there, I am Bob, a very smart guy! I want to chat with Alice. Let's see how it works!", divider=True)

    # initialize the session state with a start button
    if st.button("Start!", icon="🚀", type="primary"):
        st.session_state.step = 0

if st.session_state.step == 0:
    st.header("🔮 First, let's generate a large prime number for everyone!", divider="grey")
    slider_value = st.slider("Select the number of bits for the prime number", 512, 2048, 1024)

    # Define the color and text based on the slider value
    if slider_value < 1024:
        color = "red"
        text = "Low security - vulnerable to modern attacks."
    elif slider_value < 1536:
        color = "orange"
        text = "Medium security - moderately resistant to attacks."
    else:
        color = "green"
        text = "High security - strong resistance to attacks."

    # Display the text with the corresponding color
    st.markdown(f"<p style='color:{color};'>{text}</p>", unsafe_allow_html=True)

    if st.button("Generate a large prime"):
        with st.spinner('Generating prime...'):
            st.session_state.prime = generate_large_prime(slider_value)

        st.code(
            inspect.getsource(generate_large_prime), language="python"
        )

        st.write("Our large prime :", st.session_state.prime)
        st.write("But don't worry, you will not see it again, it's a secret!")
        st.write("Let's call it _p_.")
        st.session_state.step += 1

if st.session_state.step == 1:
    st.header("🔮 Second, we need a generator based upon the prime number!", divider="blue")

    st.code(
        inspect.getsource(generate_generator), language="python"
    )

    if st.button("Generate a generator for the prime number"):
        st.session_state.generator = generate_generator(st.session_state.prime)
        st.write("Our generator element :", st.session_state.generator)
        st.write("As you can see, it can be a pretty small number compared to the prime!")
        st.write("Let's call it _g_.")
        st.session_state.step += 1

if st.session_state.step == 2:
    st.header("👩‍🎤 Thanks guys, now I will compute my very own public and private key out of this prime and generator!",
              divider="blue")

    st.code(
        inspect.getsource(generate_keys), language="python"
    )

    if st.button("Generate a public and private key pair"):
        st.session_state.public_key, st.session_state.private_key = generate_keys(st.session_state.prime, st.session_state.generator)
        st.write("Public key generated 🔓:", st.session_state.public_key)
        st.write("Private key generated 🔐:", st.session_state.private_key)

        st.session_state.step += 1

if st.session_state.step == 3:
    st.header("👨‍🎤 Now, I will encrypt my message using the public key of Alice!", divider=True)

    st.code(
        inspect.getsource(message_to_number), language="python"
    )
    st.code(
        inspect.getsource(encrypt), language="python"
    )

    message = st.text_input("Enter a message to encrypt", "El Gamal is fun! But don't tell anyone... 🤫")

    if st.button("Encrypt a message", ) and message:
        st.session_state.message = message_to_number(message)
        st.session_state.c1, st.session_state.c2 = encrypt(st.session_state.message, st.session_state.prime, st.session_state.generator, st.session_state.public_key)
        st.write("Let's call the pair of numbers _c1_ and _c2_.")
        st.write("c1:", st.session_state.c1)
        st.write("c2:", st.session_state.c2)
        st.write("The message is now encrypted! c1 and c2 are the ciphertext pair.")
        st.write("I will send it to Alice!")
        st.session_state.step += 1

if st.session_state.step == 4:
    st.header("👩‍🎤 Finally, I will decrypt the message using my private key!", divider=True)

    st.code(
        inspect.getsource(decrypt), language="python"
    )

    if st.button("Decrypt a message"):
        decrypted_message = decrypt(st.session_state.c1, st.session_state.c2, st.session_state.prime, st.session_state.private_key)
        st.session_state.decrypted_message = number_to_message(decrypted_message)
        st.write("Message decrypted:", st.session_state.decrypted_message)
        st.session_state.step += 1

if st.session_state.step == 5:
    st.header("🎉 We did it! We have successfully encrypted and decrypted a message using El Gamal encryption!", divider=True)
    # Now let's explain the process mathematically
    # Section 1: Introduction
    st.header("Overview of ElGamal Encryption")
    st.write("""
    ElGamal is a **public-key encryption scheme** that uses modular arithmetic for secure communication.  
    It involves three main steps:
    1. **Key Creation**: Alice generates her public and private keys.  
    2. **Encryption**: Bob encrypts a message using Alice's public key.  
    3. **Decryption**: Alice decrypts the ciphertext to recover the original message.  
    """)

    # Section 2: Public Parameter Creation
    st.subheader("📌 Public Parameter Creation")
    st.write("""
    A trusted party generates and publishes two values:  
    - A large prime number \\( p \\).  
    - A generator \\( g \\) of large (prime) order modulo \\( p \\).  

    These parameters are publicly available and shared between Alice and Bob.
    """)
    st.latex(r"p \text{ (prime)}, \quad g \text{ (generator modulo } p \text{)}")

    # Section 3: Key Creation (by Alice)
    st.subheader("🗝️ Key Creation (by Alice)")
    st.write("""
    1. Alice selects a private key \\( a \\), where:
    """)
    st.latex(r"1 \leq a \leq p - 1")
    st.write("""
    2. She computes the public key \\( A \\) using the formula:
    """)
    st.latex(r"A = g^a \, (\text{mod } p)")
    st.write("""
    3. Alice **publishes the public key** \\( A \\) and keeps her private key \\( a \\) secret.
    """)

    # Section 4: Encryption (by Bob)
    st.subheader("🔒 Encryption (by Bob)")
    st.write("""
    To send a secure message to Alice, Bob follows these steps:  
    1. Chooses a plaintext message \\( m \\) and a random **ephemeral key** \\( k \\), where:
    """)
    st.latex(r"1 \leq k \leq p - 1")
    st.write("""
    2. Using Alice's public key \\( A \\), Bob computes two values:  
    - The first part of the ciphertext \\( c_1 \\):  
    """)
    st.latex(r"c_1 = g^k \, (\text{mod } p)")
    st.write("- The second part of the ciphertext \\( c_2 \\):")
    st.latex(r"c_2 = m \cdot A^k \, (\text{mod } p)")
    st.write("""
    3. Bob sends the ciphertext pair \\( (c_1, c_2) \\) to Alice.
    """)

    # Section 5: Decryption (by Alice)
    st.subheader("🔓 Decryption (by Alice)")
    st.write("""
    After receiving the ciphertext \\( (c_1, c_2) \\), Alice decrypts it as follows:  
    1. She computes the value of \\( c_1^a \\) (mod \\( p \\)) using her private key \\( a \\):  
    """)
    st.latex(r"c_1^a \, (\text{mod } p)")
    st.write("""
    2. To recover the original message \\( m \\), Alice multiplies \\( c_2 \\) by the **inverse** of \\( c_1^a \\):
    """)
    st.latex(r"m = (c_1^a)^{-1} \cdot c_2 \, (\text{mod } p)")
    st.write("""
    This operation removes the encryption and recovers the plaintext message \\( m \\).
    """)

    # Section 6: Summary
    st.subheader("✅ Summary")
    st.write("""
    The ElGamal encryption process can be summarized as follows:
    - **Public Parameter Creation**: A trusted party generates and shares \\( p \\) and \\( g \\).  
    - **Key Creation**: Alice generates her private key \\( a \\) and public key \\( A \\).  
    - **Encryption**: Bob encrypts the message using Alice's public key \\( A \\).  
    - **Decryption**: Alice decrypts the ciphertext using her private key \\( a \\).  

    The security of ElGamal encryption comes from the difficulty of solving the **Discrete Logarithm Problem**, making it computationally infeasible to derive the private key or plaintext without proper keys.
    """)

    st.info("🔑 ElGamal ensures secure communication using public-key cryptography.")

    st.write("---")
    st.subheader("🔗 References")
    st.markdown("""
    - [ElGamal Encryption - Wikipedia](https://en.wikipedia.org/wiki/ElGamal_encryption)
    - [An Introduction to Mathematical Cryptography](https://www.math.brown.edu/johsilve/MathCryptoHome.html)
                """)