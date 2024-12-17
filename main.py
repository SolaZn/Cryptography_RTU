import inspect

import streamlit as st
from encryption import generate_large_prime, generate_generator, generate_keys, encrypt, decrypt, \
    message_to_number, number_to_message

st.set_page_config(
        page_title="El Gamal Encryption 101 - Anthony Zakani",
)

st.title('El Gamal Encryption 101')
st.caption("Anthony Zakani, 2024")
#("Source: https://www.math.brown.edu/johsilve/MathCrypto/SampleSections.pdf")

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
        st.session_state.prime = generate_large_prime(slider_value)

        st.code(
            inspect.getsource(generate_large_prime), language="python"
        )

        st.write("Large prime generated:", st.session_state.prime)
        st.write("But don't worry, I will not show it to you, it's a secret!")
        st.write("Let's call it _p_.")
        st.session_state.step += 1

if st.session_state.step == 1:
    st.header("🔮 Second, we need a generator based upon the prime number!", divider="blue")

    st.code(
        inspect.getsource(generate_generator), language="python"
    )

    if st.button("Generate a generator for the prime number"):
        st.session_state.generator = generate_generator(st.session_state.prime)
        st.write("Generator generated:", st.session_state.generator)
        st.session_state.step += 1

if st.session_state.step == 2:
    st.header("👩‍🎤 Thanks guys, now I will compute a public and private key out of this prime and generator!",
              divider="blue")
    if st.button("Generate a public and private key pair"):
        st.session_state.public_key, st.session_state.private_key = generate_keys(st.session_state.prime, st.session_state.generator)
        st.write("Keys generated:", st.session_state.public_key, st.session_state.private_key)
        st.session_state.step += 1

if st.session_state.step == 3:
    message = st.text_input("Enter a message to encrypt", "42")
    if st.button("Encrypt a message") and message:
        st.session_state.message = message_to_number(message)
        st.session_state.c1, st.session_state.c2 = encrypt(st.session_state.message, st.session_state.prime, st.session_state.generator, st.session_state.public_key)
        st.write("Message encrypted:", st.session_state.c1, st.session_state.c2)
        st.session_state.step += 1

if st.session_state.step == 4:
    if st.button("Decrypt a message"):
        decrypted_message = decrypt(st.session_state.c1, st.session_state.c2, st.session_state.prime, st.session_state.private_key)
        st.session_state.decrypted_message = number_to_message(decrypted_message)
        st.write("Message decrypted:", st.session_state.decrypted_message)
        st.session_state.step += 1