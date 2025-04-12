from Crypto.PublicKey import RSA

# Generate 2048-bit RSA key pair
key = RSA.generate(2048)

# Export private key
private_key = key.export_key()
with open("rsa_private.pem", "wb") as priv_file:
    priv_file.write(private_key)

# Export public key
public_key = key.publickey().export_key()
with open("rsa_public.pem", "wb") as pub_file:
    pub_file.write(public_key)

### begrijp