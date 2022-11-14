from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def generate_keys():
        privateKey = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048
            )
        publicKey = privateKey.public_key()
        return privateKey, publicKey

def sign(message, privateKey):
    message = bytes(str(message), "utf-8")
    signature = privateKey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify(message, signature, publicKey):
    message = bytes(str(message), "utf-8")
    try:
        publicKey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
    )
        return True
    except InvalidSignature:
        return False
    except:
            print("Error during key verification")

#TEST CASES
if __name__ == "__main__":

    #Valid cases
    pr,pu = generate_keys()
    print(pr, pu, sep="\n")
    message = "this must work!"
    signature = sign(message, pr)
    print(signature)
    correct = verify(message, signature, pu)

    if correct:
            print("Signature successfully verified!")
    else:
            print("Something wrong occurred. Verification wasn't successfull.")

    #Verifying hash with incorrect public key
    pr2, pu2 = generate_keys()
    sig2 = sign(message, pr2)
    correct = verify(message, sig2, pu)

    if correct:
        print("Wrong signature has been succesfully verified. Critical.")
    else:
        print("Wrong signature doesn't check out. Good.")

    #Attempt to tamper with signed message
    badMessage = message + "Hackerman!"

    correct = verify(badMessage, signature, pu)

    if correct:
        print("Message has been tampered with. Critical.")
    else:
        print("Tampered message detected. Great!")