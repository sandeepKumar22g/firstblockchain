from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def genrate_keys():
    private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )
    public = private.public_key()
    return private,public

def sign(message,private):
    message = bytes(str(message), 'utf-8') #connverting message from string to bytes
    signature = private.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
    return signature


def verify(message, sig,public):
    message = bytes(str(message), 'utf-8')
    try:
        public.verify(
        sig,
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
        print("Error executing publick key")
        return False

if __name__=='__main__':
    pr,pu=genrate_keys() #lets this is A
    pr1,pu1=genrate_keys() # lets this is B
    # print(pr)
    # print(pu)

    message = "HI am test"
    sig = sign(message,pr)
    # print(sig)

    correct = verify(message,sig,pu1) #while verifying the message or any other persons priate key it show false
    if correct:
        print("successfull")
    else:
        print("false")