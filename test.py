
def sign(message, key):
    return rsa.sign(message.encode('utf-8'), key, 'SHA-1')

def verify(message, signature, key):
    try:
        # This verify method returns the hash algorithm used in the signature. So, what we do is to check that this is equal to the hash algorithm, i.e; SHA-1.

        return rsa.verify(message.encode('utf-8'), signature, key) == 'SHA-1'
    except:
        # This means either the message or the signature were manipulated and are not authentic.
        return False
