from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Random import get_random_bytes
import binascii



key_pem = "-----BEGIN PUBLIC KEY----- \n\
MIIBtzCCASwGByqGSM44BAEwggEfAoGBAPudsDLox0c2dmlu78aaWsNlmXmB9bHB\n\
mJv0a/YZcb6Qs6GdTR3lXjInMxW2yYUHA5EYtpIeR1AUjCAM6GvXRUJofc/XT2+x\n\
41eWFVvTgDSCxqf3DfM6URcNfl9d0vqkTl6ofoDYM2IslK2x2swIH1v76PY2BB4Z\n\
M02eTUARTfezAhUAh/yqaEkBKfQUuRV5KCp6KR3nJLUCgYEAgs7Po8juYTjifyXl\n\
AH78SMy0hhAFdIUgIkeg67IOO8c1gt/Jvi08gWLUKujWmyQUAv9FoaIwoEWG0OC2\n\
1GAUUfDZJCh6nJmtoEIXVmOqPZ+o3584LADA1kxa1GTW29DfgHnZaBW7zy/URVXH\n\
U2IelqNe3oG+EILKXJxs9p8xgGEDgYQAAoGAM0WgPjJ3w01J1niWkwgNXhlkgrut\n\
URWPEsfDhfh470URyVUp6f0mBraEIJDvwiDiolCEwCuVSZ+AT3FJhSt3B1KUf0MO\n\
hyWJycmBi3kv4o8ujadqD45mmIbD7fc1mNHM/4KpdyDEq3Zj/9qdFdsKfWvbzijN\n\
dSEE7oCiJX3rX34=\n\
-----END PUBLIC KEY-----\n\
"
fixed_message = b"CSCI301 Contemporary topic in security 2024"

def generate_locking_script(M, public_keys):
    locking_script = ["OP_{}".format(M)]
    for pubkey in public_keys:
        #locking_script.append(str(len(pubkey)//2))  # Convert integer to string
        locking_script.append(pubkey)
    locking_script.append("OP_{}".format(len(public_keys)))
    locking_script.append("OP_CHECKMULTISIG")
    return locking_script

def generate_unlocking_script(M, signatures):
    unlocking_script = ["OP_0"]  # Placeholder for the scriptSig
    for sig in signatures:
        #unlocking_script.append(str(len(sig)//2))  # Convert integer to string
        unlocking_script.append(sig)
    return unlocking_script

def requestInfo():
	cont = True
	while(cont):
		M = int(input("Enter the number of signatures (M): "))
		N = int(input("Enter the number of public keys (N): "))
		if(N<M):
			print("N is equal to or greater than M")
			cont = True;
		else:
			cont = False;
			return(M,N)
	
		
def createKeysAndSig(M,N):
	keyArray = []
	keyHexArray = []
	privateArray= []
	signs = []
	realSigns=[]
	locking_script = ""
	unlocking_script = ""
	for i in range(N):
		param_key = DSA.import_key(key_pem)
		param = [param_key.p, param_key.q, param_key.g]
		key = DSA.generate(1024, domain=param)
		keyArray.append(key.y)
		privateArray.append(key.x)
		tup = [key.y, key.g, key.p, key.q]
		#print(tup)
		hash_obj = SHA256.new(fixed_message)
		signer = DSS.new(key, 'fips-186-3')
		signature = signer.sign(hash_obj)
		#print(hash_obj.hexdigest())
		signature_hex = binascii.hexlify(signature)
		
		#print(signature_hex)
		sign_str = signature_hex.hex()
		#print("Signs")
		#byte_data = bytes.fromhex(sign_str)
		#print(byte_data)
		signs.append(signature_hex)
		#file.write(signature_hex +b"\n" )
	#print(signs)
	with open("scriptSig.txt", "w") as file:	
		for i in range(M):
			sign_str = signs[i].hex()
			realSigns.append(sign_str)
			#print(sign_str)
		
		unlocking_script =generate_unlocking_script(M, realSigns)
		for info in unlocking_script:
			#print(info)
			file.write(info +"\n" )
		#print("key1:")
		#print([key.y, key.p, key.q, key.g, key.x])
	with open("scriptPubKey.txt", "w") as file:
		for i in keyArray:
			keyHex =hex(i)
			#print(i)
			keyHexArray.append(keyHex)
			#original_integer = int(keyHex, 16)
			#print(i)
			#print(original_integer)
			#file.write(keyHex + "\n")
			#print(keyHex)
			#print(i)
		locking_script = generate_locking_script(M, keyHexArray)
		#print(locking_script)
		for info in locking_script:
			file.write(info+ "\n")
	#for i in privateArray:
	print("ScriptPubKey.txt and ScriptSig.txt created Successfully")

def main():
	M,N = requestInfo()
	#print(M + N)
	createKeysAndSig(M,N)
if __name__ == "__main__":
    main()
