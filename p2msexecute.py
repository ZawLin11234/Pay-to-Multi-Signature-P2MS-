from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii


g = 91856400161977908395308283025065140251705181937355066078088861381521716234138955951007057655670323322805052014818152087855953212832095435771882112069873990286274732617266982226622303666947321676432697901910158716128791580261483105380267011339380659963577826251913495514180846424015626888062582335634324684897

p =176690742807601926843382344200155497908166500143731270427041601244380836998324910890320595077991638152091984458004503195598513298666748560513503073593953998353391616897832753751826014187248513890689884298316293536706742975343751060574200411205632177010619620312918807181136374565632868604189700243867306948531

q = 776348386426262298728707800387603605742242178229

message = b"CSCI301 Contemporary topic in security 2024"



def main():
	op_lines = []
	pKeys = []
	signs = []
	originalKeys = []
	originalSigns = []
	validKeys = []
	scriptSigArray = []
	scriptPubArray = []
	with open("scriptPubKey.txt", "r") as file:
		for line in file:
			if line.startswith("OP_"):
				op_lines.append(line.strip())
			else:
				pKeys.append(line.strip())
			
		op_variables = [line.split("_")[1] for line in op_lines]
		#op_integers = [int(var) for var in op_variables]
	with open("scriptSig.txt", "r") as file:
		for line in file:
			if line.startswith("OP_"):
				op_lines.append(line.strip())
			else:
				signs.append(line.strip())
				
	with open("scriptPubKey.txt", "r") as file:
		for line in file:
			scriptPubArray.append(line.strip())
	with open("scriptSig.txt", "r") as file:
		for line in file:
			scriptSigArray.append(line.strip())
				
	#print(scriptPubArray)	
	#print(scriptSigArray)					
	M = op_variables[0]
	N = op_variables[1]
	#print(M , N)
	for i in pKeys:
		#print(i)
		original_key = int(i, 16)
		originalKeys.append(original_key)
		#print(original_key)
	for sign in signs:
		#print("Signs")
		byte_data = bytes.fromhex(sign)
		originalSigns.append(byte_data)
		#print(originalSigns)

	tally = 0
	for sign in originalSigns:
		
		for y in originalKeys:
			try:
				tup = [y, g, p, q]
				pub_key = DSA.construct(tup)
				hash_obj = SHA256.new(message)
				verifier = DSS.new(pub_key, 'fips-186-3')
				signature_binary = binascii.unhexlify(sign)		
				verifier.verify(hash_obj, signature_binary)
				print("The signature is verfied!")
				tally +=1
				
				
			except ValueError:
				pass
				#print("The message is not authentic.")
	#print(tally,M)
	
	if tally == int(M) :
		print("True")
		print("All Signatures have been checked and the script is valid!")
		
	else:
		print("False")
		print("The script is invalid!")

if __name__ == "__main__":
    main()
