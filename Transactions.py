import Signature

class tx:
	inAddress = None
	outAddress = None
	signatures = None
	reqSig = None
	amount = None
	def __init__(self):
		self.inAddress = []
		self.outAddress = []
		self.signatures = []
		self.reqSig = []
	def addInput(self, fromAddress, amount):
		self.inAddress.append((fromAddress, amount))
	def addOutput(self, toAddress, amount):
		self.outAddress.append((toAddress, amount))
	def addReqSig(self, address):
		self.reqSig.append(address)
	def sign(self, privateKey):
		message = self.__gather()
		newSignature = Signature.sign(message, privateKey)
		self.signatures.append(newSignature)
	def isValid(self):
		totalIn = 0
		totalOut = 0
		message = self.__gather()
		for address, amount in self.inAddress:
			found = False
			for s in self.signatures:
				if Signature.verify(message, s, address):
					found = True
			if not found:
				return False
			if amount < 0:
				return False
			totalIn += amount
		for address in self.reqSig:
			found = False
			for s in self.signatures:
				if Signature.verify(message, s, address):
					found = True
			if not found:
				return False
		for address, amount in self.outAddress:
			if amount < 0:
				return False
			totalOut += amount
		if totalOut > totalIn:
			return False
		return True
	def __gather(self):
		data=[]
		data.append(self.inAddress)
		data.append(self.outAddress)
		data.append(self.reqSig)
		return data


#TEST CASES
if __name__ == "__main__":
	prKey1, puKey1 = Signature.generate_keys()
	prKey2, puKey2 = Signature.generate_keys()
	prKey3, puKey3 = Signature.generate_keys()
	prKey4, puKey4 = Signature.generate_keys()
	prKey5, puKey5 = Signature.generate_keys()
	prKey6, puKey6 = Signature.generate_keys()

	#Valid transactions
	tx1 = tx()
	tx1.addInput(puKey1, 1)
	tx1.addOutput(puKey2, 1)
	tx1.sign(prKey1)

	tx2 = tx()
	tx2.addInput(puKey1, 2)
	tx2.addOutput(puKey3, 1)
	tx2.addOutput(puKey4, 1)
	tx2.sign(prKey1)
	
	tx3 = tx()
	tx3.addInput(puKey6, 2.5)
	tx3.addOutput(puKey4, 2.5)
	tx3.addReqSig(puKey2)
	tx3.sign(prKey6)
	tx3.sign(prKey2)

	tx4 = tx()
	tx4.addInput(puKey1, 1)
	tx4.addInput(puKey2, 2)
	tx4.addOutput(puKey5, 3)
	tx4.sign(prKey1)
	tx4.sign(prKey2)

	for t in [tx1, tx2, tx3, tx4]:
		if t.isValid():
			print("Transaction successfully made")
		else:
			print("Invalid transaction! Critical!")

	#Attacker trying to sign transaction with own key
	tx6 = tx()
	tx6.addInput(puKey1, 1)
	tx6.addOutput(puKey4, 1)
	tx6.sign(prKey4)

	#Escrow not signed
	tx7 = tx()
	tx7.addInput(puKey6, 2.5)
	tx7.addOutput(puKey4, 2.5)
	tx7.addReqSig(puKey2)
	tx7.sign(prKey6)

	#One of the inputs haven't signed
	tx8 = tx()
	tx8.addInput(puKey1, 4)
	tx8.addInput(puKey2, 1.8)
	tx8.addOutput(puKey5, 5.8)
	tx8.sign(prKey1)

	#Output bigger than input
	tx9 = tx()
	tx9.addInput(puKey1, 4)
	tx9.addInput(puKey2, 1.8)
	tx9.addOutput(puKey5, 18)
	tx9.sign(prKey1)
	tx9.sign(prKey2)

	#Negative values
	tx10 = tx()
	tx10.addInput(puKey1, -1)
	tx10.addInput(puKey2, -1)
	tx10.addOutput(puKey5, -2)
	tx10.sign(prKey1)
	tx10.sign(prKey2)

	#Trying to tamper with signature after transaction has been signed
	tx11 = tx()
	tx11.addInput(puKey1, 1)
	tx11.addOutput(puKey2, 1)
	tx11.sign(prKey1)
	tx11.inAddress[0] = (puKey2, 1)

	for t in [tx6, tx7, tx8, tx9, tx10, tx11]:
		if t.isValid():
			print("Invalid transaction made, critical!")
		else:
			print("Invalid transaction detected. Great!")

