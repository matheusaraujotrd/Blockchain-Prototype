from cryptography.hazmat.primitives import hashes

class someClass:
    string = None
    def __init__(self, myString):
        self.string = myString
    def __repr__(self):
        return self.string

class cBlock:
    data = None
    previousHash = None
    previousBlock = None
    def __init__(self, blockData, previousBlock):
        self.data = blockData
        self.previousBlock = previousBlock
        if previousBlock != None:
            self.previousHash = previousBlock.computeHash()
    def computeHash(self):
        actualHash = hashes.Hash(hashes.SHA256())
        actualHash.update(bytes(str(self.data), "utf-8"))
        actualHash.update(bytes(str(self.previousHash), "utf-8"))
        return actualHash.finalize()

#TEST CASES
if __name__ == "__main__":
    root = cBlock("I am root", None)
    B1 = cBlock("I am a child", root)
    B2 = cBlock("I am B1's brother", root)
    B3 = cBlock(666, B1)
    B4 = cBlock(someClass("Hi!"), B2)
    B5 = cBlock(someClass("That's my life!"), B2)
    B6 = cBlock(1984, B3)

    for b in [B1, B2, B3, B4, B5, B6]:
        if b.previousBlock.computeHash() == b.previousHash:
            print("Success! Good hash.")
        else:
            print("ERROR! Bad hash.")

    #attempt of tampering with data of a bloc already created
    B3.data = 6958

    if B6.previousBlock.computeHash() == B6.previousHash:
        print("Tampering not detected! Critical!")
    else:
        print("Tampering detected. Attacker neutralized.")
           