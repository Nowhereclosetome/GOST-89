ALPHABET = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЬЫЪЭЮЯ"
BINARYALPHABET = ["11000000","11000001","11000010","11000011","11000100","11000101",
"11000110","11000111","11001000","11001001","11001010","11001011","11001100",
"11001101","11001110","11001111","11010000","11010001","11010010","11010011",
"11010100","11010101","11010110","11010111","11011000","11011001","11011010",
"11011011","11011100","11011101","11011110","11011111"]
BINARYCIPHERS = ["00000000","00000001","00000010","00000011","00000100","00000101","00000110","00000111","00001000","00001001"]
HEX  = ["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"]
BINARY = ["0000","0001","0010","0011","0100","0101","0110","0111","1000","1001","1010","1011","1100","1101","1110","1111"]
TRANSLATIONTABLE = [["4","A","9","2","D","8","0","E","6","B","1","C","7","F","5","3"],
                    ["E","B","4","C","6","D","F","A","2","3","8","1","0","7","5","9"],
                    ["5","8","1","D","A","3","4","2","E","F","C","7","6","0","9","B"],
                    ["7","D","A","1","0","8","9","F","E","4","6","C","B","2","5","3"],
                    ["6","C","7","1","5","F","D","8","4","A","9","E","0","3","B","2"],
                    ["4","B","A","0","7","2","1","D","3","6","8","5","9","C","F","E"],
                    ["D","B","4","1","3","F","5","9","0","A","E","7","6","8","2","C"],
                    ["1","F","D","0","5","7","A","4","9","2","3","E","6","B","8","C"]]

def getIndex(value, struct):
    for i in range(len(struct)):
        if struct[i] == value:
            return i

def generateKeys(masterkey):
    key = []
    masterkey = bin(int(masterkey))
    masterkey = masterkey[2:]
    key.append(masterkey)
    masterkey = masterkey[4:] + masterkey[:4]
    key.append(masterkey)
    return key

def GetInformationFromFile(filename):
    data = []
    key = []
    file = open(filename,"r")
    raw = file.readlines()
    raw[0] = raw[0][:len(raw[0])-1]
    rawdata =   raw[0] 
    rawkey  =   raw[1]
    key = generateKeys(rawkey)
    binarydata  = ''
    binarykey   = ''
    for i in rawdata:
        binarydata += BINARYALPHABET[getIndex(i,ALPHABET)]
    data.append(binarydata[:32])
    data.append(binarydata[32:])
    return data,key



def binaryPlus(firstNum, secondNum, mode = "NOTXOR"):
    result = ''
    fNum = firstNum[::-1]
    sNum = secondNum[::-1]
    if mode == "NOTXOR":
        remainder   = 0
        resBit      = 0 
        for i in range(len(fNum)):
            resBit = int(fNum[i]) + int(sNum[i]) + remainder
            if resBit == 2:
                resBit = 0
                remainder = 1
            elif resBit == 3:
                resBit = 1
                remainder = 1
            else: 
                remainder = 0
            result += str(resBit)
    if mode == "XOR":
        for i in range(len(fNum)):
            resBit = int(fNum[i]) ^ int(sNum[i])
            result += str(resBit)
    return result[::-1]
         
def binaryMinus(firstNum, secondNum):
    sNum = ''
    for i in secondNum:
        if i == "1":
            sNum += "0"
        elif i == "0":
            sNum += "1"
    sNum = binaryPlus(sNum, "00000001")
    result = binaryPlus(firstNum, sNum)
    return result

def Replacement(promResult, mode):
    result = []
    groupedByFour = []
    translatedResult = ''
    i = 0
    while i < len(promResult):
        groupedByFour.append(promResult[i:i+4])
        i = i + 4
    groupedByFour = groupedByFour[::-1]
    if mode == "encryption":
        for i in range(len(groupedByFour)):
            result.append(TRANSLATIONTABLE[i][getIndex(groupedByFour[i],BINARY)])
    elif mode == "decryption":
        for i in range(len(groupedByFour)):
            hlpVar = HEX[getIndex(groupedByFour[i],BINARY)]
            result.append(HEX[getIndex(hlpVar,TRANSLATIONTABLE[i])])
    result = result[::-1]
    for i in result:
        translatedResult += BINARY[getIndex(i,HEX)]
    return translatedResult
        
def pushto11(binaryString):
    return binaryString[11:]+binaryString[:11]

def pushBackto11(binaryString):
    return binaryString[len(binaryString)-11:]+binaryString[:len(binaryString)-11]

def toLetters(binaryString):
    result = ""
    groupedByEight = []
    i = 0
    while i < len(binaryString):
        groupedByEight.append(binaryString[i:i+8])
        i = i + 83
    for j in groupedByEight:
        result += ALPHABET[getIndex(j,BINARYALPHABET)]
    return result

def encrypt(data,key):
    encrypted = []
    yonger = data[0]
    older = data[1]
    curKeyPart = key[0]
    for i in range(2):
        Summary32 = binaryPlus(older,curKeyPart)
        EncReplaced = Replacement(Summary32,"encryption")
        Pushed = pushto11(EncReplaced)
        EncPart = binaryPlus(Pushed,yonger,"XOR")
        encrypted.append(EncPart)
        yonger  = older
        older   = EncPart
        curKeyPart = key[1]
    return encrypted

def toStr(arr):
    return "" + arr[0] + arr[1]


def decrypt(encrypted,key):
    decrypted = []
    curKeyPart = key[1]
    decPart1 = encrypted[0]
    decPart2 = encrypted[1]
    for i in range(2):
        Summary32 = binaryPlus(decPart1,curKeyPart)
        EncReplaced = Replacement(Summary32,"encryption")
        Pushed = pushto11(EncReplaced)
        DecPart = binaryPlus(Pushed,decPart2,"XOR")
        decrypted.append(DecPart)   
        decPart2  = decPart1
        decPart1  = DecPart
        curKeyPart = key[0]
    return decrypted[::-1]

data,key = GetInformationFromFile("Gost-89")
print("Encrypted: ",encrypt(data,key))
print("Decrypted: ",decrypt(encrypt(data,key), key))
print("Decoded to letters: ", toLetters(toStr(decrypt(encrypt(data,key), key))))
