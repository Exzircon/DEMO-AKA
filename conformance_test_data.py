"""
conformance test data functions.

This module loads the conformance test data according to TS 35.208.
There are 20 test set (where 1 and 2 are the same!).

- a2b() - ascii(utf-8), in hex-notation, to bytes.
- b2a() - bytes to ascii/utf-8 hex-notation 

"""
fname = "TS35208_CONFORMANCE_TEST_DATA.TEXT"


#
#  Takes input on the "465b5ce8 b199b49f aa5f0a2e e238a6bc" form and converts in into a bytes object.
#  The input should conform to the format provided in TS 35.207 & TS 35.208 for test data.
#
def a2b(s: str) -> bytes:
    """Ascii to bytes. Require even length on string. """
    s = s.replace(" ","").strip()
    assert(len(s) % 2 == 0)
    bytelist = list()
    for i in range(0,len(s),2):
        bytelist.append(int("0x"+s[i]+s[i+1],16))
        
    return bytes(bytelist)


#
#  Takes a bytes object as input
#  The output conform to the format provided in TS 35.207 & TS 35.208 for test data.
#
hexdig = "0123456789abcdef"
def b2a(b: bytes) -> str:
    """Bytes to ascii a la TS 35.207/208 test data."""
    assert(len(b) > 0)
    #hexstr = Bits(b).hex
    hexstr = ""
    for byte in b:
        lo = hexdig[byte & 0x0F]
        hi = hexdig[byte >> 4]
        hexstr += hi+lo
    
    # our "default"
    if len(hexstr) == 32:
        hexstr = hexstr[0:8] + " " + hexstr[8:16] + " " + hexstr[16:24] + " " + hexstr[24:]
    else:
        hs = ""
        while len(hexstr)>=8:
            hs = hs + hexstr[0:8] + " "
            hexstr = hexstr[8:]
        hexstr = hs + hexstr
        
    return(hexstr)


#
#  Read the TS 35.208 conformance tests sets (20) from file (fname).
#  The values are converted from text (hex) to binary (bytes).
#  Then put each test set in a list. The list will have 20 elements.
#
#  Each test set is stored as a dictionary, with the following keys:
#    'name' - Testset name (str)
#    'K'    - bytes, length 16
#    'RAND' - bytes, length 16
#    'SQN'  - bytes, length 6
#    'AMF'  - bytes, length 2
#    'OP'   - bytes, length 16
#    'OPc'  - bytes, length 16
#    'f1'   - MAC-A, bytes, lenght 8
#    'f2'   - RES,   bytes, length 8
#    'f3'   - CK,    bytes, length 16
#    'f4'   - IK,    bytes, length 16
#    'f5'   - AK,    bytes, length 6
#    'f1*'  - MAC-S, bytes, length 8
#    'f5*'  - AK,    bytes, length 6 (resynch only)
#
def load_conf_test_data(fname: str) -> list:
    """Read the testdata, and load the data into the list of dicts."""
    
    def get_next_element(lines: list) -> tuple:
        elem, *lines = lines
        while elem.strip()=="": elem, *lines = lines    
        return elem, lines    
    
    f = open(fname,"r")
    lines = f.readlines()
    f.close()
    test_sets = list()
    
    while len(lines)>0:
        line, *lines = lines
        if line.strip()=="": continue
        if line[0] == "$": 
            test_set_name = line[1:].strip()
            testset = dict([("name",test_set_name)])

            elem, lines = get_next_element(lines)
            assert elem[0:2]=="K:", "Assumed K here, but got "+elem[0:2]
            testset["K"] = a2b(elem[2:].strip())
            
            elem, lines = get_next_element(lines)
            assert elem[0:5]=="RAND:", "Assumed RAND here, but got "+elem[0:5]
            testset["RAND"] = a2b(elem[5:].strip())         
            
            elem, lines = get_next_element(lines)
            assert elem[0:4]=="SQN:", "Assumed SQN here, but got "+elem[0:4]
            testset["SQN"] = a2b(elem[4:].strip())
            
            elem, lines = get_next_element(lines) 
            assert elem[0:4]=="AMF:", "Assumed AMF here, but got "+elem[0:4]
            testset["AMF"] = a2b(elem[4:].strip())            
            
            elem, lines = get_next_element(lines)  
            assert elem[0:3]=="OP:", "Assumed OP here, but got "+elem[0:3]
            testset["OP"] = a2b(elem[3:].strip())

            elem, lines = get_next_element(lines)  
            assert elem[0:4]=="OPc:", "Assumed OPc here, but got "+elem[0:4]
            testset["OPc"] = a2b(elem[4:].strip())
            
            elem, lines = get_next_element(lines)   
            assert elem[0:3]=="f1:", "Assumed f1 here, but got "+elem[0:3]
            testset["f1"] = a2b(elem[3:].strip())        

            elem, lines = get_next_element(lines)   
            assert elem[0:4]=="f1*:", "Assumed f1* here, but got "+elem[0:4]
            testset["f1*"] = a2b(elem[4:].strip())
            
            elem, lines = get_next_element(lines)   
            assert elem[0:3]=="f2:", "Assumed f2 here, but got "+elem[0:3]
            testset["f2"] = a2b(elem[3:].strip())
            
            elem, lines = get_next_element(lines)   
            assert elem[0:3]=="f5:", "Assumed f5 here, but got "+elem[0:3]
            testset["f5"] = a2b(elem[3:].strip())   
            
            elem, lines = get_next_element(lines)   
            assert elem[0:3]=="f3:", "Assumed f3 here, but got "+elem[0:3]
            testset["f3"] = a2b(elem[3:].strip())
            
            elem, lines = get_next_element(lines)   
            assert elem[0:3]=="f4:", "Assumed f4 here, but got "+elem[0:3]
            testset["f4"] = a2b(elem[3:].strip())           

            elem, lines = get_next_element(lines)   
            assert elem[0:4]=="f5*:", "Assumed f5* here, but got "+elem[0:4]
            testset["f5*"] = a2b(elem[4:].strip())  
            
            test_sets.append(testset)
    return test_sets


#
#  This class loads the TS 35.208 conformance data sets.
#  The init takes "USIM" or "HOME" as an argument.
# 
#  Only data elements that are available to to the respective parties
#  will then subsequently be available through the get_data() method.
#
#  get_data() retrieves credentials data for a given test set: [1..20]
#  
#  Note: 
#
#    One normally only uses OPc after the USIM has been populated.
#    That is, the USIM will not normally know OP at all.
#    HOME will know OP, but will still use OPc operationally. 
#    Thus, we only use OPc here.
#
class TestData():
    """Initialize as either 'HOME' or 'USIM'. Load TS 35.208 conformance test data sets."""
    case = None
    credentials = None
    fname = "TS35208_CONFORMANCE_TEST_DATA.TEXT"
    
    def __init__(self, case: str):
        if case.upper() in ["USIM","HOME"]: self.case = case
        if case == None: raise ValueError("TestData() expected 'HOME' or 'USIM' argument.")
        
        self.credentials = load_conf_test_data(self.fname)
        self.credentials.insert(0,None) # a dummy element as first item
        
        
    def get_data(self,ix: int) -> tuple:
        """get_data(ix: [1..20]) -> relevant USIM or HOME credentials (tuple)."""
        if ix>=1 and ix<=20:
            if self.case=="USIM":
                return ((self.credentials[ix]["K"],self.credentials[ix]["OPc"]))
            elif self.case == "HOME":
                cred_tuple = self.credentials[ix]["K"],self.credentials[ix]["OPc"], \
                    self.credentials[ix]["RAND"],self.credentials[ix]["SQN"],self.credentials[ix]["AMF"]
                return cred_tuple
            else:
                raise Exception("get_data() - invalid 'case', internal error.")
        else:
            raise IndexError("get_data(ix) - ix must be in range [1..20].")
