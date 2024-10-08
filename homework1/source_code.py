##------------##
##   Imports  ##
##------------##
from rubik.cube import Cube
import  string
import hashlib
from itertools import product
from collections import Counter
import string
from Crypto.Cipher import AES


##------------##
## Question 1 ##
##------------##

def split_into_digrams(txt):
    # split into digrams
    digrams = []
    while txt:
        digrams += [txt[:2]]
        txt = txt[2:]
    return digrams
    

def preprocess(message):

    # remove spaces
    message = message.replace(" ", "")
    # replace j with i
    message = message.replace("j", "i")
    # make lowercase
    message = message.lower()

    m = ""
    for c in message:
        if c in string.ascii_lowercase:
            m += c

    message = m

    # find positions of repeated characters
    indices = []
    for i in range(len(message)-1):
        if message[i] == message[i+1]:
            indices += [i]

    # add "x" between all repeated characters
    c = 0
    for i in indices:
        message = message[:i+c+1] + "x" + message[i+c+1:]
        c += 1

    # add "x" to message if it has odd length
    if len(message) % 2 == 1:
        message += "x"

    digrams = split_into_digrams(message)

    return digrams


def index(key, letter):
    for r in range(5):
        for c in range(5):
            if key[r][c] == letter:
                return r, c
    print("DID NOT FIND LETTER IN KEY")
    return 100, 100

# encrypts just one digram
def enc(key, d):

    r1, c1 = index(key, d[0])
    r2, c2 = index(key, d[1])

    ciphertext = ""

    # if in same row
    if r1 == r2:
        ciphertext += key[r1][(c1+1) % 5]
        ciphertext += key[r2][(c2+1) % 5]
    
    # if in same column
    elif c1 == c2:
        ciphertext += key[(r1+1) % 5][c1]
        ciphertext += key[(r2+1) % 5][c2]

    # if not in the same row or column
    else:
        ciphertext += key[r1][c2]
        ciphertext += key[r2][c1]

    return ciphertext

# takes in key, and list of digram strings
def encryption(key, D):
    ciphertext = []
    for d in D:
        ciphertext += [enc(key, d)]
    return "".join(ciphertext)

def dec(key, d):
    
    r1, c1 = index(key, d[0])
    r2, c2 = index(key, d[1])

    plaintext = ""

    # if in same row
    if r1 == r2:
        plaintext += key[r1][(c1-1) % 5]
        plaintext += key[r2][(c2-1) % 5]
    
    # if in same column
    elif c1 == c2:
        plaintext += key[(r1-1) % 5][c1]
        plaintext += key[(r2-1) % 5][c2]

    # if not in the same row or column
    else:
        plaintext += key[r1][c2]
        plaintext += key[r2][c1]

    return plaintext


def decryption(key, ciphertext):
    digrams = split_into_digrams(ciphertext)
    plaintext = []
    for d in digrams:
        plaintext += [dec(key, d)]
    return "".join(plaintext)


def print_problem1(Q1a_m, Q1a_k, Q1b_k, Q1b_c):

    print("PROBLEM 1 ANSWERS")
    print()

    # part A
    preprocessedA = preprocess(Q1a_m)
    ciphertextA = encryption(Q1a_k, preprocessedA)
    print("PART A CIPHERTEXT IS: ", ciphertextA)
    print()

    # part 2
    print("PART B DECRYPTED CIPHERTEXT IS: ", decryption(Q1b_k, Q1b_c))
    print()



##------------##
## Question 2 ##
##------------##

class CubeCipher:
    def __init__(self, seed):
        self.seed = seed
        # Create a Rubik's Cube with the specified seed
        self.cube = Cube(self.seed) 

    """
    Displays the current state of the cube. Example:
        MEM # M is the upper right corner of the top face. Accessed via cube.get_piece(1, 1, -1).colors[1]
        JJF 
        MTZ # Z is the bottom right corner of the top face.Accessed via cube.get_piece(1, 1, 1).colors[1]
    UJU XVE VKJ NYJ
    QTA FDX UHK DIG
    GGX PEX KRH TNO
        UIN
        OVG
        PTS

    """
    def display_state(self):
        print(self.cube())

    # Reset the state back to the initialized one.
    def reset(self):
        self.cube = Cube(self.seed)
    
    # Encrypts a plaintext pt with the cube cipher
    def encrypt(self, pt):
        ct = ""
        pos = 0 # used for keeping track of the current position of the plaintext
        
        # - Normally, you can execute the move 'R' with self.cube.R()
        # Since we will repedeatly execute R U R' and U', we prepare the
        # following list of functions
        # - Ri and Ui corresponds to R' and U'.
        moves = [self.cube.R, self.cube.U, self.cube.Ri, self.cube.Ui]
        while len(pt) - len(ct) >= 2:
            # We encrypt two characters with the the two characters we read from the cube
            # Hence, we keep track of this using char_count
            char_count = 0 
            while char_count != 2 and len(ct) != len(pt):
                # We skip the characters that are not in string.ascii_uppercase
                if pt[pos] not in string.ascii_uppercase:
                    ct += pt[pos] # write the skipped characters to ct to preserve strcuture.
                    pos +=1
                    continue
                # Execute R U R' U'
                for move in moves:
                    move()
                # Use upper right for the first character
                if char_count == 0:
                    ct += chr((ord(pt[pos]) + ord(self.cube.get_piece(1, 1, -1).colors[1]))% 26 + ord('A'))
                else: # Use bottom right for the second character.
                    ct += chr((ord(pt[pos]) + ord(self.cube.get_piece(1, 1, 1).colors[1]))% 26 + ord('A'))
                
                # Advance the positions
                pos +=1
                char_count += 1

        # Encrypt the left over character if any.
        if len(pt) != len(ct) and pt[pos] in string.ascii_uppercase:
            # Execute R U R' U'
            for move in moves:
                move()
            ct += chr((ord(pt[pos]) + ord(self.cube.get_piece(1, 1, -1).colors[1]))% 26 + ord('A')) 
            pos +=1

        # Add remaining skipped characters if any
        while len(ct) != len(pt):
            ct += pt[pos]
            pos +=1
        
        return ct

    def decrypt(self, ct):
        output = ""
        pos = 0 # used for keeping track of the current position of the ciphertext
        
        self.reset()

        # - Normally, you can execute the move 'R' with self.cube.R()
        # Since we will repedeatly execute R U R' and U', we prepare the
        # following list of functions
        # - Ri and Ui corresponds to R' and U'.
        moves = [self.cube.R, self.cube.U, self.cube.Ri, self.cube.Ui]
        while len(ct) - len(output) >= 2:
            # We encrypt two characters with the the two characters we read from the cube
            # Hence, we keep track of this using char_count
            char_count = 0 
            while char_count != 2 and len(output) != len(ct):
                # We skip the characters that are not in string.ascii_uppercase
                if ct[pos] not in string.ascii_uppercase:
                    output += ct[pos] # write the skipped characters to ct to preserve strcuture.
                    pos +=1
                    continue
                # Execute R U R' U'
                for move in moves:
                    move()
                # Use upper right for the first character
                if char_count == 0:
                    output += chr((ord(ct[pos]) - ord(self.cube.get_piece(1, 1, -1).colors[1]))% 26 + ord('A'))
                else: # Use bottom right for the second character.
                    output += chr((ord(ct[pos]) - ord(self.cube.get_piece(1, 1, 1).colors[1]))% 26 + ord('A'))
                
                # Advance the positions
                pos +=1
                char_count += 1

        # Encrypt the left over character if any.
        if len(ct) != len(output) and ct[pos] in string.ascii_uppercase:
            # Execute R U R' U'
            for move in moves:
                move()
            output += chr((ord(ct[pos]) - ord(self.cube.get_piece(1, 1, -1).colors[1]))% 26 + ord('A')) 
            pos +=1

        # Add remaining skipped characters if any
        while len(output) != len(ct):
            output += ct[pos]
            pos +=1
        
        return output
    

def decrypt_with_6_letter_key(ct, key):

    plaintext = ""
    pos = 0
    mod_counter = 0

    while pos < len(ct):
        
        if ct[pos] not in string.ascii_uppercase:
            plaintext += ct[pos] # write the skipped characters to ct to preserve strcuture.
            pos +=1
            continue

        new_char = chr((ord(ct[pos]) - ord(key[mod_counter % 6]))% 26 + ord('A'))
        plaintext += new_char
        pos += 1
        mod_counter += 1

    return plaintext


def freq_assumption_helper(assumed_freqs, col_counts_sorted):
    key = ""
    for col in range(6):
        freq = col_counts_sorted[col][0][0]
        c = chr((ord(freq) - ord(assumed_freqs[col]))% 26 + ord('A'))
        key += c
    return key


def binary_strings(bits):
    num = 2 ** bits
    lst = list(range(num))
    lst_binary = [bin(n)[2:].rjust(6, '0') for n in lst]
    return lst_binary

def char_combos_six(str):
    return [''.join(s) for s in list(product(str, repeat=6))]

def statistical(ct, Q2b_mhash):
    # divide ciphertext into strings with characters from each position mod 6 / each column
    ct_only_alphabet = ""
    for c in ct:
        if c in string.ascii_uppercase:
            ct_only_alphabet += c
    ct_cols = [ct_only_alphabet[i::6] for i in range(6)]

    # count occurences of each letter, store this info in dict
    # find the most common letter in each column
    col_counts = [Counter(col_str) for col_str in ct_cols]
    col_counts_sorted = [sorted(c.items(), key=lambda x: x[1], reverse=True) for c in col_counts]

    key, Q2b_m_guess = "", ""

    def test_assumption(assumed_freqs):
        key = freq_assumption_helper(assumed_freqs, col_counts_sorted)
        Q2b_m_guess = decrypt_with_6_letter_key(ct, key)
        return key, Q2b_m_guess
    
    # all combinations of a set of letters:
    key_combos = char_combos_six("ETAOINSH") 
    for assumed_freqs in key_combos:
        # print(assumed_freqs)
        key, Q2b_m_guess = test_assumption(assumed_freqs)
        if hashlib.sha256(Q2b_m_guess.encode()).hexdigest() == Q2b_mhash:
            return key, Q2b_m_guess

    return key, Q2b_m_guess



def print_cubecipher(Q2a_seed, Q2a_c, Q2a_mhash, Q2b_c, Q2b_mhash):

    print("PROBLEM 2 CUBECIPHER ANSWERS")
    print()

    # PART A
    C = CubeCipher(Q2a_seed)
    Q2a_m = C.decrypt(Q2a_c)
    print("PART A DECRYPTED CIPHERTEXT IS: ", Q2a_m)
    print("PART A HASH ASSERTION IS: ", hashlib.sha256(Q2a_m.encode()).hexdigest() == Q2a_mhash)
    print()

    # PART B

    key, plaintext = statistical(Q2b_c, Q2b_mhash)

    print("PART B KEY WAS: ", key)
    print("DECRYPTION WITH KEY IS: ", plaintext)
    print("PART B HASH ASSERTION IS: ", hashlib.sha256(plaintext.encode()).hexdigest() == Q2b_mhash)
    print()



##------------##
## Question 3 ##
##------------##

# return list of all bits to represent num
# if pad is set to a number, it makes sure the list of bits is "pad" long
# example:
#   get_all_bits(3, pad=5) ---> [0, 0, 0, 1, 1]
def get_all_bits(num, pad=0):
    s = bin(num)[2:]
    bits = [int(c) for c in s]
    if pad != 0:
        L = len(bits)
        padded_bits = ([0] * (pad - L)) + bits
        assert (len(padded_bits) == pad)
        return padded_bits
    return bits

# get bit at position b from the pad-length long binary representation of num 
# example:
#   get_bit(3, 2, pad=5) ---> 0
#   get_bit(3, 3, pad=5) ---> 1
# 
def get_bit(num, b, pad=0):
    bits = get_all_bits(num, pad=pad)
    assert b < len(bits)
    return bits[b]

# get bit at position b and b+1 from the pad-length long binary representation of num 
# return them as a length-2 list
# example:
#   get_2bits(3, 2, pad=5) ---> [0, 1]
#   get_2bits(3, 3, pad=5) ---> [1, 1]
# if the bit requested is longer than bit representation, the code should fail
def get_2bits(num, b, pad=0):
    return [get_bit(num, b, pad=pad), get_bit(num, b+1, pad=pad)]

def to_num(b0, b1):
    return 2*b0 + b1

# turn list of bits into the integer that it represents
# assumes that lst[0] is the most significant bit
def to_num_long(lst):
    # if len(lst) == 0:
    #     return 0
    # elif len(lst) == 1:
    #     return lst[0]
    # else:
    #     return lst[0] + 2*to_num_long(lst[1:])
    
    output = 0
    for bit in lst:
        assert (bit == 0) or (bit == 1)
        output = output * 2 + bit
    return output


def find_mjs(Q3_known_cts, Q3_known_pt, Q3_cts, Q3_n, Q3_p):

    known_AES_bits_reverse = get_all_bits(Q3_known_pt, pad=8)
    known_AES_bits_reverse.reverse()

    secret = [0, 0]

    # 63, 62, 61, ...... 4, 3, 2, 1, 0
    for j in reversed(range(len(Q3_cts))):
 
        # get special two bits of unknown ciphertext at position j
        unknown_cts_bits = to_num(*get_2bits(Q3_cts[j], Q3_n, pad=256)) # VERIFY CORRECT
        assert(unknown_cts_bits in range(4))

        found_cancellation = False

        # TRY EACH KNOWN PLAINTEXT WORD
        # k is the index of which two bits of of the plaintext AES we use
        for k in range(4):
            # get special two bits of known ciphertext at position k
            known_cts_bits = to_num(*get_2bits(Q3_known_cts[k], Q3_n, pad=256))
            assert(known_cts_bits in range(4))

            # XOR ciphertexts
            xor_result = unknown_cts_bits ^ known_cts_bits
            assert(xor_result in range(4))
            if xor_result == 0:
                #mj_raw = to_num(*get_2bits(Q3_known_pt, 2*k, pad=8)) + 2*(k+1) - 2*(j+1)
                known_AES_2bits = known_AES_bits_reverse[2*k : 2*k+2]
                known_AES_2bits.reverse()
                mj_raw = to_num(*known_AES_2bits) + 2*(k+1) - 2*(j+1)
                mj = mj_raw % 4
                secret += get_all_bits(mj, pad=2)
                found_cancellation = True
        
        assert found_cancellation

    return to_num_long(secret) % Q3_p



def decrypt(Q3_ct_aes, Q3_tag, Q3_nonce, rec_k_aes):
    # rec_k_aes is assumed to be an int
    rec_k_aes_bytes = rec_k_aes.to_bytes(16, "big")
    cipher = AES.new(rec_k_aes_bytes, AES.MODE_GCM, Q3_nonce)
    Q3_pt = cipher.decrypt_and_verify(Q3_ct_aes, Q3_tag)
    return Q3_pt


def print_problem3(Q3_known_cts, Q3_known_pt, Q3_cts, Q3_n, Q3_p):

    print("PROBLEM 3 ANSWERS")
    print()
    aes_key = find_mjs(Q3_known_cts, Q3_known_pt, Q3_cts, Q3_n, Q3_p)
    print(decrypt(Q3_ct_aes, Q3_tag, Q3_nonce, aes_key))


##----------------------------------##
##  Run code and print all answers  ##
##----------------------------------##

if __name__ == "__main__":

    #### PASTE ALL PARAMETERS HERE (and fix commas and quotes) ####

    ###### Exercise 1
    Q1a_m='To anyone who knew the country well, the mere style and title of Don Quixote of La Mancha gave the key to the authors meaning at once. La Mancha as the knights country and scene of his chivalries is of a piece with the pasteboard helmet, the farm-labourer on ass-back for a squire, knighthood conferred by a rascally ventero, convicts taken for victims of oppression, and the rest of the incongruities between Don Quixotes world and the world he lived in, between things as he saw them and things as they were.'
    Q1a_k=[['w', 'f', 'm', 'c', 'p'],
            ['v', 'd', 'a', 'n', 'q'],
            ['e', 'o', 'z', 'h', 'k'],
            ['u', 'y', 'r', 'x', 'l'],
            ['s', 'i', 'g', 'b', 't']]
    
    Q1b_k=[['i', 't', 'g', 'k', 'v'],
            ['x', 'b', 's', 'c', 'e'],
            ['p', 'q', 'l', 'a', 'w'],
            ['f', 'm', 'r', 'n', 'z'],
            ['h', 'o', 'y', 'd', 'u']]
    Q1b_c='fkzcbxhkgtdmbymiuxhxyliqlnbtnhdmwoxptbxunkwazsnkdlfpwxlncusxmhzsexzgndvbcyvxokixmgogoyyendkahqvxxgdnpsawebbdnykfkgyogxuqzcbgtfqkcwdkqkcziopwxlfgmkcuqkcqnsswdmqkuxuslnpnvbfygxucqkyxyqlnvsndozsxnzqkyzwaspglhwpfpgcuiocubzndhnymbyzbgtzbeobqglxpvbbxmkyftghryhfgkqfpwxlnbgyowkxsxbczxbdpyevbkndkmntoioqkbitfcuuqmktbuxlfxcczkoldioxcgmcwotzxhkgtdmxylcbdmkkfvwokhmqylzwqkhrgndynsvywlnrgiobvnlrcawgtdmcbxyuqbggpspotzssacwyrhgzadpgmbwvwbgbiuxqtbhidlcsxbxzmmyobuxewygyhgbbvkfcxewrdcwylmntoioxetoqabvthmdmiuxqungtgdpocxbczgmndlrqkcukfbtioxzyhyrcwhkrkawrkdwvsbyzxyzhqxbxbexqibiuxxtsqxvzmnakmtqhbdtdpcsxbczbypvucrghkhpzhcxkncydmwoxptbbvuxtftgqkthxdfgbgtflddpewsxbxmknlrcawvbhkmkdqbrndduxhphszczgqndvylkxcndhaszdplxmyxtrcdmsnyeubndokuxitanmyzpncxzvxaykfbtzclnrglcnqrdeogtzrywgtqakxtgdyminlrcawgtdmcldkcutgthrcuymahvbhvbwswkxciobzwaspnpmsxukfhc'
    
    ###### Exercise 2
    Q2a_seed='YWGYNMNPWADOWSMPWXTFMQSAQQHHDBINCQRYGVBCOXMDPQXAXJULES'
    Q2a_c='EMOW QEDQ, MCB KPQZTB PHQUG CUEE MCB IOGFWQ OO HQGW SIPQ, QSP STQ VYENQP RMQRMST YO STQ LCJT AZ. WCN LUEICJEDE LCNE BQGDACFXN OQIQF IGHL ETT EKT FA IFA PMDI YXOGF WCN RQBTYPIZS NMQ ADQ DJZ, FMFWCN WUXAGWM, FA IFA CMFTPLIXXPP, WNP FWC SODPH YHL OABGJG PUUDARQZI, YJD FTTL PHQ YDAG TGDIJA DDQL Y HOZS QPAAFT, PLZ SMUS RDAFE KCNY OGGGKUE.  UIQ WLX MQMQT ME RSNIAGH YO IF OPL XE, EMXB PHQ SGWLHAZ.  XR WLX OPKA DURUCNEZF! IFA MAOZ RQRFXT PAPQMICZ TTAJEDTRGAJU. I ETDSHD XUZC PO TQPP DED FGW WNP DTNAAF EDKATTUCE JOI. FTJH HQD IM XESUC. FA LAAZCZ AF FWC CRKBWMJ AE UU FA TTAJEDT UF WYZ SAYT IENP AU YQTTAGGPY AHTP WLUOT.  QPAZP JN WNP DTNAAF "FXQ PHQ HDGYE AR IFA SXGVEWRP," EPGZ TTQ VPUPTAC.  FKW FTT ANEMFJPAS ADSCN OZQ PZKUF, MCB IAWQ DLA RQBTYP LQEHMJS! FTDSCHF MAGYE; U YXEDT ME LCHL NQ PR OCTADJ WT AZRC. DOIQKCN, STQ VMP UB, MCB XESMC RK RQBTYP IF, NJR DED TTYZ WME HM BUXX DD PHQ XDZOTQD FSWDDUAJA, TTMI QDE TMGBHY WZTU SHMF HFA WME HYUIZS, PLZ TTQ LMNDE OPKA VQDN OQEQD XLZEQP:--   IGO TTQ KMECQ AU RDE XAQQPED; U WCWRP TXK ZEOXPPA,   "YAG WYRE NMZCZ MQ FDM XRAIC, G IUEF HSCAD YN FWID."   MH Y ZUOW LGPH UFH CUEXUSQ, OO TQ LGPH TUH LKSQ   FGGIS TUH ZALF MCB DIE NJRPOZE, PLZ TGDCQ KUF TXQ POQE. '
    Q2a_mhash='599aa36ad3fb3611ff0e274e4058bc77ccf0f3677558dd5873da64bef4c8dbc9'
    Q2b_c='  BY NO UHNEI, VWMAPS MEEETBC NXIWJUZ MH SJI OHG,    T GUWKXO JJ IBZSU YJCNCF JDX UCBYJ;   UNE, OES MALU YI IXCGUYMEJ TKNX B SBLA GHYF,    MDR, B OP YP TZLJD WGW LHQEG.   RZV QNX HWE, IWBW EIU UHNEI, QO B FPOJEHGPE RAYHCF,    QJW ALWU CKHHO CKLM FOSKFFZOBU YTE;   ZUP RHF UKNGXO B RWVD-DPCAKLLVBP BG LU JDX WZPH--    LKTJ, XXWM BD UXA KXLTEJ HY EIQP?   BG XZ OKNMS, TQEW MSF IWZX, LT XA LAZPA DBL RSUU EHNLI,    E DXAU QHE FJ MYIUL GFHU LNAQBA   UR EIU QLX ZG JDBL ZJDPFXYU--EJX LSJBHBGR UXA UHI--    BBHHP XF JK LXWM OKN T NPKLEX?   JPK WKX ZMT, OTBO UXA RHFUX, WGW JPKN CTHT QNX MZP MATD    QPH WGREIYJZ MZVWDXK EIQJ LNPU;   OAM RZV VEGBDIUZ MAP HEKLX, HJJD MAP CEJXL LOT PAX MFQG--    IKLZ XKP WTE OKN FLOQCX MZ EE EM?   BY NO UHNEI, IWBW SJI BTMSFH, E MHZL JK MAP MQS,    TGO BHCNXO FQYA VLTU SBMS NO SBYP;   BDZ MAP NKOVNWBH OMKPOWPA, PSJSD BM RBLA MH XZ ZWP,    ALT BWLMPE JDX KPTJ KY FJ MYBX.   RZV QNX HWE, IWBW EIU UHNEI, EJX PZVBZ ATCEBU LNAQEOX    MSBJ UHNC FOA PTD BI OMXLEO WL XGFH;   UXM JPK XTELOSAW TY FUH HG EIU AGW ZG OKNK YPIA--    PALU CWWX JPK OH THGKHER NMURXK?   T IQRX TYTMAKXO UXNXX BVUOMBZOI, WGW EIQP BL POEQZA,    DBYZ ABD GQPAXC; EEJM ZTWU UHNCTUHY TTSI!   ZH RZV JDBGV J'
    Q2b_mhash='db4ccc8587a6722ba0e55dcfb2f0003698136398269dcbb7785ac6140d0c7857'
    
    ###### Exercise 3
    Q3_p=65358582236399098140383852530576291366163143046961680710706395821174671515157
    Q3_g=18897172015605387895108229785692294238197575884158182212205468678506383277799
    Q3_n=8
    Q3_known_pt=78
    Q3_known_cts=[100628902399338964202200242941450411720717377931230557189110959279361311229001, 79923898701216899144853725027432650161301782570164486779243637889104029662368, 55228370606105758625095625775030639601831950673587675541654733964047812795678, 101749686178974500409803681273998979904868247884559953317310940827332622293981]
    Q3_ct_aes=b'}\x99B\xf2"\x93\xeb\x1c\x88\x07H\xdc\xfa\xcaF\x8b\xbd\x1b\xd60\xe2Js\xbe\xb8\xb3\x1f'
    Q3_nonce=b'`\xf2\x81\xdc\xf54\x03\xc0L\x96\x1e\xe3\x1a\x8e\x18\xa7'
    Q3_tag=b'\xf9\xc1\xc4\xb3\xf4\xa4\xa5\x94v\xae\x17fp;\xba\xb6'
    Q3_cts=[96197102776248135901403305067813685344069468256276047015502497634632857912810, 77667109048112706782195925279795318351880240870644084053874691247961825223105, 12064654708520710960329113824682425497406352673600704569596082058654978271218, 93440727251381127803648135663020436094433120127379861031712136174489086217389, 32727532644989767859830260394504234662984171617644357023311556289923682538029, 15392332867374215159001673690046802135587477332931416040938665140215477138093, 29907790089591110441401771823677786272181581009676721542200867058383829538517, 52356874688257175008967891133370938276571912148854925194144705185297183058481, 73714720713412445101447311528996932868473982422394976315254713776435329370159, 15055160476138103388637948342861460643264774334874917561144873215161106366112, 19827501013037451086596079497838987338777071339662937515878573672408631427481, 96163425751499124192672726649945864147643525670376150290509811822377979631091, 13059294653081968826150876185227741063398313547711584070131220642507442670172, 66344600472103300424832817985721525715721964668388176192276464860952097078505, 104623105384546245241084543428567906865734286133677305174079729880246386132243, 90740049162353765141336069545661189076267124782320876426751933700701796995699, 80945284819715270382685849505157823019110383521618469514837004767719075226179, 29779696136686304469687567199099790325749241292180334522057706853868606527604, 27536670256195309996488509375598267501578656448334352088160823394907028116480, 25177323154280731320242478819664182415209867298191264118037595837617003515572, 62188801466068834690029579188653687659457401409284502464685792602490839612930, 24010454619753894690034722118510973378141567536589062782109537961705154668040, 103011005752354228076742889223056094394682853648397061890667685831482373849291, 1185968516120312256857268931717109462416408298098070168292866412299923478687, 101608186065559436658614526765114905965812149385330396902526576373594163797833, 39643340389313732274336763253367505648838192382007505918180229245530426955268, 93167662249895420333984498140443624984775160500624771159013032470637564935485, 108220812459016356545536893066306334838725443468085086838579439525462439350749, 39870999586054738513591704966111631794267039707988294637565820760403763177892, 42838030574050232817029872004777229167232533144501097584137515134662003600481, 31318989410779206216673589280247334820596842367344318701943146535166380606434, 45361671403276491943023305359448174567062945716604254631808901090335540127136, 89674657257257891063538107152818484295420508042870324939751211869543484129745, 49801530231399779567342205111372203137641899716877185834534957635842789623195, 60322122513140911926176903156184315543947429416639687942786406168132058130517, 109817572878339768668063160993742262638913986205267404467328488178073436627281, 105857625380392275712190756387852081573250194169879285939036317643716337719258, 78434558134356183159316183447878972062251897111273139464123589615196561426339, 24705602650257596772907088676736343275311629323569585764126640373819478805109, 78598610112777540631043648044088133555837136160092531452470643128981160471432, 34810412085547216823188668371772975514447144263796919879535743879459333784599, 39485754109910699060104022589168044091953741572670281110674290882893832707880, 59714446287507601674355954065411053820716433860196788991679751779565756285974, 99961449526236873448125535271105561020331125903066936490257227022062538248120, 84143811976639777869465677640926952328126512126672770219830920370179826122840, 15165015960856288907565321296492342196948362126511670780972043449934275951281, 106071682104312228085808956351118582671190195776344308783042283416785673022747, 81198721787710812579371336963402807984571548464929303699319156450622699991162, 93584223190043132856505563365679513683649431894859485930077357411364720739650, 47707943529562416640277488573095953620694446053386644606497767829673319671245, 25235493954081720865977261964409446085647606549818412773661242209120621202694, 23980352938575899705879814951035745861711316799703673998790230025876681171867, 67816996361429374428600372046424237601502438176038443622226835428214355354766, 69911811562417475947257194218037267931991637495653559632152693474227090821944, 111375141354197162442143595818530277517171506604502733564654945294891897464265, 104603779239595768754994945958533165271514223802227262280678668513349196885313, 28904844338758007888673631390648433831909229645467884006447051993271307479128, 67106295897740038164136384360079374155223660912442632592978544111829115741798, 81307631160052534725295539283062388598650928006808019989018102697175545637442, 28103902767838524732345277162959872638157732115355044993066464635915067106452, 36849151454636572648650014600128624986271190913520007829250207824745853781148, 21335057328444140629550325284370567865745971253019370552070783069851480946421, 47880417238519502579903303597306685938604173385332850528805756498984780037190]


    print_problem1(Q1a_m, Q1a_k, Q1b_k, Q1b_c)

    print_cubecipher(Q2a_seed, Q2a_c, Q2a_mhash, Q2b_c, Q2b_mhash)

    print_problem3(Q3_known_cts, Q3_known_pt, Q3_cts, Q3_n, Q3_p)