"""
USIM side of DEMO-AKA: state-machine only (w/message syntax check).

That is, we have also included:
    - the basic AESGCM encryption/decryption.
    - load the TS 35.208 conformance test sets
    
"""
import socket
import secrets
from enum import Enum, auto
from demo_aka_util import *
from demo_aka_cipher import AEAD_encrypt, AEAD_decrypt
from conformance_test_data import TestData, b2a


hsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
usock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
usock.settimeout(SOCK_TIMEOUT)
usock.bind(USIM_ADDR)


def sendto_home(msg: bytes) -> int:
    return hsock.sendto(msg, HOME_ADDR)

def recvfrom_home() -> bytes:
    try:
        data, addr = usock.recvfrom(DGRAM_BUFF)  
    except TimeoutError:
        data = bytes()
        
    # Normally, we should have checked 'addr'
    return data


def verify_Challenge_syntax(data: bytes):
    if len(data) ==  0: return (False,"No message received.")
    if len(data) != 36: return (False,"Wrong message length: "+str(len(data))+" (expected lenght: 36)")
    if data[0:4] != MSG_CHALLENGE: return (False,"The message was not a CHALLENGE message.")
    return (True,"Syntax OK")
    
    
def verify_AssignTMSI_syntax(data: bytes):
    if len(data) ==  0: return (False,"No message received.")
    if len(data) != 40: return (False,"Wrong message length: "+str(len(data))+" (expected lenght: 40)")
    if data[0:4] != MSG_ASSIGN_TMSI: return (False,"The message was not an ASSIGN_TMSI message.")
    return (True,"Syntax OK")

    
# We define State to contain the USIM states.
class State(Enum):
    INIT = auto()
    SEND_ID = auto()
    WAIT_FOR_CHALLENGE = auto()
    SEND_RESPONSE = auto()
    WAIT_FOR_TMSI = auto()
    SEND_TMSI_ACK = auto()
    ERROR = auto()
    DONE = auto()


def run_USIM_state_machine(IMSI: bytes, K: bytes, OPc: bytes) -> bool:
    """The glorious USIM state machine."""
    was_success = False
    state = State.INIT
    
    while True:
        #>>> INIT >>>
        if  state == State.INIT:
            new_run()     
            at(state)
            test_set_no = IMSI[-1]
            print("USIM initialized (test set:",str(test_set_no)+"):")
            print("  IMSI:",b2a(IMSI))
            print("  K   :",b2a(K))
            print("  OPc :",b2a(OPc))
            state = State.SEND_ID
            
        #>>> SEND_ID >>>
        elif state == State.SEND_ID:
            at(state)
            msg = MSG_SEND_ID + IMSI
            print("Sending 'SendIdentity':")
            print("  IMSI:",b2a(IMSI))
            sendto_home(msg)
            state = State.WAIT_FOR_CHALLENGE
            
        #>>> WAIT_FOR_CHALLENGE >>>
        elif state == State.WAIT_FOR_CHALLENGE:
            at(state)
            data = recvfrom_home()
            check = verify_Challenge_syntax(data)
            if check[0]:
                RAND = data[4:20]
                AUTN = data[20:]
                MSQN = AUTN[0:6] # the masked SQN
                AMF  = AUTN[6:8]
                MACA = AUTN[8:]
                print_challenge_data("Received 'Challenge':",RAND,AUTN,MSQN,AMF,MACA)                
                
                # milenage = Milenage(K,OPc)
                # milenage.compute_w_masked_sqn(RAND,MSQN,AMF)
                
                # verify the challenge!
                #uMACA = milenage.f1()
                uMACA = bytes(8)
                if  MACA != uMACA:
                    print("Too bad -- the challenge was *invalid*!!")
                    state = State.ERROR
                else:
                    #RES = milenage.f2()                    
                    #CK = milenage.f3()
                    #IK = milenage.f4()
                    #AK = milenage.f5()
                    RES = bytes(8)
                    CK  = bytes(16)
                    IK  = bytes(16)
                    AK  = bytes(6)
                    print_computed_values(MACA,RES,CK,IK,AK)          
                      
                state = State.SEND_RESPONSE         
            else:
                print(check[1])
                state = State.ERROR
                
        #>>> SEND_RESPONSE >>>
        elif state == State.SEND_RESPONSE:   
            at(state)
            msg = MSG_RESPONSE + RES
            print("Sending 'Response':")
            print("  RES:",b2a(RES))
            sendto_home(msg)            
            state = State.WAIT_FOR_TMSI
            
        #>>> WAIT_FOR_TMSI >>>
        elif state == State.WAIT_FOR_TMSI:
            at(state)
            data = recvfrom_home()
            check = verify_AssignTMSI_syntax(data)
            if check[0]:
                nonce = data[4:20]
                ciphertext = data[20:]         
                TMSI = AEAD_decrypt(CK+IK,nonce,ciphertext,IMSI)   
                print_assign_tmsi_data("Received 'AssignTMSI':",CK+IK,nonce,ciphertext,IMSI,TMSI)
                state = State.SEND_TMSI_ACK        
            else:
                print(check[1])
                state = State.ERROR
                
        #>>> SEND_TMSI_ACK >>>
        elif state == State.SEND_TMSI_ACK:
            at(state)
            nonce = secrets.token_bytes(16)
            ciphertext = AEAD_encrypt(IK+CK,nonce,TMSI,IMSI)
            msg = MSG_ASSIGN_TMSI_ACK + nonce + ciphertext 
            print_assign_tmsi_data("Sending 'AssignTMSI-ack':",IK+CK,nonce,ciphertext,IMSI,TMSI) # also for '-ack'
        
            sendto_home(msg)          
            state = State.DONE
        
        #>>> DONE >>> 
        elif state == State.DONE:
            at(state)
            print("\nDEMO-AKA sequence successfully completed on USIM side!")  
            state = State.INIT
            was_success = True
            break
        
        #>>> ERROR >>> 
        elif state == State.ERROR:
            at(state)
            print("There was an DEMO-AKA error. Exiting.")
            was_success = False
            break
        else:
            #>>> FATAL ERROR >>> 
            print("There was a fatal error. Exiting.")
            was_success = False
        
    return was_success

    
if __name__ == "__main__":
    print("\nUSIM starting: This is *not* the complete version.")
    IMSI = bytearray(16) # dummy
    cred = TestData("USIM")
    
    for ix in range(1,21):
        IMSI[-1] = ix
        K,OPc = cred.get_data(IMSI[-1])
        ok = run_USIM_state_machine(IMSI,K,OPc)
        
        if not ok: break
    
    if ok:
        print("\nUSIM done.")
        sendto_home(TERMINATE_MESSAGE)
    else:
        print("\nUSIM exiting --- something went wrong!")