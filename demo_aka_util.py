UDP_IP = "127.0.0.1"        # We *only* use internal datagram exchange (this is "localhost")
HOME_UDP_PORT = 5005        # The exact port's can be changed. But: only to ephemeral ones. 
USIM_UDP_PORT = 5006
SOCK_TIMEOUT  = 10          # Socket timeout in seconds. May be changed (if needed).
DGRAM_BUFF    = 1024        # The max.size of a single datagram. 

USIM_ADDR = (UDP_IP, USIM_UDP_PORT)
HOME_ADDR = (UDP_IP, HOME_UDP_PORT)


PID = 0xF00D.to_bytes(2)

class MID():
    SendIdentity   = 0x0100.to_bytes(2)
    Challenge      = 0x0101.to_bytes(2)
    Response       = 0x0102.to_bytes(2)
    AssignTMSI     = 0x0103.to_bytes(2)
    AssignTMSI_ACK = 0x0104.to_bytes(2)

MSG_SEND_ID = PID + MID.SendIdentity
MSG_CHALLENGE = PID + MID.Challenge
MSG_RESPONSE = PID + MID.Response
MSG_ASSIGN_TMSI = PID + MID.AssignTMSI
MSG_ASSIGN_TMSI_ACK = PID + MID.AssignTMSI_ACK


TERMINATE_MESSAGE = b'DEMO-AKA FINISHED'


#
#  Common printout functions for USIM and HOME
#
from enum import Enum
from conformance_test_data import b2a


def at(s: Enum): print("\n==> State: "+s.name,flush=True)  

def new_run(): print("\n"+"="*10+"<<<  New DEMO-AKA run  >>>"+"="*50)     


def print_challenge_data(msg,RAND,AUTN,MSQN,AMF,MACA):
    print(msg)
    print("  RAND:",b2a(RAND))
    print("  AUTN:",b2a(AUTN))
    print("    MSQN:",b2a(MSQN))
    print("    AMF :",b2a(AMF))
    print("    MACA:",b2a(MACA))  
    
    
def print_computed_values(MACA,RES,CK,IK,AK):
    print("")
    print("Computed values:")
    print("  MAC-A :",b2a(MACA))
    print("  RES   :",b2a(RES))                
    print("  CK    :",b2a(CK))
    print("  IK    :",b2a(IK)) 
    print("  AK    :",b2a(AK))
    
    
def print_assign_tmsi_data(msg,key,nonce,ciphertext,aad,plaintext):
    print(msg)                
    print("  Key       :",b2a(key))
    print("  nonce     :",b2a(nonce))
    print("  ciphertext:",b2a(ciphertext))
    print("  aad was   :",b2a(aad))                
    print("  decr.TMSI :",b2a(plaintext))