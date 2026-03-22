#include <stdint.h>
#include "../genericTypedefs.h"

#include "cifs.h"
#include "pc_pic_cpu.h"
#include <string.h>
#ifdef USA_WIFI
#include "at_winc1500.h"
#endif
#ifdef USA_ETHERNET
//#include "stacktsk.h"   // messo in .h ...
#include "at_winc1500.h"
#endif


#if defined(USA_WIFI) || defined(USA_ETHERNET)
extern uint8_t internetBuffer[256];
extern BYTE rxBuffer[1536];
extern WORD rxBufferLen,rxBufferOfs;
//extern NETWORKFILE networkFile;
extern NETWORKDISK_STRUCT theNetworkDisk;
#endif

//https://amitschendel1.medium.com/smb-going-from-zero-to-hero-ff686e907e81
//https://www.wireshark.org/docs/wsar_html/packet-smb2_8h_source.html
//  per definizioni struct costanti ecc di SMB2

#if defined(USA_WIFI) || defined(USA_ETHERNET)

void CIFSInit(NETWORKDISK_STRUCT *cifs,uint8_t ver,uint8_t m,uint8_t sec) {

  cifs->version=ver;
  cifs->mode=m;
  cifs->security=sec;
	cifs->Flags.Bits.bConnectedD=FALSE;
	cifs->msgcnt=0;
	cifs->processid=rand();			// sarebbe long ma ok
	cifs->sessionid=0;
	cifs->treeid=0;
	cifs->dialect=0;
	cifs->fileoffset=0;
	memset(cifs->fileguid,0,16);
	memset(cifs->dirguid,0,16);
	}


int8_t CIFSConnect(NETWORKDISK_STRUCT *cifs,const char *s) {
  struct sockaddr_in strAddr;
  uint16_t tOut;
  int retVal=0;
  
  cifs->Flags.Val &= ~0x7f;
  StringToIPAddress(s,(IP_ADDR*)&cifs->HostIP.Val);
  //cifs->sSocket = TCPOpen((DWORD)&cifs->HostName, TCP_OPEN_RAM_HOST, FTP_COMMAND_PORT, TCP_PURPOSE_FTP_COMMAND);
#ifdef USA_ETHERNET
  cifs->sSocket = TCPOpen(strAddr.sin_addr.s_addr, TCP_OPEN_IP_ADDRESS, FTP_PORT, TCP_PURPOSE_FTP_COMMAND);

  //if(cifs->sSocket == INVALID_SOCKET)
  // cifs->sSocket = TCPOpen(0, TCP_OPEN_SERVER, cifs->FTPCDataPort, TCP_PURPOSE_FTP_DATA);
#endif
#ifdef USA_WIFI
  BYTE u8Flags=0;   // boh??
  if(!cifs->HostIP.Val) {
    uint16_t tOut;
    *(unsigned long*)internetBuffer=0;
    tOut=0;
    gethostbyname((uint8_t*)cifs->HostName);
    while(!*(unsigned long*)internetBuffer && tOut<DNS_TIMEOUT) {
      m2m_wifi_handle_events(NULL);
      tOut++;
      __delay_ms(1);
      }
    strAddr.sin_addr.s_addr=cifs->HostIP.Val=*(unsigned long*)internetBuffer;
    if(cifs->Flags.Bits.debug)
      printf(" (%u.%u.%u.%u)\n",cifs->HostIP.v[0],cifs->HostIP.v[1],cifs->HostIP.v[2],cifs->HostIP.v[3]);
    }
  else 
    strAddr.sin_addr.s_addr=cifs->HostIP.Val;
  if(!strAddr.sin_addr.s_addr) {
    retVal=-1;
    goto fine;
    }
  cifs->sSocket = socket(AF_INET,SOCK_STREAM,u8Flags);
  strAddr.sin_family = AF_INET;
  strAddr.sin_port = htons(cifs->mode ? 445 : 139);
  if(cifs->sSocket == INVALID_SOCKET) {
    retVal=-2;
    goto fine;
    }
  connect(cifs->sSocket, (struct sockaddr*)&strAddr, sizeof(struct sockaddr_in));
  M2M_INFO("CIFS connect");
#endif
  tOut=0;
  *(unsigned long*)internetBuffer=0;
  while(!*(unsigned long*)internetBuffer && tOut<CONNECT_TIMEOUT) {
    m2m_wifi_handle_events(NULL);
    tOut++;
    __delay_ms(1);
    }
  if(!*(unsigned long*)internetBuffer) {
    retVal=-3;
    goto fine;
    }

  
  *(unsigned long*)internetBuffer=0;
  cifs->Flags.Bits.bConnectedD = 1;
  return 1;
  
fine:
  close(cifs->sSocket);
  cifs->sSocket=INVALID_SOCKET;
  cifs->Flags.Bits.bConnectedD = 0;
  return retVal;
	}

BOOL CIFSDisconnect(NETWORKDISK_STRUCT *cifs) {

  close(cifs->sSocket);
  cifs->sSocket=INVALID_SOCKET;
  cifs->Flags.Val &= ~0x7f;
	return TRUE;
	}

int CIFSreadResponseNBSS(NETWORKDISK_STRUCT *cifs,uint8_t *buffer,uint16_t len) {
	int i,n,retVal=0;
	uint8_t *p=buffer;
  WORD tOut=0;

	n=0;
  rxBufferLen=0;
  memset(rxBuffer,0,sizeof(rxBuffer));    // forse non serve
  recv(cifs->sSocket,rxBuffer,sizeof(rxBuffer),0);

  do {
#ifdef USA_ETHERNET
    StackTask();
#endif
#ifdef USA_WIFI
    m2m_wifi_handle_events(NULL);
#endif
    __delay_ms(1);
#ifdef USA_ETHERNET
    TCPGetArray(theNetworkDisk.sSocket,p,     64);
#endif
    if(rxBufferLen) {
    
//    if(theNetworkDisk.Flags.Bits.debug)
//      PRINT_RESPONSE(rxBuffer);   //
      i=min(rxBufferLen,len   /*-n*/);    // verificare, se serve
      memcpy(p,rxBuffer,i);
      p+=i;
      n+=i;

  		if(n>=len) {
				retVal=buffer[0] == NBSS_POSITIVE_SESSION_RESPONSE;			//
				break;
				}
      rxBufferLen=0;    // così marco che sto aspettando nuovo pacchetto
#ifdef USA_WIFI
      recv(cifs->sSocket,rxBuffer,sizeof(rxBuffer),0);
#endif
			}
    tOut++;
    } while(tOut<CIFS_TIMEOUT);
    
	return retVal;
	}

int CIFSreadResponseSMB2(NETWORKDISK_STRUCT *cifs,uint8_t *buffer,uint16_t len) { // len NON è la dim pacch atteso ma la dim del buffer passato! v. le varie call
	int i,n,retVal=0;
  uint16_t lenR=0;
	uint8_t *p=buffer;
	SMB2_HEADER *sh;
  uint16_t tOut=0;

	n=0;
  rxBufferLen=0;
  memset(rxBuffer,0,sizeof(rxBuffer));
  recv(cifs->sSocket,rxBuffer+rxBufferOfs,sizeof(rxBuffer),0);
#warning GESTIRE rxBufferOfs provare, per FindFirst

  do {
#ifdef USA_ETHERNET
    StackTask();
#endif
#ifdef USA_WIFI
    m2m_wifi_handle_events(NULL);
#endif
    __delay_ms(1);
#ifdef USA_ETHERNET
    TCPGetArray(theNetworkDisk.sSocket,p,     64);
#endif
    if(rxBufferLen) {
    
//    if(theNetworkDisk.Flags.Bits.debug)
//      PRINT_RESPONSE(rxBuffer);   //
      i=min(rxBufferLen,len   /*-n*/);    // verificare, se serve
      memcpy(p,rxBuffer,i);
      p+=i;
      n+=i;

      if(!lenR) {
        if(n>=4)
          lenR=MAKELONG(MAKEWORD(buffer[3],buffer[2]),buffer[1]);   // htonl ma 16 bit qua cmq
        //buffer[0] è 0 se OK/Response o errore (0x83=Negative Session Response)
        }
      if(lenR && n>=lenR+4) {
        sh=(SMB2_HEADER*)(buffer+4);
        retVal=sh->Status == STATUS_OK;
        break;
        }
      rxBufferLen=0;    // così marco che sto aspettando nuovo pacchetto
#ifdef USA_WIFI
      recv(cifs->sSocket,rxBuffer,sizeof(rxBuffer),0);
#warning GESTIRE rxBufferOfs provare, per FindFirst
#endif
			}
    tOut++;
    } while(tOut<CIFS_TIMEOUT);

	return retVal;
	}

static int CIFSSend(NETWORKDISK_STRUCT *cifs,const uint8_t *buffer,uint16_t len) {
  uint16_t n=len;
  
  rxBufferLen=0;
  memset(rxBuffer,0,sizeof(rxBuffer));
#ifdef USA_ETHERNET
  TCPPutString(theNetworkDisk.sSocket,buffer);
#endif
#ifdef USA_WIFI
  return sendEx(cifs->sSocket,buffer,n);
#endif
  return len==0;
  }

uint8_t *CIFSprepareSMBcode(uint8_t *buf,uint8_t cmd,uint32_t len) {

	buf[0]=cmd;
	buf[1]=LOBYTE(HIWORD(len));
	buf[2]=HIBYTE(LOWORD(len));
	buf[3]=LOBYTE(LOWORD(len));
	return buf;
	}

SMB2_HEADER *CIFSprepareSMB2header(NETWORKDISK_STRUCT *cifs,SMB2_HEADER *sh,uint16_t cmd,uint8_t ccharge,uint16_t crequest) {

	sh->Protocol[0]=0xFE;
	sh->Protocol[1]='S';
	sh->Protocol[2]='M';
	sh->Protocol[3]='B';
	sh->Size=64;
	sh->CreditCharge=ccharge;
	sh->ChannelSequence=0;
	sh->Reserved=0;		// OCCHIO è insieme a Status!
	sh->Command=cmd;
	sh->CreditsRequested=crequest;
	sh->Flags=0;
	sh->ChainOffset=0;
	sh->MessageID=cifs->msgcnt++;
	sh->ProcessID=cifs->processid;
	sh->TreeID=cifs->treeid;
	sh->SessionID=cifs->sessionid;
	memset(sh->Signature,0,sizeof(sh->Signature));
	return sh;
	}


int8_t CIFSOpenSession(NETWORKDISK_STRUCT *cifs,const char *s,const char *user,const char *pasw) {
	uint8_t buf[512];
	int i,len;
	NBSS_HEADER nbsh;

	cifs->Flags.Bits.bConnectedD= CIFSConnect(cifs,s) > 0 ? 1 : 0;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			SMB1_HEADER sh;
			sh.Protocol[0]=0xFF;
			sh.Protocol[1]='S';
			sh.Protocol[2]='M';
			sh.Protocol[3]='B';
			sh.Command=SMB_COM_NEGOTIATE;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);		// verificare
			memcpy(buf+4,&sh,len);
			CIFSSend(cifs,buf,len+4);

			sh.Protocol[0]=0xFF;
			sh.Protocol[1]='S';
			sh.Protocol[2]='M';
			sh.Protocol[3]='B';
			sh.Command=SMB_COM_OPEN_ANDX;		// FINIRE!
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);		// verificare
			memcpy(buf+4,&sh,len);
      CIFSSend(cifs,buf,len+4);
			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_NEGOTIATE_PROTOCOL *snp;
			SMB2_NEGOTIATE_RESPONSE *snr;
			SMB2_OPEN_SESSION *sos;

			if(!cifs->mode) {
				nbsh.Type=NBSS_SESSION_REQUEST;
				nbsh.Flags=0;
				len=32+1+1+32+1+1;
				nbsh.Length=MAKEWORD(HIBYTE(len),LOBYTE(len));
				memcpy(buf,&nbsh,4);
				nbEncode("SKYNET",(char*)buf+4,TRUE);
				nbEncode("FROCIO",(char*)buf+4+32+1+1,FALSE);
				CIFSSend(cifs,buf,len+4);
				CIFSreadResponseNBSS(cifs,buf,4);
				}

			// dice che l'inizio negoziazione è SEMPRE SMB1! fare, v. server

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_NEGOTIATE,1,31);
			snp=(SMB2_NEGOTIATE_PROTOCOL*)((char*)buf+4+sizeof(SMB2_HEADER));
			snp->Size.size=0x24;
			snp->DialectCount=2;
			snp->Security=cifs->security;
			snp->Reserved=0;
			snp->Capabilities=0;
			memset(snp->ClientGUID,0,sizeof(snp->ClientGUID));
			snp->ClientGUID[0]=1;			// fare..
			snp->ClientGUID[1]=2;			// 
			snp->ClientGUID[2]=rand();			// 
			snp->ClientGUID[3]=rand();			// 
//			memcpy(snp->ClientGUID,"\xe1\x1e\xcf\xb3\x28\x0f\xf1\x11\xac\x61\x00\x40\xf4\x37\xf7\xfa",16);
			snp->NegotiateContextOffset=0;
			snp->NegotiateContextCount=0;
			snp->Reserved2=0;
			snp->DialectCount=2;
			snp->Dialect[0]=0x0202;			// SMB 2.0.2
			snp->Dialect[1]=0x0210;			// SMB 2.1
			len=4+sh->Size+(snp->Size.size & 0xfffe);
      CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
//			memcpy(buf+4,&sh,sh.Size);
//			memcpy(buf+4+sh.Size,&snp,(snp->Size.size & 0xfffe)+2+2);		// i dialect sono a parte dalla Size...
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 170
				goto fatto_errore;
			snr=(SMB2_NEGOTIATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
					// qua dentro c'è il security Blob!  e in NegotiateContextoffset c'è "LMSS"

			cifs->dialect=snr->Dialect;


			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_OPENSESSION,1,31);
			sos=(SMB2_OPEN_SESSION*)((char*)buf+4+sizeof(SMB2_HEADER));
			sos->Size.size=0x19;
			sos->Flags=0;
			sos->Security=cifs->security;
			sos->Capabilities=1;
			sos->Channel=0;
			sos->PrevSessionID=0;
			if(cifs->security) {
				sos->BlobOffset=0x58;
				sos->BlobLength=sizeof(NEG_TOKEN_INIT);

				NEG_TOKEN_INIT nti;

//				memcpy(sos.SecurityBlob,"\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c"
//					"\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
//					"\xa2\x2a\x04\x28" "\x4e\x54\x4c\x4d\x53\x53\x50\x00" "\x01" "\x00\x00\x00"		// qua c'è NTLMSSP e 1 è il MessageType=NTLMSSP_NEGOTIATE
//					"\x97\x82\x08\xe2" /*flags*/ "\x00\x00\x00\x00\x00\x00\x00\x00" 
//					"\x00\x00\x00\x00\x00\x00\x00\x00"		// calling workstation domain (8char) e name (8char)
//					"\x06\x01\xb1\x1d\x00\x00\x00\x0f",sos.BlobLength);		// 6.1.7601 NTLM rev15
				memcpy(nti.hdr,"\x60\x48\x06\x06",4);
				memcpy(nti.OID,"\x2b\x06\x01\x05\x05\x02",6);
				memcpy(nti.boh,"\xa0\x3e",2);
				memcpy(nti.boh2,"\x30\x3c\xa0\x0e\x30\x0c",6);
				memcpy(nti.boh3,"\x06\x0a",2);
				memcpy(nti.mechType,"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a",10);
				memcpy(nti.boh4,"\xa2\x2a\x04\x28",4);
				memcpy(nti.id,"NTLMSSP\x0",8);
				nti.messageType=NTLM_NEGOTIATE_MESSAGE;
				nti.negotiateFlags = 			/*e2088297*/
                NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_128 | 
                NTLMSSP_NEGOTIATE_VERSION | 
								NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN | 
                NTLMSSP_NEGOTIATE_NTLM | 
                NTLMSSP_NEGOTIATE_LM_KEY | NTLMSSP_NEGOTIATE_SIGN | 
								NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_OEM | NTLMSSP_NEGOTIATE_UNICODE;
				nti.lenCallingdomain=0;
				nti.maxlenCallingdomain=0;
				nti.ofsCallingdomain=0x00000000;
				nti.lenCallingname=0;
				nti.maxlenCallingname=0;
				nti.ofsCallingname=0x00000000;
				nti.versionMaj=WINDOWS_MAJOR_VERSION_6;
				nti.versionMin=WINDOWS_MINOR_VERSION_1;
				nti.versionBuild=7601;
				memset(&nti.versionUnused,0,sizeof(nti.versionUnused));
				nti.versionNTLMrev=NTLMSSP_REVISION_W2K3;
				memcpy(sos->SecurityBlob,&nti,sizeof(NEG_TOKEN_INIT));

	//https://curl.se/rfc/ntlm.html
				//https://jcifs.samba.org/ non va, froci del cazzo
				//https://github.com/nmap/ncrack/blob/master/ntlmssp.cc
//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
				//https://blog.smallsec.ca/ntlm-challenge-response/
				}   // security
			else {
				sos->BlobOffset=0;
				sos->BlobLength=0;
				sos->Size.size &= 0xfffe;
				}

			len=sh->Size+(sos->Size.size & 0xfffe)+sos->BlobLength;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			i=CIFSreadResponseSMB2(cifs,buf,512);    // 105 +sizeof(NEG_TOKEN_TARG)+   8
			rsh=(SMB2_HEADER*)((char*)buf+4);
			if(i)
				goto fatto;
			if(rsh->Status != STATUS_MORE_PROCESSING_REQUIRED)
				goto fatto_errore;
			if(!cifs->security)		// beh sì :)
				goto fatto_errore;
			cifs->sessionid=rsh->SessionID;
			{NEG_TOKEN_TARG *ntlm=(NEG_TOKEN_TARG*)((char*)buf+sizeof(SMB2_HEADER)+   4);

//			SMB2_OPENSESSION_RESPONSE;		// usare

			// a 37h c'è la challenge-key, 8 byte
			// a 1Fh c'è NTLMSSP e poi 4 byte tipo, 00000002=NTLM_CHALLENGE
//			i=*ntlm->challenge;
			}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_OPENSESSION,1,1);
			sos=(SMB2_OPEN_SESSION*)((char*)buf+4+sizeof(SMB2_HEADER));
			sos->Size.size=0x19;
			sos->Flags=0;
			sos->Security=cifs->security;
			sos->Capabilities=1;
			sos->Channel=0;
			sos->PrevSessionID=0;
			if(cifs->security) {
				sos->BlobOffset=0x58;
				sos->BlobLength=sizeof(NEG_TOKEN_TARG2);

				NEG_TOKEN_TARG2 ntt;

/*				memcpy(sos.SecurityBlob,"\xa1\x81\x99\x30\x81\x96\xa0\x03\x0a\x01\x01\xa2\x7b\x04"
					"\x79" "\x4e\x54\x4c\x4d\x53\x53\x50\x00" "\x03" "\x00\x00\x00\x01\x00\x01"		// qua c'è NTLMSSP e 3 è il MessageType=NTLMSSP_AUTH
					"\x00\x68\x00\x00\x00\x00\x00\x00\x00\x69\x00\x00\x00\x00\x00\x00"
					"\x00\x58\x00\x00\x00\x00\x00\x00\x00\x58\x00\x00\x00\x10\x00\x10"
					"\x00\x58\x00\x00\x00\x10\x00\x10\x00\x69\x00\x00\x00\x15\x8a\x88"
					"\xe2" "\x06\x01\xb1\x1d\x00\x00\x00\x0f" "\xaf\x66\xa8\x5e\xd3\xa9\xbe"		// 6.1.7601 NTLM rev15
					"\xc7\x61\x19\x99\x90\x87\xd5\x01\xc2" "\x47\x00\x52\x00\x45\x00\x47"		//qua c'è GREGGIOD unicode...
					"\x00\x47\x00\x49\x00\x4f\x00\x44\x00" "\x00\x7c\x90\x94\xe5\x14\xf7"
					"\x73\x21\x17\x47\x79\xc4\x51\xe2\xff\xe3\xa3\x12\x04\x10\x01\x00"
					"\x00\x00\xfd\x64\x61\xf3\xb4\x07\x7d\x0c\x00\x00\x00\x00",sos.BlobLength);*/

				memcpy(ntt.hdr,"\xa1\x81\x99",3);
				memcpy(ntt.hdr2,"\x30\x81\x96\xa0\x03\x0a\x01",7);
				ntt.negResult=1;
				memcpy(ntt.boh,"\xa2\x7b\x04\x79",4);

				memcpy(ntt.id,"NTLMSSP\x0",8);
				ntt.messageType=NTLM_AUTHENTICATE_MESSAGE;
				ntt.lenLMResponse=1;
				ntt.maxlenLMResponse=1;
				ntt.ofsLMResponse=0x00000068;		//120
				ntt.lenNTResponsename=0;
				ntt.maxlenNTResponsename=0;
				ntt.ofsNTResponsename=0x00000073;
				ntt.lenDomainname=0;
				ntt.maxlenDomainname=0;
				ntt.ofsDomainname=0x00000058;
				ntt.lenUsername=0;
				ntt.maxlenUsername=0;
				ntt.ofsUsername=0x00000068;
				ntt.lenHostname=6*2;     // len (PC_PIC)
				ntt.maxlenHostname=16;
				ntt.ofsHostname=0x00000058;		//88
				ntt.lenSessionkey=16;
				ntt.maxlenSessionkey=16;
				ntt.ofsSessionkey=0x00000069;		//105
				ntt.negotiateFlags =		/*e2888a15*/
                NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_128 | 
                NTLMSSP_NEGOTIATE_VERSION | 
								NTLMSSP_NEGOTIATE_TARGET_INFO |
								NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN | 
                NTLMSSP_ANONYMOUS | NTLMSSP_NEGOTIATE_NTLM | 
								NTLMSSP_NEGOTIATE_SIGN |
                NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_UNICODE;

				ntt.versionMaj=WINDOWS_MAJOR_VERSION_6;
				ntt.versionMin=WINDOWS_MINOR_VERSION_1;
				ntt.versionBuild=7601;
				memset(&ntt.versionUnused,0,sizeof(ntt.versionUnused));
				ntt.versionNTLMrev=NTLMSSP_REVISION_W2K3;
//				memcpy(ntt.MIC,"\xaf\x66\xa8\x5e\xd3\xa9\xbe\xc7\x61\x19\x99\x90\x87\xd5\x01\xc2",16);
				for(i=0; i<16; i++)
					ntt.MIC[i]=rand();
				// da qualche parte dice che è "Machine Identifier" generato casualmente
				uniEncode("PC_PIC",ntt.hostname);
//				uniEncode("GUEST",ntt.username);
				ntt.lmresponse=cifs->security<2 ? 1 : 0;			// se metto 0 vuole auth key, altrimenti mi dà ok...

ntt.key;
ntt.key[0]='0';ntt.key[15]='F';

				memcpy(ntt.boh2,"\xa3\x12\x04\x10",4);
				ntt.verifierVersionNumber=1;
				memcpy(ntt.verifierBody,"\xfd\x64\x61\xf3\xb4\x07\x7d\x0c\x00\x00\x00\x00",12);

				memcpy(sos->SecurityBlob,&ntt,sizeof(NEG_TOKEN_TARG2));


				}
			else {
				sos->BlobOffset=0;
				sos->BlobLength=0;
				sos->Size.size &= 0xfffe;
				}

			len=sh->Size+(sos->Size.size & 0xfffe)+sos->BlobLength;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))		// 105 o 85 se non NTLMSSP
				goto fatto_errore;
			{SMB2_OPENSESSION_RESPONSE *sor=(SMB2_OPENSESSION_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			sor->Flags;
			NEG_TOKEN_TARG3 *ntlm=(NEG_TOKEN_TARG3*)(buf+ sor->BlobOffset+  4);

			if(cifs->security>1) {
				i=ntlm->negResult;

				// finire
						goto fatto_errore;
				}
			else {
				if(ntlm->negResult == 0x00)
					goto fatto;
				}

			}


			}
		

fatto:
	return 1;
  }

fatto_errore:
  CIFSDisconnect(cifs);
  return 0;
	}

int8_t CIFSOpenShare(NETWORKDISK_STRUCT *cifs,const char *s) {
	uint8_t buf[512];
	int i,len;
	char *p;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {

			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_TREE_CONNECT *stc;
			SMB2_IOCTL *si;
			SMB2_CREATEFILE *scf;
			SMB2_WRITEFILE *swf;
			SMB2_READFILE *srf;
			SMB2_GETINFO *sgi;
			SMB2_CLOSEFILE *sclf;
			SMB2_FIND *sf;
			uint8_t fileguid[16];

			if(!s) {			// se NULL sfoglio shares disponibili...
				//la READ dà errore e credo che la prima DCE fallisca...

				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_TREECONNECT,1,1);
				stc=(SMB2_TREE_CONNECT*)((char*)buf+4+sizeof(SMB2_HEADER));
				stc->Size.size=0x9;
				stc->Flags=0;
				stc->BlobOffset=0x48;
				{char *s="\\\\SKYNET\\IPC$";			// sembra servire sempre
				stc->BlobLength=strlen(s)*2;		// Unicode;
				uniEncode(s,stc->Blob);
				}

				len=sh->Size+(stc->Size.size & 0xfffe)+stc->BlobLength;
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512))   // 105
					;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);
				cifs->treeid=rsh->TreeID;


				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
				scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
				scf->Size.size=0x39;
  			scf->SecurityFlags=0;
				scf->Oplock=SMB2_OPLOCK_LEVEL_NONE;
				scf->Impersonation=2;
				scf->Flags=0;
				scf->Reserved=0;
				scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READCONTROL | SMB2_ACCESS_WRITEATTRIBUTES | 
					SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_WRITEEA | SMB2_ACCESS_READEA | SMB2_ACCESS_APPEND | 
					SMB2_ACCESS_WRITE | SMB2_ACCESS_READ;	//0x0012019f
				scf->Attributes=0;
				scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
				scf->Disposition=SMB2_FILE_OPEN;
				scf->CreateOptions=SMB2_OPTION_NORECALL | SMB2_OPTION_NONDIRECTORY;	// 0x00400040
				scf->BlobFilenameOffset=0x78;
				scf->BlobOffset=0;
				scf->BlobLength=0;
				{char *s="srvsvc";
				scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
				uniEncode(s,scf->Blob);
				}

				len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512))   // 152
					;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);
				{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
				memcpy(fileguid,scr->FileGUID,16);		// FINIRE!
				}

				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_GETINFO,1,1);
				sgi=(SMB2_GETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
				sgi->Size.size=0x29;
				sgi->Class=SMB2_FILE_INFO;
				sgi->InfoLevel=SMB2_FILE_STANDARD_INFO;		// 
				sgi->MaxSize=24;
				sgi->InputOffset=0x68;
				sgi->Reserved=0;
				sgi->InputSize=0;
				sgi->AdditionalInfo=0;
				sgi->Flags=0;
//				memcpy(sgi->FileGUID,"\xf9\x00\x00\x00\x70\x00\x00\x00\xa9\x00\x30\x00\xff\xff\xff\xff",16);
				memcpy(sgi->FileGUID,fileguid,16);
				len=sh->Size+(sgi->Size.size & 0xfffe);
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512))   // 96
					;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);
				{SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
        }


				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_WRITE,1,1);		// ossia DCERPC
				swf=(SMB2_WRITEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
				swf->Size.size=0x31;
				swf->DataOffset=0x70;
				swf->Length=160;
				swf->Offset=0;
//				memcpy(swf->FileGUID,"\xf9\x00\x00\x00\x70\x00\x00\x00\xa9\x00\x30\x00\xff\xff\xff\xff",16);
				memcpy(swf->FileGUID,fileguid,16);
				swf->Channel=0;
				swf->RemainingBytes=0;
				swf->Flags=0;
				swf->BlobOffset=0;
				swf->BlobLength=0;

				memcpy(&swf->Blob[-4],"\x05\x00\x0b\x03\x10\x00\x00\x00\xa0\x00\x00\x00\x02\x00\x00\x00"
					"\xb8\x10\xb8\x10\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x01\x00"
					"\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88"
					"\x03\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00"
					"\x2b\x10\x48\x60\x02\x00\x00\x00\x01\x00\x01\x00\xc8\x4f\x32\x4b"
					"\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88\x03\x00\x00\x00"
					"\x33\x05\x71\x71\xba\xbe\x37\x49\x83\x19\xb5\xdb\xef\x9c\xcc\x36"
					"\x01\x00\x00\x00\x02\x00\x01\x00\xc8\x4f\x32\x4b\x70\x16\xd3\x01"
					"\x12\x78\x5a\x47\xbf\x6e\xe1\x88\x03\x00\x00\x00\x2c\x1c\xb7\x6c"
					"\x12\x98\x40\x45\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00",160);

				len=sh->Size+(swf->Size.size & 0xfffe)+  160;
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512))   // 80
					;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);


				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_READ,1,1);
				srf=(SMB2_READFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
				srf->Size.size=0x31;
				srf->Padding=0x50;
				srf->Flags=0;
				srf->Length=512;
				srf->Offset=0;
//				memcpy(srf->FileGUID,"\xf9\x00\x00\x00\x70\x00\x00\x00\xa9\x00\x30\x00\xff\xff\xff\xff",16);
				memcpy(srf->FileGUID,fileguid,16);
				srf->MinCount=0;
				srf->Channel=0;
				srf->RemainingBytes=0;
				srf->BlobOffset=0;
				srf->BlobLength=0;

				len=sh->Size+(srf->Size.size & 0xfffe)+srf->BlobLength;
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512))   // 196
					;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);


				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_WRITE,1,1);		// ossia NetShareEnumAll
				swf=(SMB2_WRITEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
				swf->Size.size=0x31;
				swf->DataOffset=0x70;
				swf->Length=88;
				swf->Offset=0;
//				memcpy(swf->FileGUID,"\xf9\x00\x00\x00\x70\x00\x00\x00\xa9\x00\x30\x00\xff\xff\xff\xff",16);
				memcpy(swf->FileGUID,fileguid,16);
				swf->Channel=0;
				swf->RemainingBytes=0;
				swf->Flags=0;
				swf->BlobOffset=0;
				swf->BlobLength=0;

				memcpy(&swf->Blob[-4],"\x05\x00\x00\x03\x10\x00\x00\x00\x58\x00\x00\x00\x02\x00\x00\x00"
					"\x40\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x02\x00\x09\x00\x00\x00"
					"\x00\x00\x00\x00\x09\x00\x00\x00\x5c\x00\x5c\x00\x53\x00\x4b\x00"
					"\x59\x00\x4e\x00\x45\x00\x54\x00\x00\x00\x00\x00\x01\x00\x00\x00"
					"\x01\x00\x00\x00\x04\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"
					"\xff\xff\xff\xff\x00\x00\x00\x00",88);
				len=sh->Size+(swf->Size.size & 0xfffe)+   88;
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512))   // 80
					;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);

				
				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_READ,1,1);
				srf=(SMB2_READFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
				srf->Size.size=0x31;
				srf->Padding=0x50;
				srf->Flags=0;
				srf->Length=512;
				srf->Offset=0;
//				memcpy(srf->FileGUID,"\xf9\x00\x00\x00\x70\x00\x00\x00\xa9\x00\x30\x00\xff\xff\xff\xff",16);
				memcpy(srf->FileGUID,fileguid,16);
				srf->MinCount=0;
				srf->Channel=0;
				srf->RemainingBytes=0;
				srf->BlobOffset=0;
				srf->BlobLength=0;

				len=sh->Size+(srf->Size.size & 0xfffe)+srf->BlobLength;
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512))   // 196
					;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);


				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
				sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
				sclf->Size.size=0x18;
				sclf->Flags=0;
//				memcpy(sclf->FileGUID,"\xf9\x00\x00\x00\x70\x00\x00\x00\xa9\x00\x30\x00\xff\xff\xff\xff",16);
				memcpy(sclf->FileGUID,fileguid,16);

				len=sh->Size+(sclf->Size.size & 0xfffe);
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512))   // 120
					;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);


				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_IOCTL,1,1);
				si=(SMB2_IOCTL*)((char*)buf+4+sizeof(SMB2_HEADER));
				si->Size.size=0x39;
				si->Reserved=0;
				si->Function=0x00060194;		// FSCTL_DFS_GET_REFERRALS
				memcpy(si->GUID,"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",16);
				si->MaxInSize=0;
				si->MaxOutSize=4096;
				si->Flags=1;
				si->Reserved2=0;
				si->BlobInOffset=0x78;
	//			{char *s="\\Skynet\\Cdc";			// minuscolo?
				si->BlobInLength=strlen(s)*2  +2;		// MaxReferralLevel è qua dentro, e con 00 al fondo
				uniEncode(s+1,si->Blob);
		//		}

				si->MaxInReferralLevel=4;
				si->BlobOutLength=0;
				si->BlobOutOffset=0;

				len=sh->Size+(si->Size.size & 0xfffe)+si->BlobInLength+si->BlobOutLength;
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512))   // 54
					;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);

				memset(cifs->fileguid,0,16);
				memset(cifs->dirguid,0,16);
				}   // if(s)

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_TREECONNECT,1,1);
			stc=(SMB2_TREE_CONNECT*)((char*)buf+4+sizeof(SMB2_HEADER));
			stc->Size.size=0x9;
			stc->Flags=0;
			stc->BlobOffset=0x48;
			stc->BlobLength=strlen(s)*2;		// Unicode;
			uniEncode(s,stc->Blob);

			len=sh->Size+(stc->Size.size & 0xfffe)+stc->BlobLength;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(CIFSreadResponseSMB2(cifs,buf,512)) {  // 105
  			rsh=(SMB2_HEADER*)((char*)buf+4);
    		cifs->treeid=rsh->TreeID;
        return 1;
        }

			}

		}

	return 0;
	}

int8_t CIFSFindFirst(NETWORKDISK_STRUCT *cifs,const char *s,uint8_t attr,void *dirbuf) {
	uint8_t buf[4096];
	int i,len;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {

			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_TREE_CONNECT *stc;
			SMB2_IOCTL *si;
			SMB2_CREATEFILE *scf;
			SMB2_WRITEFILE *swf;
			SMB2_READFILE *srf;
			SMB2_GETINFO *sgi;
			SMB2_CLOSEFILE *sclf;
			SMB2_FIND *sf;
			uint8_t guid[16];

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			scf->Size.size=0x39;
			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_LEASE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask= SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_READ;		// 0x00100081
			scf->Attributes=0;
			scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
			scf->Disposition=SMB2_FILE_OPEN;
			scf->CreateOptions=SMB2_OPTION_SYNCIONO;	// 0x00000020		// SyncIO non-alert
			scf->BlobFilenameOffset=0x00000078;
			scf->BlobFilenameLength=0;
			scf->BlobOffset=0x00000080;
			scf->BlobLength=120;

			memcpy(&scf->Blob,"\x28\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x10\x00\x00\x00"
				"\x44\x48\x6e\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x10\x00\x04\x00"
				"\x00\x00\x18\x00\x00\x00\x00\x00\x4d\x78\x41\x63\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x20\x00\x00\x00"
				"\x52\x71\x4c\x73\x00\x00\x00\x00\x10\xf7\x00\x12\xa0\xf8\xff\xff"
				"\x3c\xec\x01\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x00",120);


			len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength    +8;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 152
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// FINIRE!
			}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_FIND,1,1);
			sh->Flags;		// v. SMB2_FLAG_CHAINED   FIND in certi casi tipo la DIR da dos...
			sf=(SMB2_FIND*)((char*)buf+4+sizeof(SMB2_HEADER));
			sf->Size.size=0x21;
			sf->InfoLevel=FileBothDirectoryInformation  /*FileIdBothDirectoryInformation*/;		// 
			sf->FindFlags=0;
			sf->FileIndex=0;
			memcpy(sf->FileGUID,guid,16);
			sf->OutputBufferLength=4000; // 65536
			sf->BlobOffset=0x00000060;
			sf->BlobLength=2;		// Unicode;
			uniEncode("*",sf->Blob);    // mettere search nome?

			len=sh->Size+(sf->Size.size & 0xfffe)+sf->BlobLength;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
      
      // andrebbe interrotto qua e poi proseguito in FindNext... ma va gestito
      
			if(!CIFSreadResponseSMB2(cifs,buf,4000))
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_FIND_RESPONSE *sfr=(SMB2_FIND_RESPONSE*)((char*)buf+sizeof(SMB2_HEADER)+   4);
			SMB2_FIND_RESPONSE_INFO4 *sfri=(SMB2_FIND_RESPONSE_INFO4*)((char*)buf+sizeof(SMB2_HEADER)+   4+8);   // ossia SMB2_FIND_RESPONSE
      i=0;
			do {			// il "." c'è sempre, anche se la Dir è vuota
        SearchRec *sr=(SearchRec*)(((char*)dirbuf)+i*SEARCHREC_VARIABLE_SIZE);
        memset(sr->filename,0,FILE_NAME_SIZE_8P3+2);    // si potrebbe togliere...
        if(sfri->ShortNameLength) {
          uniDecode(sfri->ShortFileName,sfri->ShortNameLength,sr->filename);
          }
        else {
#ifdef SUPPORT_LFN
#endif            
          uniDecode(sfri->FileName,sfri->FilenameLength,sr->filename);
          }
        strupr(sr->filename);   // 
        sr->attributes=sfri->Attrib & 0xff;
        sr->timestamp=FiletimeToPackedTime(sfri->WriteTime /*ModifiedTime no| questo pare sempre aggiornato ad ora, gli altri 2 insomma...*/);
        sr->filesize=sfri->EOFSize;
        sr->entry=i;  
        i++;
        if(!sfri->NextOffset)
          break;
        sfri=(SMB2_FIND_RESPONSE_INFO4*)(((char*)sfri)+sfri->NextOffset);
        if((((uint8_t*)sfri)-buf)>=4000)		// patch per buffer piccolo!
          break;
        } while(i<((MEDIA_SECTOR_SIZE*2/*v. MEDIA_INFORMATION, sfora in DISK a seguire*/)/
            SEARCHREC_VARIABLE_SIZE)-1 /* circa 40, devo lasciare spazio per una vuota completa per marker*/);
			}

			if(0) {		// SOLO se ho chiesto CHAINED sopra
				CIFSreadResponseSMB2(cifs,buf,512);		// 152
				if(rsh->Status != STATUS_NO_MORE_FILES)
					goto errore;
				}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,guid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);

			return 1;
			}
		}

errore:
	return 0;
	}

int8_t CIFSFindNext(NETWORKDISK_STRUCT *cifs) {
	SMB2_FIND_RESPONSE_INFO4 *sfri;
	SMB2_HEADER *sh,*rsh;
  SMB2_CLOSEFILE *sclf;
	uint8_t buf[4096];
	int i,len;
			uint8_t guid[16];     // SALVARE da SOPRA!

// usare una   CIFSreadResponseSMB2 speciale per le DIR, e   rxBufferOfs
          
  if(!CIFSreadResponseSMB2(cifs,buf,4000))
    goto errore;
  sh=(SMB2_HEADER*)((char*)buf+4);
  CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
  sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
  sclf->Size.size=0x18;
  sclf->Flags=0;
  memcpy(sclf->FileGUID,guid,16);

  len=sh->Size+(sclf->Size.size & 0xfffe);
  CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
  CIFSSend(cifs,buf,len+4);
  if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
    goto errore;
  rsh=(SMB2_HEADER*)((char*)buf+4);

  return 1;

errore:
	return 0;
	}

int8_t CIFSCloseShare(NETWORKDISK_STRUCT *cifs) {
	uint8_t buf[512];
	int i,len;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_TREE_DISCONNECT *std;

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_TREEDISCONNECT,1,1);
			std=(SMB2_TREE_DISCONNECT*)((char*)buf+4+sizeof(SMB2_HEADER));
			std->Size.size=0x4;
			std->Flags=0;
			len=4+sh->Size+(std->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(CIFSreadResponseSMB2(cifs,buf,512))   // 68
				;
			rsh=(SMB2_HEADER*)((char*)buf+4);

//			SMB2_TREEDISCONNECT_RESPONSE;
			}
		cifs->treeid=0;
		}

	return 0;
	}

int8_t CIFSChDir(NETWORKDISK_STRUCT *cifs,const char *s) {
	uint8_t buf[512];
	int i,len;
	char *p;


//	usare dirguid, passare handle alla dir aperta quando si fanno le operazioni sui file
//	gestire \ root e path ...

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {

			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_TREE_CONNECT *stc;
			SMB2_CREATEFILE *scf;
			SMB2_CLOSEFILE *sclf;


			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			scf->Size.size=0x39;
			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_LEASE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_READ;	//0x00100081;
			scf->Attributes=0;
			scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
			scf->Disposition=SMB2_FILE_OPEN;
			scf->CreateOptions=SMB2_OPTION_DIRECTORY | SMB2_OPTION_SYNCIONO;		// 0x00000020		// SyncIO non-alert
			scf->BlobFilenameOffset=0x00000078;
			scf->BlobFilenameLength=0;
			scf->BlobOffset=0x00000080;
			scf->BlobLength=120;

			memcpy(&scf->Blob,"\x28\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x10\x00\x00\x00"
				"\x44\x48\x6e\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x10\x00\x04\x00"
				"\x00\x00\x18\x00\x00\x00\x00\x00\x4d\x78\x41\x63\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x20\x00\x00\x00"
				"\x52\x71\x4c\x73\x00\x00\x00\x00\x10\xf7\x00\x12\xa0\xf8\xff\xff"
				"\x3c\xec\x01\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00"
				"\x00\x00\x00\x00\x00\x00\x00\x00",120);


			len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength    +8;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))   // 152
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			memcpy(cifs->dirguid,scr->FileGUID,16);		// FINIRE!
			}



			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,cifs->dirguid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(CIFSreadResponseSMB2(cifs,buf,512))   // 120
				;		// se ok/completo
			rsh=(SMB2_HEADER*)((char*)buf+4);
      
      return 1;

			}
		}
  
errore:
	return 0;
	}

int8_t CIFSMkDir(NETWORKDISK_STRUCT *cifs,const char *s) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;
  SMB2_CLOSEFILE *sclf;
  uint8_t guid[16];

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			scf->Size.size=0x39;
 			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_NONE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_WRITEDAC | SMB2_ACCESS_READCONTROL | SMB2_ACCESS_DELETE |
				SMB2_ACCESS_WRITEATTRIBUTES | SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_WRITEEA | SMB2_ACCESS_READEA |
				SMB2_ACCESS_WRITE | SMB2_ACCESS_READ; // 0x0017019b
			scf->Attributes=0 /*SMB2_FILE_ATTRIB_DIR*/;
			scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
			scf->Disposition=SMB2_FILE_CREATE;
			scf->CreateOptions=SMB2_OPTION_SYNCIONO | SMB2_OPTION_DIRECTORY;		// 0x00000021	// Directory, SyncIO non-alert
			scf->BlobFilenameOffset=0x78;
			scf->BlobLength=0;
			scf->BlobOffset=0;
			scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
			uniEncode(s,&scf->Blob[-8]);

			len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(CIFSreadResponseSMB2(cifs,buf,512)) {   // 152
				
				rsh=(SMB2_HEADER*)((char*)buf+4);
				{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
				memcpy(guid,scr->FileGUID,16);		// FINIRE!
				}
        
        sh=(SMB2_HEADER*)((char*)buf+4);
        CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
        sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
        sclf->Size.size=0x18;
        sclf->Flags=0;
        memcpy(sclf->FileGUID,guid,16);

        len=sh->Size+(sclf->Size.size & 0xfffe);
        CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
        CIFSSend(cifs,buf,len+4);
        if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
          goto errore;
        rsh=(SMB2_HEADER*)((char*)buf+4);
        {SMB2_CLOSE_RESPONSE *scr=(SMB2_CLOSE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

        }
				return 1;
				}

			}
		}
  
errore:
	return 0;
	}

int8_t CIFSRmDir(NETWORKDISK_STRUCT *cifs,const char *s) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;
	SMB2_SETINFO *si;
	SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			scf->Size.size=0x39;
 			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_LEASE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_DELETE | SMB2_ACCESS_READATTRIBUTES;	//0x00110080;		//Delete, Sync, Read
			scf->Attributes=0;
			scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
			scf->Disposition=SMB2_FILE_OPEN;
			scf->CreateOptions=SMB2_OPTION_SYNCIONO;		// 0x00000020	// SyncIO non-alert
			scf->BlobFilenameOffset=0x78;
			scf->BlobLength=0;
			scf->BlobOffset=0;
			scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
			uniEncode(s,&scf->Blob[-8]);

			len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 152
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// 
			}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_SETINFO,1,1);
			si=(SMB2_SETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
			si->Size.size=0x21;
			si->Class=SMB2_FILE_INFO;
			si->InfoLevel=SMB2_FILE_DISPOSITION_INFO;
			si->InfoSize=1;
			si->InfoOffset=0x0060;
			si->Reserved=0;
			si->AdditionalInfo=0;
			memcpy(si->FileGUID,guid,16);
			si->Blob[0]=1;

			len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 196
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

			}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,guid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CLOSE_RESPONSE *scr=(SMB2_CLOSE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

			}

			return 1;
			}
		}

errore:
	return 0;
	}

int8_t CIFSOpenFile(NETWORKDISK_STRUCT *cifs,const char *s,uint8_t mode,uint8_t share) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;

	cifs->fileoffset=0;
  share >> 2;     // i 2 bit più bassi sono type binary o text
	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,320);
			scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			scf->Size.size=0x39;
 			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_LEASE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask= 0x00000000 | /*0x0012019f*/
				(mode == OPEN_READ ? 1 : (mode == OPEN_WRITE ? 2 : (mode == OPEN_WRITEPLUS ? 3 : 0)));		// 
//			scf->AccessMask= 0x00120089;
//			scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READCONTROL | SMB2_ACCESS_WRITEATTRIBUTES | 
//				SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_WRITEEA | SMB2_ACCESS_READEA | SMB2_ACCESS_APPEND | 
//				SMB2_ACCESS_WRITE | SMB2_ACCESS_READ;	//0x0012019f

			scf->Attributes=SMB2_FILE_ATTRIB_NORMAL | (mode != OPEN_READ ? SMB2_FILE_ATTRIB_ARCHIVE : 0);			// diciamo
			scf->ShareAccess= 0x0000 | /*0x0007*/
				(share == SHARE_READWRITE ? (SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE) :
				(share == SHARE_READ ? SMB2_FILE_SHARE_READ : (share == SHARE_WRITE ? 0 : 
				(SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE))));			//
			scf->Disposition= mode == OPEN_READ ? SMB2_FILE_OPEN : (mode == OPEN_WRITE ? SMB2_FILE_OVERWRITE_IF/*SMB2_FILE_CREATE*/ : 
				(mode == OPEN_WRITEPLUS ? SMB2_FILE_OPEN_IF : 0));		// VERIFICARE specie RW
					// 2 fallisce se il file c'è già... è CREATE
			scf->CreateOptions=SMB2_OPTION_NONDIRECTORY | SMB2_OPTION_SYNCIONO;	// 0x00000060;		// Not a directory... SyncIO non-alert; 4 sarebbe Sequential only...

			scf->BlobFilenameOffset=0x80;
			scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
			uniEncode(s,scf->Blob);

			scf->BlobLength=144;
			scf->BlobOffset=0x90;
			// non sembra servire cmq... verificare (questo era per Leggi un file
				memcpy(((char*)&scf->Blob)+scf->BlobFilenameLength,"\x10\x00\x00\x00"
					"\x28\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x10\x00\x00\x00"
					"\x44\x48\x6e\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
					"\x00\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x10\x00\x04\x00"
					"\x00\x00\x18\x00\x00\x00\x00\x00\x4d\x78\x41\x63\x00\x00\x00\x00"
					"\x18\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x00\x00\x00\x00"
					"\x51\x46\x69\x64\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x04\x00"
					"\x00\x00\x18\x00\x20\x00\x00\x00\x52\x71\x4c\x73\x00\x00\x00\x00"
					"\x10\xab\x7c\x21\xa0\xf8\xff\xff\xb4\x12\x15\x00\x00\x00\x00\x00"
					"\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",144+4);


			scf->BlobLength=0;
			scf->BlobOffset=0;

			len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength   +8;		// 4 se Blob esteso.. verificare
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 152
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			if(rsh->Status==STATUS_OK) {
				memcpy(cifs->fileguid,scr->FileGUID,16);		// FINIRE!

				scr->EOFSize;

				return 1;
				}
			}

			}
		}

errore:
	return 0;
	}

int8_t CIFSReadFile(NETWORKDISK_STRUCT *cifs,uint8_t *data,uint32_t size) {
	uint8_t buf[4096]; uint32_t totread=0;
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_READFILE *srf;
	SMB2_READ_RESPONSE *srr;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			do {
				i=min(size,4096);

				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_READ,1,320);
				srf=(SMB2_READFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
				srf->Size.size=0x31;
				srf->Padding=0x50;
				srf->Flags=0;
				srf->Length=i;
				srf->Offset=cifs->fileoffset;
				memcpy(srf->FileGUID,cifs->fileguid,16);
				srf->MinCount=0;
				srf->Channel=0;
				srf->RemainingBytes=0;
				srf->BlobOffset=0;
				srf->BlobLength=0;

				len=sh->Size+(srf->Size.size & 0xfffe)+srf->BlobLength  +1;
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(!CIFSreadResponseSMB2(cifs,buf,4096))    // 64+16+i
					goto errore;		// se ok/completo
				rsh=(SMB2_HEADER*)((char*)buf+4);
				srr=(SMB2_READ_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

				memcpy(data,srr->Blob,i);

				size-=i;
				data+=i;
        totread+=i;
				} while(size>0);
      cifs->fileoffset+=totread;
      return totread;
			}
		}

errore:
	return 0;
	}

int8_t CIFSWriteFile(NETWORKDISK_STRUCT *cifs,const uint8_t *data,uint32_t size) {
	uint8_t buf[4096];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_WRITEFILE *swf;
	SMB2_WRITE_RESPONSE *swr;
	SMB2_SETINFO *si;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_SETINFO,1,1);
			// bah questo non penso che serva davvero, allora credo solo lo spazio
			si=(SMB2_SETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
			si->Size.size=0x21;
			si->Class=SMB2_FILE_INFO;
			si->InfoLevel=SMB2_FILE_ENDOFFILE_INFO;
			si->InfoSize=8;
			si->InfoOffset=0x0060;
			si->Reserved=0;
			si->AdditionalInfo=0;
			memcpy(si->FileGUID,cifs->fileguid,16);
			*(uint64_t*)(&si->Blob[0])=cifs->fileoffset+size;

			len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,4096))      // 196
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

			}

			sh=(SMB2_HEADER*)((char*)buf+4);
      CIFSprepareSMB2header(cifs,sh,SMB2_COM_WRITE,1,1);		// ossia NetShareEnumAll
			swf=(SMB2_WRITEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			swf->Size.size=0x31;
			swf->DataOffset=0x70;
			swf->Offset=cifs->fileoffset;
			memcpy(swf->FileGUID,cifs->fileguid,16);
			swf->Channel=0;
			swf->RemainingBytes=0;
			swf->Flags=0;
			swf->BlobOffset=0;
			swf->BlobLength=0;

			swf->Length=size;
			cifs->fileoffset+=size;


//			i=min(512,size);
			memcpy(&swf->Blob[-4],data,size);
//			data+=i;
//			size-=i;

			len=sh->Size+(swf->Size.size & 0xfffe)+size;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(CIFSreadResponseSMB2(cifs,buf,4096))   // 80
				;		// se ok/completo
			rsh=(SMB2_HEADER*)((char*)buf+4);
			swr=(SMB2_WRITE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

			// COME SI FA se > 65535?!
	/*		if(size) do {
				i=min(512,size);
				Send(data,i);
				data+=i;
				size-=i;
				} while(size>0);*/   return size;
			}
		}

errore:
	return 0;
	}

int8_t CIFSCloseFile(NETWORKDISK_STRUCT *cifs) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CLOSEFILE *sclf;
	SMB2_CLOSE_RESPONSE *scr;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,cifs->fileguid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(CIFSreadResponseSMB2(cifs,buf,512))     // 120
				;		// se ok/completo
			rsh=(SMB2_HEADER*)((char*)buf+4);
			scr=(SMB2_CLOSE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

			memset(cifs->fileguid,0,16);  return 1;
			}
		}

	return 0;
	}

int8_t CIFSDeleteFile(NETWORKDISK_STRUCT *cifs,const char *s) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;
	SMB2_SETINFO *si;
	SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			scf->Size.size=0x39;
 			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_LEASE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_DELETE | SMB2_ACCESS_READATTRIBUTES;	//0x00110080;		//Delete, Sync, Read
			scf->Attributes=0;
			scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
			scf->Disposition=SMB2_FILE_OPEN;
			scf->CreateOptions=SMB2_OPTION_SYNCIONO;		// 0x00000020	// SyncIO non-alert
			scf->BlobFilenameOffset=0x78;
			scf->BlobLength=0;
			scf->BlobOffset=0;
			scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
			uniEncode(s,&scf->Blob[-8]);

			len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 152
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// 
			}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_SETINFO,1,1);
			si=(SMB2_SETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
			si->Size.size=0x21;
			si->Class=SMB2_FILE_INFO;
			si->InfoLevel=SMB2_FILE_DISPOSITION_INFO;
			si->InfoSize=1;
			si->InfoOffset=0x0060;
			si->Reserved=0;
			si->AdditionalInfo=0;
			memcpy(si->FileGUID,guid,16);
			si->Blob[0]=SMB2_SETINFO_DELETEONCLOSE;

			len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 196
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

			}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,guid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CLOSE_RESPONSE *scr=(SMB2_CLOSE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			}

			return 1;

			}
		}

errore:
	return 0;
	}

int8_t CIFSRenameFile(NETWORKDISK_STRUCT *cifs,const char *s,const char *d) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;
	SMB2_SETINFO *si;
	SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];

	//non si capisce... fa delle Create ma boh idem... anche per le Dir
	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			scf->Size.size=0x39;
 			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_LEASE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_DELETE | SMB2_ACCESS_READATTRIBUTES;	//0x00110080;		//Delete, Sync, Read
			scf->Attributes=0;
			scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
			scf->Disposition=SMB2_FILE_OPEN;
			scf->CreateOptions=SMB2_OPTION_SYNCIONO;		// 0x00000020	// SyncIO non-alert
			scf->BlobFilenameOffset=0x78;
			scf->BlobLength=0;
			scf->BlobOffset=0;
			scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
			uniEncode(s,&scf->Blob[-8]);

			len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 152
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// 
			}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_SETINFO,1,1);
			si=(SMB2_SETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
			si->Size.size=0x21;
			si->Class=SMB2_FILE_INFO;
			si->InfoLevel=SMB2_FILE_RENAME_INFO;
			si->InfoOffset=0x0060;
			si->Reserved=0;
			si->AdditionalInfo=0;
			memcpy(si->FileGUID,guid,16);
			{SMB2_FILERENAMEINFO *sfri=(SMB2_FILERENAMEINFO*)&si->Blob[0];
			sfri->ReplaceIf=0;
			memset(&sfri->Reserved,0,7);
			*(uint32_t*)&sfri->Reserved=rand();
			sfri->RootDirHandle=0;		// mah com'è?
			sfri->FilenameLength=2*strlen(d);		//unicode
			uniEncode(d,sfri->Blob);
			si->InfoSize=sizeof(SMB2_FILERENAMEINFO)-256+sfri->FilenameLength;
			}

			len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 196
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

			}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,guid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CLOSE_RESPONSE *scr=(SMB2_CLOSE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

			}

			return 1;

			}
		}

errore:
	return 0;
	}

int8_t CIFSFileStat(NETWORKDISK_STRUCT *cifs,const char *s, struct FSstat *statbuf) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_GETINFO *sgi;
	SMB2_CREATEFILE *scf;
	SMB2_GETINFO_RESPONSE *sgir;
	SMB2_CLOSEFILE *sclf;

	//non si capisce... fa delle Create ma boh
	if(cifs->Flags.Bits.bConnectedD) {
		memset(statbuf,0,sizeof(struct FSstat));
		if(cifs->version==1) {
			}
		else {
			if(s) {
				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
				scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
				scf->Size.size=0x39;
   			scf->SecurityFlags=0;
				scf->Oplock=SMB2_OPLOCK_LEVEL_NONE;
				scf->Impersonation=2;
				scf->Flags=0;
				scf->Reserved=0;
				scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READCONTROL | SMB2_ACCESS_WRITEATTRIBUTES | 
					SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_WRITEEA | SMB2_ACCESS_READEA | SMB2_ACCESS_APPEND | 
					SMB2_ACCESS_WRITE | SMB2_ACCESS_READ;	//0x0012019f
				scf->Attributes=0;
				scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
				scf->Disposition=SMB2_FILE_OPEN;
				scf->CreateOptions=SMB2_OPTION_NORECALL | SMB2_OPTION_NONDIRECTORY;		// 0x00400040
				scf->BlobFilenameOffset=0x78;
				scf->BlobOffset=0;
				scf->BlobLength=0;
				{
				scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
				uniEncode(s,&scf->Blob[-8]);
				}

				len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512)) {   // 152
					rsh=(SMB2_HEADER*)((char*)buf+4);
					{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
          
          FILETIMEPACKED ft;
					statbuf->st_size=scr->EOFSize;
          ft=FiletimeToPackedTime(scr->AccessTime);
					statbuf->st_atime=ft.v;
          ft=FiletimeToPackedTime(scr->WriteTime);
					statbuf->st_ctime=ft.v;
          ft=FiletimeToPackedTime(scr->ModifiedTime);
					statbuf->st_mtime=ft.v;
					statbuf->st_mode=scr->Attrib;			// verificare...
        
          sh=(SMB2_HEADER*)((char*)buf+4);
          CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
          sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
          sclf->Size.size=0x18;
          sclf->Flags=0;
					memcpy(sclf->FileGUID,scr->FileGUID,16);
					}

          len=sh->Size+(sclf->Size.size & 0xfffe);
          CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
          CIFSSend(cifs,buf,len+4);
          if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
            return 0;
          rsh=(SMB2_HEADER*)((char*)buf+4);

          return 1;
          }
				}
			else {
				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_GETINFO,1,1);
				sgi=(SMB2_GETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
				sgi->Size.size=0x29;
				sgi->Class=SMB2_FILE_INFO;
				sgi->InfoLevel=SMB2_FILE_BASIC_INFO;		// 
				sgi->MaxSize=24;
				sgi->InputOffset=0x68;
				sgi->Reserved=0;
				sgi->InputSize=0;
				sgi->AdditionalInfo=0;
				sgi->Flags=0;
				memcpy(sgi->FileGUID,cifs->fileguid,16);
				len=sh->Size+(sgi->Size.size & 0xfffe);
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,512)) {   // 96
					rsh=(SMB2_HEADER*)((char*)buf+4);
					{SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
//					statbuf->st_size=sgir->EOFSize;
//					statbuf->st_atime=*(uint32_t*)&FiletimeToPackedTime(scr->AccessTime);
//					statbuf->st_ctime=*(uint32_t*)&FiletimeToPackedTime(scr->WriteTime);
//					statbuf->st_mtime=*(uint32_t*)&FiletimeToPackedTime(scr->ModifiedTime);
//					statbuf->st_mode=scr->Attrib;			// verificare...
					}
					return 1;
					}
				}
			}
		}

errore:
	return 0;
	}

int8_t CIFSSetFileTime(NETWORKDISK_STRUCT *cifs,const char *s, uint32_t t) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_SETINFO *si;
	SMB2_CREATEFILE *scf;
  SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];
  extern volatile unsigned long now;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			if(!t) 
        t=now;
      sh=(SMB2_HEADER*)((char*)buf+4);
      CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
      scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
      scf->Size.size=0x39;
 			scf->SecurityFlags=0;
      scf->Oplock=SMB2_OPLOCK_LEVEL_NONE;
      scf->Impersonation=2;
      scf->Flags=0;
      scf->Reserved=0;
      scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READCONTROL | SMB2_ACCESS_WRITEATTRIBUTES | 
        SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_WRITEEA | SMB2_ACCESS_READEA | SMB2_ACCESS_APPEND | 
        SMB2_ACCESS_WRITE | SMB2_ACCESS_READ;	//0x0012019f
      scf->Attributes=0;
      scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
      scf->Disposition=SMB2_FILE_OPEN;
      scf->CreateOptions=SMB2_OPTION_NORECALL | SMB2_OPTION_NONDIRECTORY;		// 0x00400040
      scf->BlobFilenameOffset=0x78;
      scf->BlobOffset=0;
      scf->BlobLength=0;
      {
      scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
      uniEncode(s,&scf->Blob[-8]);
      }

      len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
      CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
      CIFSSend(cifs,buf,len+4);
      if(CIFSreadResponseSMB2(cifs,buf,512)) {   // 152
        rsh=(SMB2_HEADER*)((char*)buf+4);
        {SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
        
				memcpy(guid,scr->FileGUID,16);		// 
        
        sh=(SMB2_HEADER*)((char*)buf+4);
        CIFSprepareSMB2header(cifs,sh,SMB2_COM_SETINFO,1,1);
        si=(SMB2_SETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
        si->Size.size=0x21;
        si->Class=SMB2_FILE_INFO;
        si->InfoLevel=SMB2_FILE_BASIC_INFO;
        si->InfoSize=sizeof(SMB2_FILEBASICINFO) /*0x40*/;
        si->InfoOffset=0x0060;
        si->Reserved=0;
        si->AdditionalInfo=0;
        memcpy(si->FileGUID,guid,16);
        {SMB2_FILEBASICINFO *sfbi=(SMB2_FILEBASICINFO*)((char*)si+si->InfoOffset);
        memset(sfbi,0,sizeof(SMB2_FILEBASICINFO));
				sfbi->AccessTime=scr->AccessTime;
				sfbi->ModifiedTime=scr->ModifiedTime;
				sfbi->FileSize=scr->FileSize;
				sfbi->Attrib=scr->Attrib;
        sfbi->WriteTime=TimeToFiletime(t);
        }

        len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
        CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
        CIFSSend(cifs,buf,len+4);
        if(!CIFSreadResponseSMB2(cifs,buf,512))    // 196
          goto errore;
        rsh=(SMB2_HEADER*)((char*)buf+4);
        {SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

        }
        
        }
        
        sh=(SMB2_HEADER*)((char*)buf+4);
        CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
        sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
        sclf->Size.size=0x18;
        sclf->Flags=0;
        memcpy(sclf->FileGUID,guid,16);

        len=sh->Size+(sclf->Size.size & 0xfffe);
        CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
        CIFSSend(cifs,buf,len+4);
        if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
          return 0;
        rsh=(SMB2_HEADER*)((char*)buf+4);

        return 1;
        }
			}
		}

errore:
	return 0;
	}

int8_t CIFSAttrib(NETWORKDISK_STRUCT *cifs,const char *s,uint8_t attrAnd,uint8_t attrOr) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_GETINFO *sgi;
	SMB2_SETINFO *si;
	SMB2_CREATEFILE *scf;
  SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];
  extern volatile unsigned long now;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
      sh=(SMB2_HEADER*)((char*)buf+4);
      CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
      scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
      scf->Size.size=0x39;
 			scf->SecurityFlags=0;
      scf->Oplock=SMB2_OPLOCK_LEVEL_NONE;
      scf->Impersonation=2;
      scf->Flags=0;
      scf->Reserved=0;
      scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READCONTROL | SMB2_ACCESS_WRITEATTRIBUTES | 
        SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_WRITEEA | SMB2_ACCESS_READEA | SMB2_ACCESS_APPEND | 
        SMB2_ACCESS_WRITE | SMB2_ACCESS_READ;	//0x0012019f
      scf->Attributes=0;
      scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
      scf->Disposition=SMB2_FILE_OPEN;
      scf->CreateOptions=SMB2_OPTION_NORECALL | SMB2_OPTION_NONDIRECTORY;		// 0x00400040
      scf->BlobFilenameOffset=0x78;
      scf->BlobOffset=0;
      scf->BlobLength=0;
      {
      scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
      uniEncode(s,&scf->Blob[-8]);
      }
// VERIFICARE!
      len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
      CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
      CIFSSend(cifs,buf,len+4);
      if(CIFSreadResponseSMB2(cifs,buf,512)) {   // 152
        SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
        rsh=(SMB2_HEADER*)((char*)buf+4);
        
				memcpy(guid,scr->FileGUID,16);		// 
        
				sh=(SMB2_HEADER*)((char*)buf+4);
				CIFSprepareSMB2header(cifs,sh,SMB2_COM_GETINFO,1,1);
				sgi=(SMB2_GETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
				sgi->Size.size=0x29;
				sgi->Class=SMB2_FILE_INFO;
        si->InfoLevel=SMB2_FILE_BASIC_INFO;
				sgi->MaxSize=24;
				sgi->InputOffset=0x68;
				sgi->Reserved=0;
				sgi->InputSize=0;
				sgi->AdditionalInfo=0;
				sgi->Flags=0;
				memcpy(sgi->FileGUID,guid,16);
				len=sh->Size+(sgi->Size.size & 0xfffe);
				CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				CIFSSend(cifs,buf,len+4);
				if(CIFSreadResponseSMB2(cifs,buf,1024)) {		// 96
					rsh=(SMB2_HEADER*)((char*)buf+4);
					{SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
		      SMB2_FILEBASICINFO *sfbi=(SMB2_FILEBASICINFO*)((char*)buf+sgir->BlobOffset+4);
					i=sfbi->Attrib;
					}

					sh=(SMB2_HEADER*)((char*)buf+4);
					CIFSprepareSMB2header(cifs,sh,SMB2_COM_SETINFO,1,1);
					si=(SMB2_SETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
					si->Size.size=0x21;
					si->Class=SMB2_FILE_INFO;
					si->InfoLevel=SMB2_FILE_BASIC_INFO;
					si->InfoSize=sizeof(SMB2_FILEBASICINFO) /*0x40*/;
					si->InfoOffset=0x0060;
					si->Reserved=0;
					si->AdditionalInfo=0;
					memcpy(si->FileGUID,guid,16);
					{SMB2_FILEBASICINFO *sfbi=(SMB2_FILEBASICINFO*)((char*)si+si->InfoOffset);
					memset(sfbi,0,sizeof(SMB2_FILEBASICINFO));
					sfbi->AccessTime=scr->AccessTime;
					sfbi->ModifiedTime=scr->ModifiedTime;
					sfbi->FileSize=scr->FileSize;
					sfbi->WriteTime=scr->WriteTime;
					sfbi->Attrib=(i & attrAnd) | attrOr;
					}

					len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
					CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
					CIFSSend(cifs,buf,len+4);
					if(!CIFSreadResponseSMB2(cifs,buf,512))    // 196
						goto errore;
					rsh=(SMB2_HEADER*)((char*)buf+4);
					{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));

					}
        
          sh=(SMB2_HEADER*)((char*)buf+4);
          CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
          sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
          sclf->Size.size=0x18;
          sclf->Flags=0;
          memcpy(sclf->FileGUID,guid,16);

          len=sh->Size+(sclf->Size.size & 0xfffe);
          CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
          CIFSSend(cifs,buf,len+4);
          if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
            return 0;
          rsh=(SMB2_HEADER*)((char*)buf+4);

					}
        return 1;
        }
			}
		}

errore:
	return 0;
	}


int8_t CIFSCloseSession(NETWORKDISK_STRUCT *cifs) {
	uint8_t buf[512];
	int i,len;

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_CLOSE_SESSION *scs;

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_ENDSESSION,1,1);
			scs=(SMB2_CLOSE_SESSION*)((char*)buf+4+sizeof(SMB2_HEADER));
			scs->Size.size=0x4;
			scs->Flags=0;
			len=4+sh->Size+(scs->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(CIFSreadResponseSMB2(cifs,buf,512)) {   // 68
  			rsh=(SMB2_HEADER*)((char*)buf+4);
        

//			SMB2_CLOSESESSION_RESPONSE;		// usare...
        }

			}
		cifs->sessionid=0;

		CIFSDisconnect(cifs);
		}

	return 0;
	}

int8_t CIFSGetVolumeInfo(NETWORKDISK_STRUCT *cifs,char *d,FILETIMEPACKED *t) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_GETINFO *sgi;
  SMB2_CREATEFILE *scf;
	SMB2_CLOSEFILE *sclf;
  uint8_t guid[16];

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
// provare...
      // credo che serva una Create prima, con filename vuoto  v.wireshark
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			scf->Size.size=0x39;
 			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_LEASE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask= SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_READ;		// 0x00100081
			scf->Attributes=0;
			scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
			scf->Disposition=SMB2_FILE_OPEN;
			scf->CreateOptions=SMB2_OPTION_SYNCIONO;	// 0x00000020		// SyncIO non-alert
			scf->BlobFilenameOffset=0x00000078;
			scf->BlobFilenameLength=0;
			scf->BlobOffset=0x00000080;
			scf->BlobLength=64;

			memcpy(&scf->Blob,"\x28\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x10\x00\x00\x00"
        "\x44\x48\x6e\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x04\x00"
        "\x00\x00\x18\x00\x00\x00\x00\x00\x4d\x78\x41\x63\x00\x00\x00\x00",64);

			len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength    +8;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 152
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// FINIRE!
			}

			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_GETINFO,1,1);
			sgi=(SMB2_GETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
			sgi->Size.size=0x29;
			sgi->Class=SMB2_FS_INFO;
			sgi->InfoLevel=SMB2_FS_VOLUME_INFO;		// 
			sgi->MaxSize=88;
			sgi->InputOffset=0;
			sgi->Reserved=0;
			sgi->InputSize=0;
			sgi->AdditionalInfo=0;
			sgi->Flags=0;
			memcpy(&sgi->FileGUID,guid,16);
			len=sh->Size+(sgi->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 96
				goto errore;
			{rsh=(SMB2_HEADER*)((char*)buf+4);
			SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
      SMB2_FILEVOLUMEINFO *sfvi=(SMB2_FILEVOLUMEINFO*)((char*)buf+sgir->BlobOffset   +4);
      uniDecode(sfvi->Label,sfvi->LabelLength,d);
      strupr(d);
      *t=FiletimeToPackedTime(sfvi->CreateTime);
      }

			/*sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_GETINFO,1,1);
			sgi=(SMB2_GETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
			sgi->Size.size=0x29;
			sgi->Class=SMB2_FS_INFO;
			sgi->InfoLevel=SMB2_FS_ATTRIBUTE_INFO;		// 
			sgi->MaxSize=80;
			sgi->InputOffset=0;
			sgi->Reserved=0;
			sgi->InputSize=0;
			sgi->AdditionalInfo=0;
			sgi->Flags=0;
			memcpy(&sgi->FileGUID,guid,16);
			len=sh->Size+(sgi->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,512))    // 96
				goto errore;
			{rsh=(SMB2_HEADER*)((char*)buf+4);
			SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
      SMB2_FILEFSINFO *sffi=(SMB2_FILEFSINFO*)((char*)sgir+sgir->BlobOffset+    4);
// bah qua c'è FSname "NTFS" e attributi del file system...
      }*/

      sh=(SMB2_HEADER*)((char*)buf+4);
      CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
      sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
      sclf->Size.size=0x18;
      sclf->Flags=0;
      memcpy(sclf->FileGUID,guid,16);

      len=sh->Size+(sclf->Size.size & 0xfffe);
      CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
      CIFSSend(cifs,buf,len+4);
      if(!CIFSreadResponseSMB2(cifs,buf,512))    // 120
				goto errore;
      rsh=(SMB2_HEADER*)((char*)buf+4);

			return 1;
			}
		}

errore:
	return 0;
	}

int8_t CIFSVolumeInfo(NETWORKDISK_STRUCT *cifs,uint64_t *totalSectors,uint64_t *freeSectors,uint32_t *sectorSize) {
	uint8_t buf[1024],buf2[256];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_GETINFO *sgi;
	SMB2_CREATEFILE *scf;
	SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];

	if(cifs->Flags.Bits.bConnectedD) {
		if(cifs->version==1) {
			}
		else {
// provare...
      // credo che serva una Create prima, con filename vuoto  v.wireshark
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
			scf->Size.size=0x39;
 			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_LEASE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask= SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_READ;		// 0x00100081
			scf->Attributes=0;
			scf->ShareAccess=SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE;			//
			scf->Disposition=SMB2_FILE_OPEN;
			scf->CreateOptions=SMB2_OPTION_SYNCIONO;	// 0x00000020		// SyncIO non-alert
			scf->BlobFilenameOffset=0x00000078;
			scf->BlobFilenameLength=0;
			scf->BlobOffset=0x00000080;
			scf->BlobLength=64;

			memcpy(&scf->Blob,"\x28\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x10\x00\x00\x00"
        "\x44\x48\x6e\x51\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x04\x00"
        "\x00\x00\x18\x00\x00\x00\x00\x00\x4d\x78\x41\x63\x00\x00\x00\x00",64);

			len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength    +8;
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,1024))			// 152
				goto errore;
			rsh=(SMB2_HEADER*)((char*)buf+4);
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// FINIRE!
			}

			//PROVARE!!
			sh=(SMB2_HEADER*)((char*)buf+4);
			CIFSprepareSMB2header(cifs,sh,SMB2_COM_GETINFO,1,1);
			sgi=(SMB2_GETINFO*)((char*)buf+4+sizeof(SMB2_HEADER));
			sgi->Size.size=0x29;
			sgi->Class=SMB2_FS_INFO;
			sgi->InfoLevel=SMB2_FS_FULL_SIZE_INFO;		// 
			sgi->MaxSize=32;
			sgi->InputOffset=68;
			sgi->Reserved=0;
			sgi->InputSize=0;
			sgi->AdditionalInfo=0;
			sgi->Flags=0;
			memcpy(&sgi->FileGUID,guid,16);
			len=sh->Size+(sgi->Size.size & 0xfffe);
			CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			CIFSSend(cifs,buf,len+4);
			if(!CIFSreadResponseSMB2(cifs,buf,1024))		// 96
				goto errore;
			{rsh=(SMB2_HEADER*)((char*)buf+4);
			SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
      SMB2_FILEVOLUMESIZEINFO *sfvsi=(SMB2_FILEVOLUMESIZEINFO*)((char*)buf+sgir->BlobOffset+4);
			*totalSectors=sfvsi->ActualFreeUnits;		// o AllocSize??
			*freeSectors=sfvsi->CallerFreeUnits;
			*sectorSize=sfvsi->SectorsSize*sfvsi->SectorsPerUnit;   // per comodità!
      }

      sh=(SMB2_HEADER*)((char*)buf+4);
      CIFSprepareSMB2header(cifs,sh,SMB2_COM_CLOSE,1,1);
      sclf=(SMB2_CLOSEFILE*)((char*)buf+4+sizeof(SMB2_HEADER));
      sclf->Size.size=0x18;
      sclf->Flags=0;
      memcpy(sclf->FileGUID,guid,16);

      len=sh->Size+(sclf->Size.size & 0xfffe);
      CIFSprepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
      CIFSSend(cifs,buf,len+4);
      if(!CIFSreadResponseSMB2(cifs,buf,1024))			// 120
				goto errore;
      rsh=(SMB2_HEADER*)((char*)buf+4);

			return 1;
			}
		}

errore:
	return 0;
	}



//# File 'lib/ruby_smb/nbss/netbios_name.rb', line 27

/*def nb_name_decode(encoded_name)
  name = encoded_name.scan(/../).map do |char_pair|
    first_half = char_pair[0];
    second_half = char_pair[1]
    char = ((first_half.ord - 'A'.ord) << 4) + (second_half.ord - 'A'.ord)
    char.chr
  end
  name.join
end

#nb_name_encode(name) ? Object*/




//# File 'lib/ruby_smb/nbss/netbios_name.rb', line 16
char *nbEncode(const char *name,char *encoded_name,BOOL mode) {
	char *p=encoded_name;
	int8_t i=strlen(name),j;

	*p++=0x20;
	for(j=0; j<15; j++) {
		if(j<i) {
			*p++=(*name >> 4) + 'A';
			*p++=(*name & 0xf) + 'A';
			name++;
			}
		else {
			*p++=(' ' >> 4) + 'A';
			*p++=(' ' & 0xf) + 'A';
			}
		}
	if(mode) {		// server
		*p++=2+'A';
		*p++=0+'A';
		}
	else {				// workstation
		*p++=0+'A';
		*p++=0+'A';
		}
	*p=0;		// dice che a volte c'è a volte no.. ma ok
	return encoded_name;
	}

/*def nb_name_encode(name)
  encoded_name = ''
  name.each_byte do |char|
    first_half = (char >> 4) + 'A'.ord
    second_half = (char & 0xF) + 'A'.ord
    encoded_name << first_half.chr
    encoded_name << second_half.chr
  end
  encoded_name
end*/

uint8_t *uniEncode(const char *src,uint8_t *dst) {
	uint8_t *p=dst;
				// o usare 	i=MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED,a,-1,p,n*2);
//	n=wcslen(p);
	while(*src) {
		*p++=*src++;
		*p++=0;
		}
	*p++=0;
	*p=0;

	return dst;
	}

char *uniDecode(const uint8_t *src,int16_t len,char *dst) {
	char *p=dst;

	while(len>0) {    // in caso fosse dispari!
		*p++=*src++;
		src++;
    len-=2;
		}
	*p=0;

	return dst;
	}

uint32_t FiletimeToTime(uint64_t value) {
	//The FILETIME structure is a 64-bit value that represents the number of 100-nanosecond intervals that have elapsed since January 1, 1601, Coordinated Universal Time (UTC).
#define FILETIME_EPOCH_VALUE 116444736000000000ULL

	uint32_t t;
	value-=FILETIME_EPOCH_VALUE;
	value /= 10000000UL;
	t=value;		// va uguale, ok per PC_PIC
	
	return t;
	}

FILETIMEPACKED FiletimeToPackedTime(uint64_t value) {
	uint32_t t;
  PIC32_DATE date;
  PIC32_TIME time;
  FILETIMEPACKED ft;

  t=FiletimeToTime(value);
  SetTimeFromNow(t,&date,&time);
  ft.day=date.mday;
  ft.mon=date.mon;
  ft.year=date.year-1980;
  ft.hour=time.hour;
  ft.min=time.min;
  ft.sec=time.sec;
	
	return ft;
	}

uint64_t TimeToFiletime(uint32_t value) {
	//The FILETIME structure is a 64-bit value that represents the number of 100-nanosecond intervals that have elapsed since January 1, 1601, Coordinated Universal Time (UTC).

	uint64_t t=(uint64_t)value*10000000ULL;
	t+=FILETIME_EPOCH_VALUE;
	
	return t;
	}

BYTE CIFS_MediaDetect(MEDIA_INFORMATION *mi) {    // anche FTP cmq

//  mi->tag=(DWORD)&networkFile;    fatto da Command, se no devo includere tutto pure qua...
	return theNetworkDisk.Flags.Bits.bConnectedD ? 1 : 0;
	}

void CIFS_initIO(MEDIA_INFORMATION *mi) {    // anche FTP cmq

//  mi->tag=(DWORD)&networkFile;    fatto da Command, se no devo includere tutto pure qua...
// ev fare connect? bah
	}

#endif

