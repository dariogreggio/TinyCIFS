#include <stdint.h>
#include <string.h>
#include <sys/endian.h>

#include "compiler.h"
#include "fsio.h"
#include "cifs.h"
#include "at_winc1500.h"
	
//https://amitschendel1.medium.com/smb-going-from-zero-to-hero-ff686e907e81

//https://www.wireshark.org/docs/wsar_html/packet-smb2_8h_source.html
//  per definizioni struct costanti ecc di SMB2

extern volatile unsigned long now;
extern Ipv4Addr myIp,acceptedIp;
extern WORD acceptedPort;
extern uint8_t internetBuffer[1024];
extern WORD internetBufferLen;   //
extern uint8_t rxBuffer[1536];
extern WORD rxBufferLen;   //
extern SOCKET TCPDataSocket,TCPDataSocket2;   // METTERE anche il 2 nella Struct
extern SOCKET UDPclientSocket;
extern Ipv4Addr myIp;
extern BYTE SDcardOK;
extern struct SAVED_PARAMETERS configParms;
extern const char * const ASTERISKS,* const DOTDOTS,* const ROOTDIR;

SMB2_SERVER_DATA SMB2Server;

int16_t sendEx(SOCKET, const void *, uint16_t);

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

char *nbEncode(const char *name,char *encoded_name,BOOL mode) {
	char *p=encoded_name;
	int8_t i=strlen(name),j;

	*p++=0x20;
	for(j=0; j<15; j++) {
		if(j<i) {
			*p++=(toupper(*name) >> 4) + 'A';
			*p++=(toupper(*name) & 0xf) + 'A';
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

uint64_t PackedTimeToFiletime(FILETIMEPACKED t) {
  PIC32_DATE date;
  PIC32_TIME time;

  date.mon=t.mon;
  date.year=t.year+1980;
  date.mday=t.day;
  time.hour=t.hour;
  time.min=t.min;
  time.sec=t.sec;
	return TimeToFiletime(SetNowFromTime(date,time));
	}

uint64_t TimeToFiletime(uint32_t value) {
	//The FILETIME structure is a 64-bit value that represents the number of 100-nanosecond intervals that have elapsed since January 1, 1601, Coordinated Universal Time (UTC).

	uint64_t t=(uint64_t)value*10000000ULL;
	t+=FILETIME_EPOCH_VALUE;
	
	return t;
	}

void getGUID(uint8_t *p) {
	int8_t i;

	for(i=0; i<16; i++)
		p[i]=rand();
	}

inline BOOL cmpGUID(uint8_t *p1,uint8_t *p2) {

	return !memcmp(p1,p2,16);		// o confrontare 2 uint64_t ??
	}

uint64_t gettime(uint32_t t) {
	uint64_t n=FILETIME_EPOCH_VALUE;

	if(!t)
		t=now;
	n+=((uint64_t)t)*10000000UL;

	return n;
	}


// ---------------------------------------------------------------------------------------------------------------

BOOL SMB2CreateServer() {
  int8_t error=0;
  int16_t tOut;

  memset(&SMB2Server,0,sizeof(SMB2_SERVER_DATA));
	SMB2Server.version=2;
	SMB2Server.port=445 /*configParms.port*/;
  //Open a TCP socket
  SMB2Server.sock = socket(AF_INET, SOCK_STREAM, 0);
  //Failed to open socket?
  if(SMB2Server.sock == INVALID_SOCKET) {
      //Report an error
    error = 1;
    }
//  TRACE_INFO("SMB2 socket : %d\r\n",SMB2Server.sock);

  TCPDataSocket=SMB2Server.sock;
      //Bind the socket to the passive port number
  {
    struct sockaddr_in strAddr;
    strAddr.sin_family = AF_INET;
    strAddr.sin_port = htons(SMB2Server.port);
    strAddr.sin_addr.s_addr = nmi_inet_addr(INADDR_ANY);
    tOut=0;
    *(unsigned long*)internetBuffer=0;
    error = bind(SMB2Server.sock, (struct sockaddr*)&strAddr, sizeof(struct sockaddr_in)) != SOCK_ERR_NO_ERROR;
    while(!*(unsigned long*)internetBuffer && tOut<1000) {
      m2m_wifi_handle_events(NULL);
      tOut++;
      __delay_ms(1);
      }
    }
      //Failed to bind the socket to the desired port?
  
       //Place the data socket in the listening state
//ARRIVA DI LA'       error = listen(connection->dataChannel.socket, 1);
/*  tOut=0;
  *(unsigned long*)internetBuffer=0;
	while(!*(unsigned long*)internetBuffer && tOut<1000) {
    m2m_wifi_handle_events(NULL);
    tOut++;
    __delay_ms(1);
		}*/
    //Any error to report?

  return !error;
	}

void SMB2OnAccept() {

	if(SMB2Server.totConn < MAX_CLIENT_CONNECTIONS) {
			SMB2Server.totConn++;

//			j=Accept(*s);
//			s->getPeer() ;
			SMB2Server.startConn=now;		// o in NEGOTIATE?
      setStatusLed(LED_NORMALE_CONNESSO_FTP);
			return;
		}

	close(TCPDataSocket2);
  TCPDataSocket2=INVALID_SOCKET;
	}


void doDelete() {
	SMB2Server.totConn--;
	}

void smb2ServerTask() {
  
	SMB2Server.cliTimeOut; // CONTROLLARE 
  if(rxBufferLen) {
    SMB2OnReceive();
    rxBufferLen=0;
    recv(TCPDataSocket2, rxBuffer, sizeof(rxBuffer), 0);
    }

  }

BOOL SMB2CloseServer() {
  close(SMB2Server.sock);
  SMB2Server.sock=INVALID_SOCKET;
  close(TCPDataSocket2);
  TCPDataSocket2=INVALID_SOCKET;
  }

static int SMB2Send(const uint8_t *buffer) {
  uint16_t len=(uint16_t)htonl(*(DWORD*)buffer)+4;
  
  rxBufferLen=0;
//  memset(rxBuffer,0,sizeof(rxBuffer));
  return sendEx(TCPDataSocket2 /*SMB2Server.sock*/,buffer,len);
  }

const char *NEGOTIATE_SECURITY_BLOB="\x60\x28"
  "\x06\x06"    // ossia NEG_RESPONSE
	"\x2b\x06\x01\x05\x05\x02"		// OID SPNEGO
	"\xa0\x1e"
  "\x30\x1c\xa0\x1a\x30\x18"
	"\x06\x0a"
	"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e"		 //OID mechtipe1
	"\x06\x0a"
	"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a";		// OID mechtipe2
const char *domainName="SKYNET";
const char *computerName="SKYNET";

const uint8_t OID_1_3_6_1_5_5_2[]={0x2b,0x06,0x01,0x05,0x05,0x02};		// OID inviati da server in risposta a Negotiate Protocol
const uint8_t OID_1_3_6_1_4_1_311_2_2_30[]={0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x1e}; //OID mechtipe1
const uint8_t OID_1_3_6_1_4_1_311_2_2_10[]={0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0xa}; //OID mechtipe2

//#pragma GCC push_options
//#pragma GCC optimize("O0")    // non fa nulla puttano dio
void SMB2OnReceive() {
	char myBuf[512];
	int i,n;


	if(SMB2Server.version==1) {
		SMB1_HEADER sh;
//		i=recv(SMB2Server.sock,&sh,sizeof(SMB2_HEADER),0);		// ossia len  FINIRE!
//    SMB2Receive(myBuf,1024);
		}
	else {
		SMB2_HEADER *sh; //

//    SMB2Receive(myBuf,1024);
//		sh=(SMB2_HEADER*)((char*)myBuf);
		sh=(SMB2_HEADER*)((char*)rxBuffer);
// https://serverfault.com/questions/877968/smbv2-and-windows-7
    if(sh->Protocol[0] == 0xff) {     // e gli altri 3 char? :)
      if(((SMB1_HEADER*)sh)->Command == SMB_COM_NEGOTIATE) {   // gestisco il NEGOTIATE in SMB1... dice
				SMB_NEGOTIATE_PROTOCOL *snp;
				SMB2_NEGOTIATE_RESPONSE *snr;
//				i=Receive(&myBuf,i /*sizeof(SMB2_NEGOTIATE_PROTOCOL)*/);
				snp=(SMB_NEGOTIATE_PROTOCOL*)((char*)rxBuffer+sizeof(SMB1_HEADER));
				SMB2Server.msgcntS=0;

				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_NEGOTIATE,STATUS_OK,SMB2Server.sessionid,0,1);

				snr=(SMB2_NEGOTIATE_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				snr->Size.dynamicPart=1;  snr->Size.fixedPart=32;
				snr->Security=SMB2_FLAG_SIGNING_ENABLED;
				snr->Dialect=0x2ff;   // SMB2 wildcard
				snr->Capabilities=SMB2_NEGOTIATE_DFS | SMB2_NEGOTIATE_LEASING;
				snr->NegotiateContextcount=0;
				getGUID(SMB2Server.serverguid);
				memcpy(snr->ServerGUID,SMB2Server.serverguid,16);
				snr->MaxTransactionSize=65536;
				snr->MaxReadSize=65536;
				snr->MaxWriteSize=65536;
				snr->CurrentTime=gettime(0);
				snr->BootTime=gettime((0-0));   // fare :)
				snr->BlobOffset=0x80;
				snr->BlobLength=42;
				snr->NegotiateContextoffset=0x53534d4c /*LMSS*/;  /*0x204D4C20*/	// LM 
        NEG_TOKEN_RESPONSE *ntr=(NEG_TOKEN_RESPONSE*)&snr->Blob;
        ntr->oi1.type=0x06;
        ntr->oi1.type=sizeof(ntr->OID);
        memcpy(ntr->OID,OID_1_3_6_1_5_5_2,6);
        ntr->mt1.type=0x06;
        ntr->mt1.type=sizeof(ntr->mechType1);
        memcpy(ntr->mechType1,OID_1_3_6_1_4_1_311_2_2_30,10);
        ntr->mt2.type=0x06;
        ntr->mt2.type=sizeof(ntr->mechType2);
        memcpy(ntr->mechType2,OID_1_3_6_1_4_1_311_2_2_10,10);
        memcpy(snr->Blob,NEGOTIATE_SECURITY_BLOB,snr->BlobLength);    // FINIRE e TOGLIERE!

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_NEGOTIATE_RESPONSE)-sizeof(snr->Blob)+snr->BlobLength);
				SMB2Send(myBuf);
        }
      else
        goto bad_protocol;
      }
    else {
      if(sh->Protocol[0] != 0xfe)      // e gli altri 3 char? :)
        goto bad_protocol;
      }

		if(SMB2Server.sessionid && SMB2Server.sessionid != sh->SessionID)
			goto errore_sid;
		if(SMB2Server.treeid && SMB2Server.treeid != sh->TreeID)
			goto errore_tid;
		if(SMB2Server.processid && SMB2Server.processid != sh->ProcessID)
			goto errore_pid;
//    if(memcmp(SMB2Server.signature,sh->Signature,sizeof(SMB2Server.signature))
//      goto errore_sig;
    
		switch(sh->Command) {
			case SMB2_COM_NEGOTIATE:
				{
				SMB2_NEGOTIATE_PROTOCOL *snp;
				SMB2_NEGOTIATE_RESPONSE *snr;
//				i=Receive(&myBuf,i /*sizeof(SMB2_NEGOTIATE_PROTOCOL)*/);
				snp=(SMB2_NEGOTIATE_PROTOCOL*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(snp->Size.size != 0x24)
					goto errore_size;
				n=snp->DialectCount;
				SMB2Server.processid=sh->ProcessID;
				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;

				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_NEGOTIATE,STATUS_OK,SMB2Server.sessionid,1,1);

				snr=(SMB2_NEGOTIATE_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				snr->Size.dynamicPart=1;  snr->Size.fixedPart=32;
				snr->Security=SMB2_FLAG_SIGNING_ENABLED;
				snr->Dialect=0x210;
				snr->Capabilities=SMB2_NEGOTIATE_DFS | SMB2_NEGOTIATE_LEASING;
				snr->NegotiateContextcount=0;
				getGUID(SMB2Server.serverguid);
				memcpy(snr->ServerGUID,SMB2Server.serverguid,16);
				snr->MaxTransactionSize=65536;
				snr->MaxReadSize=65536;
				snr->MaxWriteSize=65536;
				snr->CurrentTime=gettime(0);
				snr->BootTime=gettime((0));   // fare :)
				snr->BlobOffset=0x80;
				snr->BlobLength=42;
				snr->NegotiateContextoffset=0x53534d4c;		//LMSS
        memcpy(snr->Blob,NEGOTIATE_SECURITY_BLOB,snr->BlobLength);

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_NEGOTIATE_RESPONSE)-sizeof(snr->Blob)+snr->BlobLength);
				SMB2Send(myBuf);
				}
				break;
			case SMB2_COM_OPENSESSION:
        {BOOL asGuest=FALSE;
				switch(SMB2Server.sessionstate) {
					SMB2_OPEN_SESSION *sos;
          SMB2_OPENSESSION_RESPONSE *sosr;
					case 0:
            {SESS_TOKEN_TARG *stt1;
						if(sh->SessionID==SMB2Server.sessionid)
							;

		//				i=Receive(&myBuf,i /*sizeof(SMB2_OPEN_SESSION)*/);
						sos=(SMB2_OPEN_SESSION*)((char*)rxBuffer+sizeof(SMB2_HEADER));
						if(sos->Size.size != 0x19)
							goto errore_size;

            NEG_TOKEN_INIT *nti=(NEG_TOKEN_INIT*)sos->SecurityBlob;
            
						SMB2Server.msgcntR=sh->MessageID;
						SMB2Server.msgcntS=SMB2Server.msgcntR;
						sh=(SMB2_HEADER*)((char*)myBuf+4);
						prepareSMB2header(sh,SMB2_COM_OPENSESSION,asGuest ? STATUS_OK : STATUS_MORE_PROCESSING_REQUIRED,
							rand() | ((uint32_t)rand() << 16),1,32);

						sosr=(SMB2_OPENSESSION_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
						sosr->Size.dynamicPart=1;		sosr->Size.fixedPart=4;
						sosr->Flags=asGuest ? SMB2_SESSION_GUEST : 0;
            if(asGuest) {
  						sosr->BlobOffset=0;
    					sosr->BlobLength=0;
  						SMB2Server.sessionstate=2;
              }
            else {// no pare serva cmq, ma tanto non funzia lo stesso... serve AUTH
              sosr->BlobOffset=0x48;
              sosr->BlobLength=179;     // sizeof(stt1)
              stt1=(SESS_TOKEN_TARG*)&sosr->Blob;
              stt1->hdr[0]=0xa1; stt1->hdr[1]=0x81; stt1->hdr[2]=0xb0;
              stt1->hdr2[0]=0x30; stt1->hdr2[1]=0x81; stt1->hdr2[2]=0xad; stt1->hdr2[3]=0xa0; stt1->hdr2[4]=0x03; stt1->hdr2[5]=0x0a; stt1->hdr2[6]=0x01;
              stt1->negResult=1;   // incomplete
              stt1->boh[0]=0xa1; stt1->boh[1]=0x0c; 
              stt1->smt.type=0x06;
              stt1->smt.dim=sizeof(stt1->supportedMech);
//              memcpy(&stt1->supportedMech,"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a",sizeof(stt1->supportedMech));
              memcpy(&stt1->supportedMech,nti->mechType,sizeof(stt1->supportedMech));
              stt1->boh2[0]=0xa2; stt1->boh2[1]=0x81; stt1->boh2[2]=0x97; stt1->boh2[3]=0x04; stt1->boh2[4]=0x81; stt1->boh2[5]=0x94;
              memcpy(&stt1->id,"NTLMSSP",sizeof(stt1->id));
              stt1->messageType=NTLM_CHALLENGE_MESSAGE;   // challenge
              stt1->lenName=6*2;   // ABCDEF  domainName    WiFi_Pen
              stt1->maxlenName=6*2;
              stt1->ofsName=0x00000038;
              stt1->negotiateFlags=       //0xe28a8215;
                NTLMSSP_NEGOTIATE_56 | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_128 | 
                NTLMSSP_NEGOTIATE_VERSION | 
								NTLMSSP_NEGOTIATE_TARGET_INFO |
								NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_TARGET_TYPE_SERVER |
                NTLMSSP_NEGOTIATE_ALWAYS_SIGN | 
                NTLMSSP_ANONYMOUS | NTLMSSP_NEGOTIATE_NTLM | 
								NTLMSSP_NEGOTIATE_SIGN |
                NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_UNICODE;

              stt1->NTLMchallenge=0x0102030405060708;
              stt1->reserved=0;
              stt1->lenInfo=80;
              stt1->maxlenInfo=80;
              stt1->ofsInfo=0x00000044;
              stt1->versionMaj=WINDOWS_MAJOR_VERSION_6;    // cambiare?!
              stt1->versionMin=WINDOWS_MINOR_VERSION_1;
              stt1->versionBuild=7601;
              stt1->versionUnused[0]=stt1->versionUnused[1]=stt1->versionUnused[2]=0;
              stt1->versionNTLMrev=15;
              uniEncode(domainName,stt1->info);
              stt1->attribute[0].type=MsvAvNbDomainName;   // NetBIOS domain name
              stt1->attribute[0].length=12;
              uniEncode(domainName,stt1->attribute[0].name);
              stt1->attribute[1].type=MsvAvNbComputerName;   // NetBIOS computer name
              stt1->attribute[1].length=12;
              uniEncode(computerName,stt1->attribute[1].name);
              stt1->attribute[2].type=MsvAvDnsDomainName;   // DNS domain name
              stt1->attribute[2].length=12;
              uniEncode(domainName,stt1->attribute[2].name);
              stt1->attribute[3].type=MsvAvDnsComputerName;   // DNS computer name
              stt1->attribute[3].length=12;
              uniEncode(computerName,stt1->attribute[3].name);
              memset(&stt1->attribute[4],0,16*2);   // patch perché ultimo e penultimo campo sono più corti..
              stt1->attribute[4].type=MsvAvTimestamp;   // Timestamp
              stt1->attribute[4].length=8;
              *(uint64_t*)&stt1->attribute[4].name=gettime(0);
              stt1->attribute[5].type=MsvAvEOL;   // End of list
              stt1->attribute[5].length=0;
  						SMB2Server.sessionstate++;
              }
            
						*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_OPENSESSION_RESPONSE)-sizeof(sosr->Blob)+sosr->BlobLength);
						SMB2Send(myBuf);
            }
						break;
					case 1:
            {SESS_TOKEN_TARG2 *stt2;
		//				i=Receive(&myBuf,i /*sizeof(SMB2_OPEN_SESSION)*/);
						sos=(SMB2_OPEN_SESSION*)((char*)rxBuffer+sizeof(SMB2_HEADER));
						SMB2Server.sessionid=sh->SessionID;
						if(sos->Size.size != 0x19)
							goto errore_size;

						SMB2Server.msgcntR=sh->MessageID;
						SMB2Server.msgcntS=SMB2Server.msgcntR;
            memcpy(&SMB2Server.signature,"\xda\x91\x7f\xdb\xa4\x4d\x87\x86\xca\xd7\x18\x4e\xcf\x53\x1a\xf3",sizeof(SMB2Server.signature));
        memset(&SMB2Server.signature,0,sizeof(SMB2Server.signature));// SOLO se il flag in Header contiene SIGNED!
						sh=(SMB2_HEADER*)((char*)myBuf+4);
						prepareSMB2header(sh,SMB2_COM_OPENSESSION,STATUS_OK,SMB2Server.sessionid,1,1);
// ev.            sh->Flags |= SMB2_FLAG_SIGNING;

						sosr=(SMB2_OPENSESSION_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
						sosr->Size.dynamicPart=1;		sosr->Size.fixedPart=4;
						sosr->Flags=0;
						sosr->BlobOffset=0x48;
						sosr->BlobLength=29;    // sizeof(stt2)
            stt2=(SESS_TOKEN_TARG2*)&sosr->Blob;
            stt2->hdr.type=0xa1;
            stt2->hdr.dim=0x1b;
            stt2->hdr2[0]=0x30; stt2->hdr2[1]=0x19; stt2->hdr2[2]=0xa0; stt2->hdr2[3]=0x03; stt2->hdr2[4]=0x0a; stt2->hdr2[5]=0x01;
            stt2->negResult=0;   // accept -complete
            stt2->boh[0]=0xa3; stt2->boh[1]=0x12; stt2->boh[2]=0x04; stt2->boh[3]=0x10;
            stt2->verifierVersionNumber=1;
//            memcpy(&stt2->verifierBody,"\x23\x61\x4e\xe4\xc4\xff\x33\x79\x00\x00\x00\x00",sizeof(stt2->verifierBody));
            memcpy(&stt2->verifierBody,"\xd2\xd7\xf5\x78\xca\x85\x38\xb5\x00\x00\x00\x00",sizeof(stt2->verifierBody));

						*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_OPENSESSION_RESPONSE)-sizeof(sosr->Blob)+sosr->BlobLength);
						SMB2Send(myBuf);
            }

						SMB2Server.sessionstate++;
						break;
					}
        }
				break;
			case SMB2_COM_ENDSESSION:
				{
				SMB2_CLOSE_SESSION *scs;
				SMB2_CLOSESESSION_RESPONSE *scsr;
//				i=Receive(&myBuf,sizeof(SMB2_CLOSE_SESSION));
				scs=(SMB2_CLOSE_SESSION*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(scs->Size.size != 0x4)
					goto errore_size;

				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_ENDSESSION,STATUS_OK,SMB2Server.sessionid,1,1);

				scsr=(SMB2_CLOSESESSION_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				scsr->Size.dynamicPart=0;		scsr->Size.fixedPart=2;
				scsr->Reserved=0;
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_CLOSESESSION_RESPONSE));
				SMB2Send(myBuf);

        memset(&SMB2Server.signature,0,sizeof(SMB2Server.signature));
				SMB2Server.sessionstate=0;
				}
				break;
			case SMB2_COM_TREECONNECT:
				{
				SMB2_TREE_CONNECT *stc;
				SMB2_TREE_CONNECT_RESPONSE *stcr;
				uint8_t *p;
				char nome[64],*p2;
				SearchRec finder;
//				char realPath[128];
				int n;

//				i=Receive(&myBuf,sizeof(SMB2_FIND));
				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;

        if(!SDcardOK) 
          goto no_disc;

//				i=Receive(&myBuf,sizeof(SMB2_TREE_CONNECT));
				stc=(SMB2_TREE_CONNECT*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(stc->Size.size != 0x9)
					goto errore_size;

				p=(uint8_t*)rxBuffer+stc->BlobOffset;
				uniDecode(p,stc->BlobLength,nome);
				p2=strrchr(nome,'\\');
				if(p2)
					/* p2++ */;		// vado in root cmq
				else			// beh NON deve accadere!
					p2=nome;

        FSchdir(ROOTDIR);
				strcpy(SMB2Server.curtree,p2);
        if(!stricmp(p2,"C$")) {
          // gestire!
          }
        else if(!stricmp(p2,"IPC$")) {
          }
        else {
          }
//				strcat(p2,"\\*.*");   ASTERISKS
//				BOOL bWorking = FindFirst("*.*" /*p2*/,ATTR_MASK,&finder) >= 0;
				BOOL bWorking = FindFirst((char*)SMB2Server.curtree+1,ATTR_DIRECTORY,&finder) >= 0;   // salto "\"
				n=bWorking;
/*				if(bWorking) {
					bWorking = !FindNext(&finder);
					if(bWorking) {
						n=1;
						}
					}*/
				if(!n)
					*SMB2Server.curtree=0;

				SMB2Server.treeid=rand();		// VERIFICARE! o mettere un progressivo su finder
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_TREECONNECT,n ? STATUS_OK : STATUS_NO_SUCH_FILE /*STATUS_OBJECT_NAME_NOT_FOUND*/,SMB2Server.sessionid,1,1);

				stcr=(SMB2_TREE_CONNECT_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				stcr->Size.dynamicPart=0;		stcr->Size.fixedPart=8;
/* per IPC$				stcr->Type=SMB2_TREE_NAMEDPIPE;	//named pipe
				stcr->Reserved=0;
				stcr->Flags=0x00000030;
				stcr->Capabilities=0x00000000;
				stcr->AccessMask=0x011f01ff;*/
				stcr->Type=SMB2_TREE_PHYSICALDISK;		// physical disk
				stcr->Reserved=0;
				stcr->Flags=0x00000000;
				stcr->Capabilities=0x00000000;
				stcr->AccessMask=0x001200a9;

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_TREE_CONNECT_RESPONSE));
				SMB2Send(myBuf);
				}
				break;
			case SMB2_COM_TREEDISCONNECT:
				{
				SMB2_TREE_DISCONNECT *std;
				SMB2_TREEDISCONNECT_RESPONSE *stdr;
//				i=Receive(&myBuf,sizeof(SMB2_TREE_DISCONNECT));
				std=(SMB2_TREE_DISCONNECT*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(std->Size.size != 0x4)
					goto errore_size;

				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_TREEDISCONNECT,STATUS_OK,SMB2Server.sessionid,1,1);

				stdr=(SMB2_TREEDISCONNECT_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				stdr->Size.dynamicPart=0;		stdr->Size.fixedPart=2;
				stdr->Reserved=0;
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_TREEDISCONNECT_RESPONSE));
				SMB2Send(myBuf);

				*SMB2Server.curfile=0;
				*SMB2Server.curtree=0;
				SMB2Server.treeid=0;
				}
				break;
			case SMB2_COM_CREATE:
				{
				SMB2_CREATEFILE *scf;
				SMB2_CREATE_RESPONSE *scr;
				char nomefile[64]/*,nometemp[64]*/;
				uint8_t *p;
				int i;
				char myguid[16];

//				i=Receive(&myBuf,sizeof(SMB2_CREATEFILE));
				scf=(SMB2_CREATEFILE*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(scf->Size.size != 0x39)
					goto errore_size;

				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;

        if(!SDcardOK) 
          goto no_disc;
        
				SMB2Server.createflags=scf->Flags;
				SMB2Server.createoptions=scf->CreateOptions;
				p=(uint8_t*)rxBuffer+scf->BlobFilenameOffset;

				if(scf->BlobFilenameLength)
					uniDecode(p,scf->BlobFilenameLength,nomefile);
				else
					*nomefile=0;

				sh=(SMB2_HEADER*)((char*)myBuf+4);

				scr=(SMB2_CREATE_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				scr->Size.dynamicPart=1;		scr->Size.fixedPart=44;		// OCCHIO è variabile a seconda del tipo di create!

/*				strcpy(nometemp,SMB2Server.curtree);
				strcat(nometemp,"\\"); 
				strcat(nometemp,nomefile); idem come in Find */
        FSchdir(ROOTDIR);
#warning CHDIR cmq dovrebbe gestire i subpath, provare ovunque
        FSchdir(SMB2Server.curtree);
        if(*SMB2Server.curdir)
          FSchdir(SMB2Server.curdir);

        SetClockVarsNow();
				getGUID(myguid);
				if(*nomefile) {
					i=0;
					if(SMB2Server.createoptions & SMB2_OPTION_DIRECTORY) {
						strcpy(SMB2Server.curdir,nomefile);
						i=FSmkdir(nomefile);
						memcpy(SMB2Server.dirguid,myguid,16);
						}
					else {
						strcpy(SMB2Server.curfile,nomefile);
						if(scf->AccessMask & SMB2_ACCESS_READ) {
							SMB2Server.file=FSfopen(nomefile,OPEN_READ,SHARE_READ /*    | shareDenyWrite*/);
              i=SMB2Server.file != 0;
							scr->Action=i ? 1 : 0;			// 
							}
						else if(scf->AccessMask & SMB2_ACCESS_WRITE) {
							SMB2Server.file=FSfopen(nomefile,OPEN_WRITE,SHARE_READWRITE /*| shareDenyNone*/);
              i=SMB2Server.file != 0;
							scr->Action=i ? 2 : 0;			// FINIRE con create opp no
							}
						else if(scf->AccessMask & (SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_WRITEATTRIBUTES | SMB2_ACCESS_DELETE)) {
//						else if((scf->AccessMask & 7) == 0) {		// FINIRE per casi come Rename e altro
              i=2;
							scr->Action=i ? 1 : 0;			// 
							}
						memcpy(SMB2Server.fileguid,myguid,16);
						}

					struct FSstat fs;
					FSstat(SMB2Server.curfile,&fs);
					scr->Attrib=fs.st_mode;
					scr->EOFSize=fs.st_size;
					scr->FileSize=fs.st_size;
					scr->AccessTime=gettime(fs.st_atime);
					scr->CreateTime=gettime(fs.st_ctime);
					scr->ModifiedTime=gettime(fs.st_mtime);
					scr->WriteTime=gettime(fs.st_mtime);
					}
				else {
					i=3;		// casi speciali con Blob...
					memcpy(SMB2Server.fileguid,myguid,16);		// serve per Find... e rename?
					}

				scr->Oplock=scf->Oplock;	// sembra, quasi
				scr->Flags=0;		//finire
				if(i != 1) {
					scr->Attrib=0;
					scr->EOFSize=0;
					scr->FileSize=0;
					scr->AccessTime=0;
					scr->CreateTime=0;
					scr->ModifiedTime=0;
					scr->WriteTime=0;
					}
				scr->Reserved=0;
				scr->BlobLength=0;
				scr->BlobOffset=0;
				memcpy(scr->FileGUID,myguid,16);

				prepareSMB2header(sh,SMB2_COM_CREATE,i ? STATUS_OK : STATUS_OBJECT_NAME_NOT_FOUND,SMB2Server.sessionid,1,1);

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_CREATE_RESPONSE)-sizeof(scr->Blob)+scr->BlobLength);
				SMB2Send(myBuf);
				}
				break;
			case SMB2_COM_CLOSE:
				{
				SMB2_CLOSEFILE *scs;
				SMB2_CLOSE_RESPONSE *scsr;

//				i=Receive(&myBuf,sizeof(SMB2_CLOSEFILE));
				scs=(SMB2_CLOSEFILE*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(scs->Size.size != 0x18)
					goto errore_size;

				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);

				scsr=(SMB2_CLOSE_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				scsr->Size.dynamicPart=0;		scsr->Size.fixedPart=30;
				if(*SMB2Server.curfile) {
					struct FSstat fs;
					FSstat(SMB2Server.curfile,&fs);
					scsr->Attrib=fs.st_mode;
					scsr->EOFSize=fs.st_size;
					scsr->FileSize=fs.st_size;
					scsr->AccessTime=gettime(fs.st_atime);
					scsr->CreationTime=gettime(fs.st_ctime);
					scsr->ModifiedTime=gettime(fs.st_mtime);
					scsr->WriteTime=gettime(fs.st_mtime);
					FSfclose(SMB2Server.file);
					}
				else {
					scsr->AccessTime=0;
					scsr->CreationTime=0;
					scsr->ModifiedTime=0;
					scsr->WriteTime=0;
					scsr->Reserved=0;
					scsr->EOFSize=0;
					scsr->FileSize=0;
					scsr->Attrib=0;
					scsr->Flags=0;
					}
				if(*SMB2Server.curfile && SMB2Server.createoptions & SMB2_OPTION_DELETEONCLOSE)
					FSremove(SMB2Server.curfile);

				prepareSMB2header(sh,SMB2_COM_CLOSE,STATUS_OK,SMB2Server.sessionid,1,1);

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_CLOSE_RESPONSE));
				SMB2Send(myBuf);

        FSchdir(ROOTDIR);
        
				*SMB2Server.curfile=0;		// occhio se le cose si sovrappongono
				SMB2Server.createflags=0;
				SMB2Server.createoptions=0;
				}
				break;
			case SMB2_COM_FLUSH:
				{
				}
				break;
			case SMB2_COM_READ:
				{
				SMB2_READFILE *srf;
				SMB2_READ_RESPONSE *srr;
        int n2;
//				uint8_t buf[256 /*65536*/];			// v. max Transaction ecc
        
//				i=Receive(&myBuf,sizeof(SMB2_READFILE));
				srf=(SMB2_READFILE*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(srf->Size.size != 0x31)
					goto errore_size;
				if(memcmp(srf->FileGUID,SMB2Server.fileguid,16))
					goto errore_guid;

				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);

				srr=(SMB2_READ_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				srr->Size.dynamicPart=1;		srr->Size.fixedPart=8;
				FSfseek(SMB2Server.file,srf->Offset,SEEK_SET);
				srr->BlobOffset=0x50;
        n2=min(65536 /*MaxTransaction Size*/,srf->Length);    // VERIFICARE se c'è tutto :)
        srr->BlobLength=srf->Length;    // VERIFICARE se c'è tutto :)
// ecco        srr->BlobLength=n;
        srr->RemainingBytes=srf->Length-n2;
        srr->Reserved=srr->Reserved2=0;
        
				prepareSMB2header(sh,SMB2_COM_READ,  /*?*/ STATUS_OK,SMB2Server.sessionid,1,1);
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_READ_RESPONSE)-sizeof(srr->Blob)+srr->BlobLength);
        sendEx(TCPDataSocket2 /*SMB2Server.sock*/,myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_READ_RESPONSE)-sizeof(srr->Blob));

        n=0;
        while(n<n2) {    // il max sarebbe MaxTransaction da Negotiate
          i=FSfread((char*)myBuf,1,256,SMB2Server.file);		// v. sopra
          sendEx(TCPDataSocket2 /*SMB2Server.sock*/,myBuf,i);
          n+=i;
          }
				SMB2Server.fileoffset=FSftell(SMB2Server.file);

//				*(DWORD*)buf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_READ_RESPONSE)-sizeof(srr->Blob)+srr->BlobLength);
//				SMB2Send(buf);
				}
				break;
			case SMB2_COM_WRITE:
				{
				SMB2_WRITEFILE *swf;
				SMB2_WRITE_RESPONSE *swr;
//				i=Receive(&myBuf,sizeof(SMB2_WRITEFILE));
				swf=(SMB2_WRITEFILE*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(swf->Size.size != 0x31)
					goto errore_size;
				if(memcmp(swf->FileGUID,SMB2Server.fileguid,16))
					goto errore_guid;

				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_WRITE,STATUS_OK,SMB2Server.sessionid,1,1);

				swr=(SMB2_WRITE_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				swr->Size.dynamicPart=1;		swr->Size.fixedPart=8;
				FSfseek(SMB2Server.file,swf->Offset,SEEK_SET);
        
        // fare loop che riceve e scrive...
        n=0;
        do {
          i=FSfwrite(swf->Blob,1,swf->Length,SMB2Server.file);		// 
          n+=i;
          } while(0   );
				swr->Count=swf->Length;
        swr->ChannelInfoLength=0;
        swr->ChannelInfoOffset=0;
        swr->Reserved=0;
        swr->RemainingBytes=    0;
				SMB2Server.fileoffset=FSftell(SMB2Server.file);

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_WRITE_RESPONSE));
				SMB2Send(myBuf);
				}
				break;
			case SMB2_COM_LOCK:
				break;
			case SMB2_COM_IOCTL:
				{
				SMB2_IOCTL *si;
				SMB2_IOCTL_RESPONSE *sir;
//				i=Receive(&myBuf,sizeof(SMB2_WRITEFILE));
				si=(SMB2_IOCTL*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(si->Size.size != 0x31)
					goto errore_size;

				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_IOCTL,STATUS_OK,SMB2Server.sessionid,1,1);

				sir=(SMB2_IOCTL_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				sir->Size.dynamicPart=1;		sir->Size.fixedPart=8;		// FINIRE!

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_IOCTL_RESPONSE));
				SMB2Send(myBuf);
				}
				break;
			case SMB2_COM_CANCEL:
				break;
			case SMB2_COM_KEEPALIVE:
				break;
			case SMB2_COM_FIND:
				{
				SMB2_FIND *sf;
				SMB2_FIND_RESPONSE *sfr;
				SMB2_FIND_RESPONSE_INFO1 *sfri1;
				SMB2_FIND_RESPONSE_INFO2 *sfri2;
				SMB2_FIND_RESPONSE_INFO3 *sfri3;
				SMB2_FIND_RESPONSE_INFO4 *sfri4;
				SMB2_FIND_RESPONSE_INFO5 *sfri5;
				SMB2_FIND_RESPONSE_INFO6 *sfri6;
				SearchRec finder;
//				char realPath[128];
        char mask[32];
				uint8_t *p;
				//uint8_t buf[512 /*65536*/];			// v. MaxTransactionSize cmq
				uint16_t bufsize;
				int8_t j;
				uint32_t flags;

//				i=Receive(&myBuf,sizeof(SMB2_FIND));
				sf=(SMB2_FIND*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(sf->Size.size != 0x21)
					goto errore_size;

				SMB2Server.msgcntR=sh->MessageID;
				flags=sh->Flags;		// se SMB2_FLAG_CHAINED è un comando identico a quello prima... v. FIND in certi casi tipo la DIR da dos...
				SMB2Server.msgcntS=SMB2Server.msgcntR;

        if(!SDcardOK) 
          goto no_disc;
        
				p=(uint8_t*)rxBuffer+sf->BlobOffset;
				uniDecode(p,sf->BlobLength,mask);

//				strcpy(realPath,SMB2Server.curtree);
//				strcat(realPath,SMB2Server.curdir);
//				strcat(realPath,"\\");
//				strcat(realPath,ASTERISKS);
//				strcat(p2,mask);
// non credo che accetti il path qua...
//				BOOL bWorking = FindFirst(realPath,ATTR_MASK,&finder) >= 0;
        
        FSchdir(ROOTDIR);
        FSchdir(SMB2Server.curtree);
        if(*SMB2Server.curdir)
          FSchdir(SMB2Server.curdir);

        for(j=0; j<2; j++) {
  				BOOL bWorking = FindFirst(ASTERISKS/*mask*/,ATTR_MASK,&finder) >= 0;
          n=0;
          bufsize=0;
          while(bWorking) {
            uint32_t ofs;

            sfri1=(SMB2_FIND_RESPONSE_INFO1*)((char*)myBuf);
            sfri2=(SMB2_FIND_RESPONSE_INFO2*)sfri1;
            sfri3=(SMB2_FIND_RESPONSE_INFO3*)sfri1;
            sfri4=(SMB2_FIND_RESPONSE_INFO4*)sfri1;
            sfri5=(SMB2_FIND_RESPONSE_INFO5*)sfri1;
            sfri6=(SMB2_FIND_RESPONSE_INFO6*)sfri1;

            switch(sf->InfoLevel) {
              case FileNamesInformation:
                uniEncode(finder.filename,(uint8_t*)sfri6->FileName);
                sfri6->FilenameLength=strlen(finder.filename)*2;
                break;
              case FileFullDirectoryInformation:
                uniEncode(finder.filename,(uint8_t*)sfri2->FileName);
                sfri2->FilenameLength=strlen(finder.filename)*2;
                break;
              case FileIdFullDirectoryInformation:
                uniEncode(finder.filename,(uint8_t*)sfri3->FileName);
                sfri3->Reserved=0;
                sfri3->FilenameLength=strlen(finder.filename)*2;
                break;
              case FileBothDirectoryInformation:
                uniEncode(finder.filename,(uint8_t*)sfri4->FileName);
                sfri4->Reserved=0;
                sfri4->FilenameLength=strlen(finder.filename)*2;
                break;
              case FileInformationClass_Reserved:
                break;
              default:
                uniEncode(finder.filename,(uint8_t*)sfri1->FileName);
                sfri1->FilenameLength=strlen(finder.filename)*2;
                break;
              }
            
            if(j==1) {
              switch(sf->InfoLevel) {
                case FileNamesInformation:
                  break;
                case FileInformationClass_Reserved:
                  break;
                default:
                  sfri1->Attrib=finder.attributes;
                  sfri1->EOFSize=finder.filesize;
                  sfri1->Size=(finder.filesize+511) & -512;
                  sfri1->CreationTime=PackedTimeToFiletime(finder.timestamp);
                  sfri1->WriteTime=PackedTimeToFiletime(finder.timestamp);
                  sfri1->ModifiedTime=PackedTimeToFiletime(finder.timestamp);
                  sfri1->AccessTime=PackedTimeToFiletime(finder.timestamp);
                  break;
                }
              switch(sf->InfoLevel) {
                case FileBothDirectoryInformation:
                case FileIdBothDirectoryInformation:
                case FileIdAllExtdBothDirectoryInformation:
                  uniEncode("",sfri4->ShortFileName);		// fare! 
                  sfri4->ShortNameLength=0;
                  break;
                case FileInformationClass_Reserved:
                  break;
                default:
                  break;
                }

              switch(sf->InfoLevel) {
                case FileFullDirectoryInformation:
                case FileIdFullDirectoryInformation:
                case FileBothDirectoryInformation:
                case FileIdBothDirectoryInformation:
                  sfri2->EASize=0;		// trovare
                  break;
                case FileInformationClass_Reserved:
                  break;
                default:
                  break;
                }
              switch(sf->InfoLevel) {
                case FileIdBothDirectoryInformation:
                  sfri5->Reserved2=0;
                case FileIdFullDirectoryInformation:
                  sfri3->Reserved=0;
                  //sfri3->FileID;
                  break;
                case FileIdExtdDirectoryInformation:
                  //sfri->reparsePoint
                  break;
                case FileId64ExtdDirectoryInformation:
                case FileId64ExtdBothDirectoryInformation:
    //							sfri->ID64;
                  break;
                case FileIdAllExtdDirectoryInformation:
                case FileIdAllExtdBothDirectoryInformation:
    //							sfri->ID128;
                  break;
                case FileInformationClass_Reserved:
                  break;
                }
              sfri1->FileIndex=n;
              }   // solo seconda passata
            
            switch(sf->InfoLevel) {
              case FileDirectoryInformation:
                ofs=sizeof(SMB2_FIND_RESPONSE_INFO1)-sizeof(sfri1->FileName)+sfri1->FilenameLength;
                i=STATUS_OK;
                break;
              case FileFullDirectoryInformation:
                ofs=sizeof(SMB2_FIND_RESPONSE_INFO2)-sizeof(sfri2->FileName)+sfri2->FilenameLength;
                i=STATUS_OK;
                break;
              case FileIdFullDirectoryInformation:
                ofs=sizeof(SMB2_FIND_RESPONSE_INFO3)-sizeof(sfri3->FileName)+sfri3->FilenameLength;
                i=STATUS_OK;
                break;
              case FileBothDirectoryInformation:
                ofs=sizeof(SMB2_FIND_RESPONSE_INFO4)-sizeof(sfri4->FileName)+sfri4->FilenameLength;
                i=STATUS_OK;
                break;
              case FileIdBothDirectoryInformation:
                ofs=sizeof(SMB2_FIND_RESPONSE_INFO5)-sizeof(sfri5->FileName)+sfri5->FilenameLength;
                i=STATUS_OK;
                break;
              case FileNamesInformation:
                ofs=sizeof(SMB2_FIND_RESPONSE_INFO6)-sizeof(sfri6->FileName)+sfri6->FilenameLength;
                i=STATUS_OK;
                break;
              case FileIdExtdDirectoryInformation:
              case FileId64ExtdDirectoryInformation:
              case FileId64ExtdBothDirectoryInformation:
              case FileIdAllExtdDirectoryInformation:
              case FileIdAllExtdBothDirectoryInformation:
              case FileInformationClass_Reserved:
                i=STATUS_INVALID_INFO_CLASS;
                bWorking=FALSE;		// direi :)
                break;
              }
            ofs = (ofs+7) & 0xfffffff8;		// pad 8 byte
            bufsize += ofs;
            
            bWorking = !FindNext(&finder);
            if(j==1) {
              sfri1->NextOffset=bWorking ? ofs : 0;
              switch(sf->InfoLevel) {
                case FileDirectoryInformation:
                  sendEx(TCPDataSocket2 /*SMB2Server.sock*/,myBuf,ofs);
                  break;
                case FileFullDirectoryInformation:
                  sendEx(TCPDataSocket2 /*SMB2Server.sock*/,myBuf,ofs);
                  break;
                case FileIdFullDirectoryInformation:
                  sendEx(TCPDataSocket2 /*SMB2Server.sock*/,myBuf,ofs);
                  break;
                case FileBothDirectoryInformation:
                  sendEx(TCPDataSocket2 /*SMB2Server.sock*/,myBuf,ofs);
                  break;
                case FileIdBothDirectoryInformation:
                  sendEx(TCPDataSocket2 /*SMB2Server.sock*/,myBuf,ofs);
                  break;
                case FileNamesInformation:
                  sendEx(TCPDataSocket2 /*SMB2Server.sock*/,myBuf,ofs);
                  break;
                case FileIdExtdDirectoryInformation:
                case FileId64ExtdDirectoryInformation:
                case FileId64ExtdBothDirectoryInformation:
                case FileIdAllExtdDirectoryInformation:
                case FileIdAllExtdBothDirectoryInformation:
                case FileInformationClass_Reserved:
                  break;
                }
              }

//            if(bufsize > sizeof(buf))
//              break;
            n++;
            }
          if(j==0) {
            *(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_FIND_RESPONSE)-sizeof(sfr->Blob)+bufsize);
            sh=(SMB2_HEADER*)((char*)myBuf+4);
            prepareSMB2header(sh,SMB2_COM_FIND,i,SMB2Server.sessionid,1,1);
            sfr=(SMB2_FIND_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
            sfr->Size.dynamicPart=1;		sfr->Size.fixedPart=4;
            sfr->BlobOffset=0x00000048;
            sfr->BlobLength=bufsize;
//                sfr->RemainingBytes=0;
//                sfr->Reserved=0;
//            SMB2Send(myBuf);
            sendEx(TCPDataSocket2 /*SMB2Server.sock*/,myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_FIND_RESPONSE)-sizeof(sfr->Blob));
            }
          sfri1->NextOffset=0;
          }
        FSchdir(ROOTDIR);

				if(flags & SMB2_FLAG_CHAINED) {		// verificare come e quando...
					sh=(SMB2_HEADER*)((char*)myBuf+4);
					prepareSMB2header(sh,SMB2_COM_FIND,STATUS_NO_MORE_FILES,SMB2Server.sessionid,1,1);
					sfr=(SMB2_FIND_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
					sfr->Size.dynamicPart=1;		sfr->Size.fixedPart=4;
					sfr->BlobOffset=0;
					sfr->BlobLength=0;

					*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_FIND_RESPONSE)-sizeof(sfr->Blob)+sfr->BlobLength);
					SMB2Send(myBuf);
					}
				}
				break;
			case SMB2_COM_NOTIFY:
				{
				}
				break;
			case SMB2_COM_GETINFO:
				{
				SMB2_GETINFO *sgi;
				SMB2_GETINFO_RESPONSE *sgr;
//				i=Receive(&myBuf,sizeof(SMB2_GETINFO ));
				sgi=(SMB2_GETINFO*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(sgi->Size.size != 0x29)
					goto errore_size;

				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);

				sgr=(SMB2_GETINFO_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));

				switch(sgi->Class) {
					struct FSstat fs;
					case SMB2_FILE_INFO:
    				FSstat(SMB2Server.curfile,&fs);
            switch(sgi->InfoLevel) {
              case SMB2_FILE_BASIC_INFO:		// verificare
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=sizeof(SMB2_FILEBASICINFO);
                sgr->BlobOffset=0x0048;
                {
                SMB2_FILEBASICINFO *sfbi=(SMB2_FILEBASICINFO*)((char*)myBuf+4+sgr->BlobOffset);
                sfbi->AccessTime=gettime(fs.st_atime);
                sfbi->Attrib=fs.st_mode;
                sfbi->FileSize=fs.st_size;
                sfbi->ModifiedTime=gettime(fs.st_mtime);
                sfbi->Unknown=0;
                sfbi->WriteTime=gettime(fs.st_mtime);
                }
                i=STATUS_OK;
                break;
              case SMB2_FILE_STANDARD_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=20;
                sgr->BlobLength=24;
                sgr->BlobOffset=0x0048;
                {
                SMB2_FILESTANDARDINFO *sfsi=(SMB2_FILESTANDARDINFO*)((char*)myBuf+4+sgr->BlobOffset);
                sfsi->AllocSize=fs.st_size;
                sfsi->EOFSize=fs.st_size;
                sfsi->LinkCount=0;
                sfsi->DeletePending=0;
                sfsi->IsDirectory=fs.st_mode & ATTR_DIRECTORY ? 1 : 0;
                sfsi->Unknown=0;
                }
                i=STATUS_OK;
                break;
              case SMB2_FILE_INTERNAL_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=8;
                sgr->BlobOffset=0x0048;
                *(uint64_t*)sgr->Blob=0;    // dir. index... fare
                i=STATUS_OK;
                break;
              case SMB2_FILE_EA_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=4;
                sgr->BlobOffset=0x0048;
                *(uint32_t*)sgr->Blob=0;    // EA
                i=STATUS_OK;
                break;
              case SMB2_FILE_ACCESS_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=4;
                sgr->BlobOffset=0x0048;
                *(uint32_t*)sgr->Blob=0x000f010ff;    // read/write/append/execute/delete ecc
                i=STATUS_OK;
                break;
              case SMB2_FILE_POSITION_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=4;
                sgr->BlobOffset=0x0048;
                *(uint32_t*)sgr->Blob=SMB2Server.fileoffset;
                i=STATUS_OK;
                break;
              case SMB2_FILE_INFO_0F:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=0;
                sgr->BlobOffset=0;
                // ci sarebbero stringhe per "EA"...
                i=STATUS_OK;
                break;
              case SMB2_FILE_MODE_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=4;
                sgr->BlobOffset=0x0048;
                *(uint32_t*)sgr->Blob=2;    // boh, ho visto un 2
                i=STATUS_OK;
                break;
              case SMB2_FILE_ALIGNMENT_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=4;
                sgr->BlobOffset=0x0048;
                *(uint32_t*)sgr->Blob=0;    // byte align
                i=STATUS_OK;
                break;
              case SMB2_FILE_ALL_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=100+strlen(SMB2Server.curdir)*2+strlen(SMB2Server.curtree)*2;
                sgr->BlobOffset=0x0048;
                // mettere TUTTE le info, v. ; incluso path completo del file
                i=STATUS_OK;
                break;
              case SMB2_FILE_ALTERNATE_NAME_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=4+12*2;   // credo sempre così
                sgr->BlobOffset=0x0048;
                *(uint32_t*)sgr->Blob=12*2;
                uniEncode(SMB2Server.curfile,(char*)sgr->Blob+4);	
                i=STATUS_OK;
                break;
              case SMB2_FILE_STREAM_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=0;
                sgr->BlobOffset=0;
                // boh
                i=STATUS_OK;
                break;
              case SMB2_FILE_COMPRESSION_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=16;
                sgr->BlobOffset=0x0048;
// uint64 size e poi tutto 0=non compresso
                i=STATUS_OK;
                break;
              case SMB2_FILE_NETWORK_OPEN_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=0;
                sgr->BlobOffset=0;
                {
                SMB2_NETWORKOPENINFO *snoi=(SMB2_NETWORKOPENINFO*)((char*)myBuf+4+sgr->BlobOffset);
                snoi->Attrib=fs.st_mode;
                snoi->EOFSize=fs.st_size;
                snoi->Size=(snoi->EOFSize+7) & 0xffffff8;    // bah pare
                snoi->AccessTime=gettime(fs.st_atime);
                snoi->CreationTime=gettime(fs.st_ctime);
                snoi->ModifiedTime=gettime(fs.st_mtime);
                snoi->WriteTime=gettime(fs.st_mtime);
                snoi->Reserved=0;
                }
                i=STATUS_OK;
                break;
              case SMB2_FILE_ATTRIBUTE_TAG_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=8;
                sgr->BlobOffset=0x0048;
                *(uint32_t*)sgr->Blob=fs.st_mode;
                *(uint32_t*)((char*)sgr->Blob+4)=0;   // reparse tag...
                i=STATUS_OK;
                break;
              default:
                i=STATUS_ILLEGAL_FUNCTION;
                break;
              }
						break;
					case SMB2_FS_INFO:
            switch(sgi->InfoLevel) {
              case SMB2_FS_VOLUME_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobOffset=0x0048;
                {
                SMB2_FILEVOLUMEINFO *sfvi=(SMB2_FILEVOLUMEINFO*)((char*)myBuf+4+sgr->BlobOffset);
                FILETIMEPACKED t /*={2026-1980,3,15,21,39,0}*/;
                char buf[16];
                FSgetVolume(buf,(uint32_t*)&t);
                uniEncode(buf /*"WIFI_PEN"*/,sfvi->Label);
                sfvi->LabelLength=2*strlen(buf);
                sfvi->CreateTime=PackedTimeToFiletime(t);
                sfvi->Reserved=0;
                sfvi->SerialNumber=MAKELONG(0/*VERNUML*/,1/*VERNUMH*/);
                sgr->BlobLength=18+sfvi->LabelLength;
                }
                i=STATUS_OK;
                break;
              case SMB2_FS_SIZE_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=0;
                sgr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FS_DEVICE_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=sizeof(SMB2_FSDEVICEINFO);
                sgr->BlobOffset=0x0048;
                {
                SMB2_FSDEVICEINFO *sfdi=(SMB2_FSDEVICEINFO*)((char*)myBuf+4+sgr->BlobOffset);
                sfdi->Type=7;   // disk
                if(SDcardOK)
                  sfdi->Attributes=0x00000020;    // mounted
                else
                  sfdi->Attributes=0;
                sfdi->Attributes |= 1;    // removable
                }
                i=STATUS_OK;
                break;
              case SMB2_FS_ATTRIBUTE_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=20;
                sgr->BlobOffset=0x0048;
                {
                SMB2_FSINFO *sfi=(SMB2_FSINFO*)((char*)myBuf+4+sgr->BlobOffset);
                uniEncode("FAT",sfi->Label);
                sfi->Attrib=0;		// case-sensitive, LFN, compression, quotas, OID, ACL, Encrypt...
                sfi->LabelLength=3*2;
                sfi->MaxLabelLength=3*2;
                sgr->BlobLength=12+sfi->LabelLength;
                }
                i=STATUS_OK;
                break;
              case SMB2_FS_QUOTA_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=sizeof(SMB2_FSQUOTAINFO);
                sgr->BlobOffset=0x0048;
                {
                SMB2_FSQUOTAINFO *sfi=(SMB2_FSQUOTAINFO *)((char*)myBuf+4+sgr->BlobOffset);
                // fare :)
                }
                i=STATUS_OK;
                break;
              case SMB2_FS_FULL_SIZE_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=sizeof(SMB2_FILEVOLUMESIZEINFO);
                sgr->BlobOffset=0x0048;
                {
                SMB2_FILEVOLUMESIZEINFO *sfvsi=(SMB2_FILEVOLUMESIZEINFO*)((char*)myBuf+4+sgr->BlobOffset);
                FS_DISK_PROPERTIES fsdp;
                fsdp.new_request=1;
                do {
                  FSGetDiskProperties(&fsdp);
                  } while(fsdp.properties_status == FS_GET_PROPERTIES_STILL_WORKING);
                if(fsdp.properties_status==FS_GET_PROPERTIES_NO_ERRORS) {
                  sfvsi->ActualFreeUnits=fsdp.results.free_clusters;		// o AllocSize??
                  sfvsi->CallerFreeUnits=fsdp.results.free_clusters;
                  sfvsi->CallerFreeUnits=fsdp.results.free_clusters;
                  sfvsi->SectorsSize=fsdp.results.sector_size;
                  sfvsi->SectorsPerUnit=fsdp.results.sectors_per_cluster;
                  }
                else
                  ;     // errore...
                sfvsi->AllocSize=1;
                }
                i=STATUS_OK;
                break;
              case SMB2_FS_OID_INFO:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
                sgr->BlobLength=64;
                sgr->BlobOffset=0x0048;
                {// ci sono 4 GUID
                }
                i=STATUS_OK;
                break;
              default:
                i=STATUS_ILLEGAL_FUNCTION;
                break;
    					}
						break;
					case SMB2_SEC_INFO:
            switch(sgi->InfoLevel) {
              case SMB2_SEC_INFO_00:
                sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=20;
                sgr->BlobLength=20;
                sgr->BlobOffset=0x0048;
                // NT security descriptor
                i=STATUS_OK;
                break;
              default:
                i=STATUS_ILLEGAL_FUNCTION;
                break;
              }
						break;
          default:
            i=STATUS_ILLEGAL_FUNCTION;
            break;
					}

				prepareSMB2header(sh,SMB2_COM_GETINFO,i,SMB2Server.sessionid,1,1);
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_GETINFO_RESPONSE)-sizeof(sgr->Blob)+sgr->BlobLength);
				SMB2Send(myBuf);
				}
				break;
			case SMB2_COM_SETINFO:
				{
				SMB2_SETINFO *ssi;
				SMB2_SETINFO_RESPONSE *ssr;
				char nometemp[64],nometemp2[64];
//				i=Receive(&myBuf,sizeof(SMB2_SETINFO));
				ssi=(SMB2_SETINFO*)((char*)rxBuffer+sizeof(SMB2_HEADER));
				if(ssi->Size.size != 0x21)
					goto errore_size;

				SMB2Server.msgcntR=sh->MessageID;
				SMB2Server.msgcntS=SMB2Server.msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);

				ssr=(SMB2_SETINFO_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));

				switch(ssi->Class) {
					case SMB2_FILE_INFO:
            FSchdir(ROOTDIR);
// serve per localizzare il file qua
            FSchdir(SMB2Server.curtree);
            if(*SMB2Server.curdir)
              FSchdir(SMB2Server.curdir);
//            strcpy(nometemp,SMB2Server.curtree);
//            strcat(nometemp,"\\");
//            strcat(nometemp,SMB2Server.curfile);
            switch(ssi->InfoLevel) {
              // verificare quelli che non ci sono! e finire
              case SMB2_FILE_BASIC_INFO:
								{
								SMB2_FILEBASICINFO *sfbi=(SMB2_FILEBASICINFO*)((char*)ssr+8+ssi->InfoOffset);
                {FSFILE *f;
                f=FSfopen(nometemp2,OPEN_READ,SHARE_NONE);
								i=FSattrib(f,sfbi->Attrib) ? STATUS_OK : STATUS_UNSUCCESSFUL;
                FSfclose(f);
                }
								i=FSstamp(nometemp,FiletimeToPackedTime(sfbi->WriteTime).v) ? STATUS_OK : STATUS_UNSUCCESSFUL;
								ssr->BlobLength=0;
								ssr->BlobOffset=0;
								ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
								}
                break;
              case SMB2_FILE_STANDARD_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=20;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FILE_EA_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FILE_ACCESS_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FILE_RENAME_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                {
                SMB2_FILERENAMEINFO *sfri=(SMB2_FILERENAMEINFO*)((char*)myBuf+4+ssi->InfoOffset);

                uniDecode((uint8_t*)sfri->Blob,sfri->FilenameLength,nometemp2);		//
                {FSFILE *f;
                f=FSfopen(nometemp,OPEN_READ,SHARE_NONE);
                i=FSrename(nometemp2,f) ? STATUS_OK : STATUS_OBJECT_NAME_NOT_FOUND;
                FSfclose(f);
                }
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                }
                break;
              case SMB2_FILE_DISPOSITION_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FILE_POSITION_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=20;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FILE_MODE_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=20;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FILE_ENDOFFILE_INFO:
                ssr->Size.dynamicPart=0;		ssr->Size.fixedPart=1;
                FSfseek(SMB2Server.file,(uint32_t)*(uint64_t*)((char*)myBuf+ssi->InfoOffset),SEEK_SET);		// mah verificare
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FILE_ALLOCATION_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FILE_NETWORK_OPEN_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              default:
                i=STATUS_ILLEGAL_FUNCTION;
                break;
              }
            FSchdir(ROOTDIR);
            FSchdir(SMB2Server.curtree);
						break;
					case SMB2_FS_INFO:
            switch(ssi->InfoLevel) {
              case SMB2_FS_VOLUME_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FS_SIZE_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FS_FULL_SIZE_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              case SMB2_FS_OID_INFO:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              default:
                i=STATUS_ILLEGAL_FUNCTION;
                break;
              }
						break;
					case SMB2_SEC_INFO:
            switch(ssi->InfoLevel) {
              case SMB2_SEC_INFO_00:
                ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=20;
                ssr->BlobLength=0;
                ssr->BlobOffset=0;
                i=STATUS_OK;
                break;
              default:
                i=STATUS_ILLEGAL_FUNCTION;
                break;
              }
						break;
          default:
            i=STATUS_ILLEGAL_FUNCTION;
            break;
					}

				prepareSMB2header(sh,SMB2_COM_SETINFO,i,SMB2Server.sessionid,1,1);
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_SETINFO_RESPONSE)-sizeof(ssr->Blob)+ssr->BlobLength);
				SMB2Send(myBuf);
				}
				break;
			case SMB2_COM_BREAK:
				break;
			}
		}
  return;
  
bad_protocol:
  {
  SMB2_HEADER *sh=(SMB2_HEADER*)((char*)myBuf+4);
	prepareSMB2header(sh,SMB2_COM_NEGOTIATE,STATUS_NOT_SUPPORTED,0,1,1);
  *(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER) );
  SMB2Send(myBuf  );
  close(TCPDataSocket2); TCPDataSocket2=INVALID_SOCKET;
  return;
  }
  
no_disc:
  {
  SMB2_HEADER *sh=(SMB2_HEADER*)((char*)myBuf+4);
	prepareSMB2header(sh,SMB2_COM_TREECONNECT,STATUS_OBJECT_NAME_NOT_FOUND /*STATUS_OBJECT_PATH_NOT_FOUND*/,SMB2Server.sessionid,1,1);
  *(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER) );
  SMB2Send(myBuf  );
  return;
  }
        
errore_sid:
errore_tid:
errore_pid:
errore_sig:
errore_size:
errore_guid:
		;

	}
//#pragma GCC pop_options

void OnClose() {

  SMB2Server.processid=0;
  SMB2Server.sessionid=0;
  SMB2Server.treeid=0;
  SMB2Server.msgcntS=SMB2Server.msgcntR=0;
  SMB2Server.sessionstate=0;
  if(SMB2Server.file) {
    FSfclose(SMB2Server.file);
    SMB2Server.file=NULL;
    }
  SMB2Server.fileoffset=0;
	memset(SMB2Server.signature,0,sizeof(SMB2Server.signature));
  
  setStatusLed(LED_NORMALE_CONNESSO_WIFI);

	}



SMB2_HEADER *prepareSMB2header(SMB2_HEADER *sh,uint32_t command,uint32_t status,uint32_t session,
																								uint8_t ccharge,uint16_t crequest) {

	sh->Protocol[0]=0xFE;
	sh->Protocol[1]='S';
	sh->Protocol[2]='M';
	sh->Protocol[3]='B';
	sh->Size=64;
	sh->CreditCharge=ccharge;
	sh->Status=status;
	sh->Command=command;			// 
	sh->CreditsRequested=crequest;
	sh->Flags=SMB2_FLAG_RESPONSE;
	sh->ChainOffset=0;
	sh->MessageID=SMB2Server.msgcntS;
	sh->ProcessID=SMB2Server.processid;
	sh->TreeID=SMB2Server.treeid;
	sh->SessionID=session;
	memcpy(sh->Signature,&SMB2Server.signature,sizeof(sh->Signature));

	return sh;
	}


   // https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedotherprotocol4b.html
   // https://github.com/alezhu/delphi-FreeTalk/blob/master/nb30.pas
   // https://svn.nmap.org/nmap-releases/nmap-7.99/nselib/netbios.lua
   // https://cultdeadcow.bnbn.it/tools/nbname.html
        
enum {
  // NCB Command codes
  NCBCALL         = 0x10,            // NCB CALL
  NCBLISTEN       = 0x11,            // NCB LISTEN
  NCBHANGUP       = 0x12,            // NCB HANG UP
  NCBSEND         = 0x14,            // NCB SEND
  NCBRECV         = 0x15,            // NCB RECEIVE
  NCBRECVANY      = 0x16,            // NCB RECEIVE ANY
  NCBCHAINSEND    = 0x17,            // NCB CHAIN SEND
  NCBDGSEND       = 0x20,            // NCB SEND DATAGRAM
  NCBDGRECV       = 0x21,            // NCB RECEIVE DATAGRAM
  NCBDGSENDBC     = 0x22,            // NCB SEND BROADCAST DATAGRAM
  NCBDGRECVBC     = 0x23,            // NCB RECEIVE BROADCAST DATAGRAM
  NCBADDNAME      = 0x30,            // NCB ADD NAME
  NCBDELNAME      = 0x31,            // NCB DELETE NAME
  NCBRESET        = 0x32,            // NCB RESET
  NCBASTAT        = 0x33,            // NCB ADAPTER STATUS
  NCBSSTAT        = 0x34,            // NCB SESSION STATUS
  NCBCANCEL       = 0x35,            // NCB CANCEL
  NCBADDGRNAME    = 0x36,            // NCB ADD GROUP NAME
  NCBENUM         = 0x37,            // NCB ENUMERATE LANA NUMBERS
  NCBUNLINK       = 0x70,            // NCB UNLINK
  NCBSENDNA       = 0x71,            // NCB SEND NO ACK
  NCBCHAINSENDNA  = 0x72,            // NCB CHAIN SEND NO ACK
  NCBLANSTALERT   = 0x73,            // NCB LAN STATUS ALERT
  NCBACTION       = 0x77,            // NCB ACTION
  NCBFINDNAME     = 0x78,            // NCB FIND NAME
  NCBTRACE        = 0x79,            // NCB TRACE

  ASYNCH          = 0x80,            // high bit set = asynchronous

  // NCB Return codes
  NRC_GOODRET     = 0x00,    // good return
                            // also returned when ASYNCH request accepted
  NRC_BUFLEN      = 0x01,    // illegal buffer length
  NRC_ILLCMD      = 0x03,    // illegal command
  NRC_CMDTMO      = 0x05,    // command timed out
  NRC_INCOMP      = 0x06,    // message incomplete, issue another command
  NRC_BADDR       = 0x07,    // illegal buffer address
  NRC_SNUMOUT     = 0x08,    // session number out of range
  NRC_NORES       = 0x09,    // no resource available
  NRC_SCLOSED     = 0x0a,    // session closed
  NRC_CMDCAN      = 0x0b,    // command cancelled
  NRC_DUPNAME     = 0x0d,    // duplicate name
  NRC_NAMTFUL     = 0x0e,    // name table full
  NRC_ACTSES      = 0x0f,    // no deletions, name has active sessions
  NRC_LOCTFUL     = 0x11,    // local session table full
  NRC_REMTFUL     = 0x12,    // remote session table full
  NRC_ILLNN       = 0x13,    // illegal name number
  NRC_NOCALL      = 0x14,    // no callname
  NRC_NOWILD      = 0x15,    // cannot put * in NCB_NAME
  NRC_INUSE       = 0x16,    // name in use on remote adapter
  NRC_NAMERR      = 0x17,    // name deleted
  NRC_SABORT      = 0x18,    // session ended abnormally
  NRC_NAMCONF     = 0x19,    // name conflict detected
  NRC_IFBUSY      = 0x21,    // interface busy, IRET before retrying
  NRC_TOOMANY     = 0x22,    // too many commands outstanding, retry later
  NRC_BRIDGE      = 0x23,    // NCB_lana_num field invalid
  NRC_CANOCCR     = 0x24,    // command completed while cancel occurring
  NRC_CANCEL      = 0x26,    // command not valid to cancel
  NRC_DUPENV      = 0x30,    // name defined by anther local process
  NRC_ENVNOTDEF   = 0x34,    // environment undefined. RESET required
  NRC_OSRESNOTAV  = 0x35,    // required OS resources exhausted
  NRC_MAXAPPS     = 0x36,    // max number of applications exceeded
  NRC_NOSAPS      = 0x37,    // no saps available for netbios
  NRC_NORESOURCES = 0x38,    // requested resources are not available
  NRC_INVADDRESS  = 0x39,    // invalid ncb address or length > segment
  NRC_INVDDID     = 0x3B,    // invalid NCB DDID
  NRC_LOCKFAIL    = 0x3C,    // lock of user area failed
  NRC_OPENERR     = 0x3f,    // NETBIOS not loaded
  NRC_SYSTEM      = 0x40,    // system error

  NRC_PENDING     = 0xff    // asynchronous command is not yet finished
  };    
 
#define NCBNAMSZ 16
#define LANANUM     3
  
typedef struct __attribute__((__packed__)) _NCB {
  USHORT tid;   // 0x9385
  union __attribute__((__packed__)) {
    struct __attribute__((__packed__)) {
      uint8_t unused:4;
      uint8_t broadcast:1;
      uint8_t unused2:3;
      uint8_t recursion:1;
      uint8_t truncated:1;
      uint8_t unused3:1;
      uint8_t opcode:4;
      uint8_t response:1;   // invertire v.sotto
      } flags;
    uint16_t v;
    };
  USHORT questions;
  USHORT answerRRs;
  USHORT authorityRRs;
  USHORT additionalRRs;
  struct __attribute__((__packed__)) {
    UCHAR  name[34];
    uint16_t type;
    uint16_t class;
    } queries;
  struct __attribute__((__packed__)) {
    UCHAR boh;
    UCHAR name;
    USHORT type;
    USHORT class;
    uint32_t ttl;
    USHORT length;
    USHORT flags;
    uint32_t address;
    } additionalRecords;
  } NCB, *PNCB;


BOOL advertizeNetbiosName(const char *n) {
  NCB ncb;
  int i;
  struct sockaddr_in strAddr;
  
  memset(&ncb, 0, sizeof(ncb));
  ncb.tid=htons(1);   // rand() ?
  ncb.flags.broadcast=1;
  ncb.flags.recursion=0;  // 1 per query
  ncb.flags.truncated=0;
  ncb.flags.opcode=5;   // 5=registration   0=name query
  ncb.flags.response=0;
  i=ncb.v;
  ncb.v=htons(i);
  ncb.questions=htons(1);
  ncb.answerRRs=htons(0);
  ncb.additionalRRs=htons(1);   // 0 se query
  nbEncode("WiFi_Pen",ncb.queries.name,FALSE);
  ncb.queries.type=htons(32);   // NB
  ncb.queries.class=htons(1);   // IN
  ncb.additionalRecords.boh=0xc0;
  ncb.additionalRecords.name=0x0c;   // boh...
  ncb.additionalRecords.type=htons(32);   // NB
  ncb.additionalRecords.class=htons(1);   // IN
  ncb.additionalRecords.length=htons(6);
  ncb.additionalRecords.flags=0;
  ncb.additionalRecords.ttl=htonl(0xe0930400);   // 3 giorni 11 ore 20 minuti
  ncb.additionalRecords.address=myIp.ip;

// ovviamente sbagliato, quella usa una funzione "netbios()"  trovare e fare
  
/*  i = strlen(n);
  if(i > NCBNAMSZ)
    i = NCBNAMSZ;
  // Solving the trailing-space in 16-bytes storage if any
  // Firstly set all to ' ' char
  memset(&ncb.ncb_name,' ',NCBNAMSZ);
  // Then copy the string, leaving the ' ' chars
  memcpy(&ncb.ncb_name,n,i);*/

	UDPclientSocket = socket(AF_INET,SOCK_DGRAM,0);
  if(UDPclientSocket >= 0) {
    strAddr.sin_family = AF_INET;
    strAddr.sin_port = htons(137);
    strAddr.sin_addr.s_addr = INADDR_BROADCAST;
    sendto(UDPclientSocket,&ncb,110 /*sizeof(ncb)*/,0,(struct sockaddr*)&strAddr,sizeof(strAddr));
    M2M_WAIT();
    close(UDPclientSocket);
    UDPclientSocket=INVALID_SOCKET;
    }
  
/*  Netbios (&ncb);
  NBCheck (ncb);
*/
//  return (NRC_GOODRET == ncb.ncb_retcode);
  }
