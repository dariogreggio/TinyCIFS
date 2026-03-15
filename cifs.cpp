#include "stdafx.h"
#include "testsocket.h"
#include <stdint.h>
#include <mmsystem.h>		//rompe il cazzo
#include <direct.h>

//uint32_t timeGetTime();


#include "cifs.h"
	
//https://amitschendel1.medium.com/smb-going-from-zero-to-hero-ff686e907e81

//https://www.wireshark.org/docs/wsar_html/packet-smb2_8h_source.html
//  per definizioni struct costanti ecc di SMB2


CCIFSCliSocket::CCIFSCliSocket(uint8_t ver,uint8_t m,uint8_t sec) : version(ver),mode(m),security(sec) {

	isConnected=FALSE;
	msgcnt=0;
	processid=rand();			// sarebbe long ma ok
	sessionid=0;
	treeid=0;
	dialect=0;
	fileoffset=0;
	ZeroMemory(fileguid,16);
	ZeroMemory(dirguid,16);
//CTime t=FiletimeToTime(0x01dca64a8c8b61ff);
// 25/2/2026 11:33:23 .000780700		test
//	CString S=t.Format("%d/%m/%Y %H:%M:%S");
	}

CCIFSCliSocket::~CCIFSCliSocket() {

	}

BOOL CCIFSCliSocket::Connect(LPCTSTR s) {

	if(CSocket::Create()) {
		return CSocket::Connect(s,7700 /*mode ? 445 : 139*/);
		}
	int i=GetLastError();
	return FALSE;
	}

BOOL CCIFSCliSocket::Disconnect() {

	CSocket::Close();
	return TRUE;
	}

int CCIFSCliSocket::Send(const void *p,uint16_t n) {
//	SMB1_HEADER sh;

	return CSocket::Send(p,n);
	}

int CCIFSCliSocket::readResponseNBSS(uint8_t *buf,DWORD len,WORD timeout) {
	int i,n,n2,retVal=0;
	DWORD ti,lenR=0;
	uint8_t *myBuf,myBuf2[16],*p;

	n=0;
	myBuf=(uint8_t*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS,2048);
	if(!myBuf)
		return -1;

	ti=timeGetTime()+timeout;
	while(ti>timeGetTime()) {
		i=CAsyncSocket::Receive(myBuf2,1);		// 
		if(i<0) {
			i=GetLastError();
			if(i != WSAEWOULDBLOCK)
				break;
			}
		else {
			if((n+i) >= 2048) {
				break;
				}
			else {
				memcpy(myBuf+n,myBuf2,i);
				n+=i;
				if(n>=len) {
					retVal=myBuf[0] == NBSS_POSITIVE_SESSION_RESPONSE;			//
					break;
					}
				}
			}
		}
	if(buf) {
		i=min(len,n);
		memcpy(buf,myBuf,i);
		}

	HeapFree(GetProcessHeap(),0,myBuf);

	return retVal;
	}

int CCIFSCliSocket::readResponseSMB2(uint8_t *buf,DWORD len,WORD timeout) {		// len NON è la dim pacch atteso ma la dim del buffer passato! v. le varie call
	int i,n,n2,retVal=0;
	DWORD ti,lenR=0;
	uint8_t *myBuf,myBuf2[16],*p;
	SMB2_HEADER *sh;

	n=0;
	myBuf=(uint8_t*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS,65535);
	if(!myBuf)
		return -1;

	ti=timeGetTime()+timeout;
	while(ti>timeGetTime()) {
		i=CAsyncSocket::Receive(myBuf2,1);		// 
		if(i<0) {
			i=GetLastError();
			if(i != WSAEWOULDBLOCK)
				break;
			}
		else {
			if((n+i) >= 65535) {
				break;
				}
			else {
				memcpy(myBuf+n,myBuf2,i);
				n+=i;
				if(!lenR) {
					if(n>=4)
						lenR=MAKELONG(MAKEWORD(myBuf[3],myBuf[2]),myBuf[1]);
					//myBuf[0] è 0 se OK/Response o errore (0x83=Negative Session Response)
					}
				if(lenR && n>=lenR+4) {
					sh=(SMB2_HEADER*)&myBuf[4];
					retVal=sh->Status == STATUS_OK;
					break;
					}
				}
			}
		}
	if(buf) {
		i=min(len,n);
		memcpy(buf,myBuf+4,i);
		}

	HeapFree(GetProcessHeap(),0,myBuf);

	return retVal;
	}

int CCIFSCliSocket::readData(uint8_t *buf,DWORD len,WORD timeout) {
	int i,n,n2,retVal=-1;
	DWORD ti,lenR=0;
	uint8_t *myBuf,myBuf2[16],*p;

	n=0;
	myBuf=(uint8_t*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS,65535);
	if(!myBuf)
		return -1;

	ti=timeGetTime()+timeout;
	while(ti>timeGetTime()) {
		i=CAsyncSocket::Receive(myBuf2,1);		// 
		if(i<0) {
			i=GetLastError();
			if(i != WSAEWOULDBLOCK)
				break;
			}
		else {
			if((n+i) >= 65535) {
				break;
				}
			else {
				memcpy(myBuf+n,myBuf2,i);
				n+=i;
				if(n>=len) {
					retVal=1;			//
					break;
					}
				}
			}
		}
	if(buf) {
		i=min(len,n);
		memcpy(buf,myBuf,i);
		}

	HeapFree(GetProcessHeap(),0,myBuf);

	return retVal;
	}

uint8_t *CCIFSCliSocket::prepareSMBcode(uint8_t *buf,uint8_t cmd,uint32_t len) {

	buf[0]=cmd;
	buf[1]=LOBYTE(HIWORD(len));
	buf[2]=HIBYTE(LOWORD(len));
	buf[3]=LOBYTE(LOWORD(len));
	return buf;
	}

SMB2_HEADER *CCIFSCliSocket::prepareSMB2header(SMB2_HEADER *sh,uint16_t cmd,uint8_t ccharge,uint16_t crequest) {

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
	sh->MessageID=msgcnt++;
	sh->ProcessID=processid;
	sh->TreeID=treeid;
	sh->SessionID=sessionid;
	ZeroMemory(sh->Signature,sizeof(sh->Signature));
	return sh;
	}


int CCIFSCliSocket::OpenSession(LPCTSTR s,LPCTSTR user,LPCTSTR pasw) {
	uint8_t buf[1024],buf2[256];
	int i,len;
	NBSS_HEADER nbsh;

	isConnected=Connect(s);

	if(isConnected) {
		if(version==1) {
			SMB1_HEADER sh;
			sh.Protocol[0]=0xFF;
			sh.Protocol[1]='S';
			sh.Protocol[2]='M';
			sh.Protocol[3]='B';
			sh.Command=SMB_COM_NEGOTIATE;
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);		// verificare
			memcpy(buf+4,&sh,len);
			Send(&buf,len+4);

			sh.Protocol[0]=0xFF;
			sh.Protocol[1]='S';
			sh.Protocol[2]='M';
			sh.Protocol[3]='B';
			sh.Command=SMB_COM_OPEN_ANDX;		// FINIRE!
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);		// verificare
			memcpy(buf+4,&sh,len);
			Send(&buf,len+4);
			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_NEGOTIATE_PROTOCOL *snp;
			SMB2_NEGOTIATE_RESPONSE *snr;
			SMB2_OPEN_SESSION *sos;

			if(!mode) {
				nbsh.Type=NBSS_SESSION_REQUEST;
				nbsh.Flags=0;
				len=32+1+1+32+1+1;
				nbsh.Length=MAKEWORD(HIBYTE(len),LOBYTE(len));
				memcpy(buf,&nbsh,4);
				memcpy(buf+4,nbEncode("SKYNET",(char*)buf2,TRUE),32+1+1);
				memcpy(buf+4+32+1+1,nbEncode("FROCIO",(char*)buf2,FALSE),32+1+1);
				Send(&buf,len+4);
				readResponseNBSS(buf,4);
				}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_NEGOTIATE,1,31);
			snp=(SMB2_NEGOTIATE_PROTOCOL*)(buf+sizeof(SMB2_HEADER)+4);
			snp->Size.size=0x24;
			snp->DialectCount=2;
			snp->Security=security;
			snp->Reserved=0;
			snp->Capabilities=0;
			ZeroMemory(snp->ClientGUID,sizeof(snp->ClientGUID));
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
//			memcpy(buf+4,&sh,sh.Size);
//			memcpy(buf+4+sh.Size,&snp,(snp->Size.size & 0xfffe)+2+2);		// i dialect sono a parte dalla Size...
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 170
				goto fatto_errore;
			snr=(SMB2_NEGOTIATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
					// qua dentro c'è il security Blob!  e in NegotiateContextoffset c'è "LMSS"

			dialect=snr->Dialect;


			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_OPENSESSION,1,31);
			sos=(SMB2_OPEN_SESSION*)(buf+sizeof(SMB2_HEADER)+4);
			sos->Size.size=0x19;
			sos->Flags=0;
			sos->Security=security;
			sos->Capabilities=1;
			sos->Channel=0;
			sos->PrevSessionID=0;
			if(security) {
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
				ZeroMemory(&nti.versionUnused,sizeof(nti.versionUnused));
				nti.versionNTLMrev=NTLMSSP_REVISION_W2K3;
				memcpy(sos->SecurityBlob,&nti,sizeof(NEG_TOKEN_INIT));

	//https://curl.se/rfc/ntlm.html
				//https://jcifs.samba.org/ non va, froci del cazzo
				//https://github.com/nmap/ncrack/blob/master/ntlmssp.cc
//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
				//https://blog.smallsec.ca/ntlm-challenge-response/
				}
			else {
				sos->BlobOffset=0;
				sos->BlobLength=0;
				sos->Size.size &= 0xfffe;
				}

			len=sh->Size+(sos->Size.size & 0xfffe)+sos->BlobLength;
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			i=readResponseSMB2(buf,1024);		// 105 +sizeof(NEG_TOKEN_TARG)+   8
			rsh=(SMB2_HEADER*)buf;
			if(i)
				goto fatto;
			if(rsh->Status != STATUS_MORE_PROCESSING_REQUIRED)
				goto fatto_errore;
			if(!security)		// beh sì :)
				goto fatto_errore;
			sessionid=rsh->SessionID;
			{NEG_TOKEN_TARG *ntlm=(NEG_TOKEN_TARG*)(buf+sizeof(SMB2_HEADER)+   0);

			SMB2_OPENSESSION_RESPONSE;		// usare

			// a 37h c'è la challenge-key, 8 byte
			// a 1Fh c'è NTLMSSP e poi 4 byte tipo, 00000002=NTLM_CHALLENGE
//			i=*ntlm->challenge;
			}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_OPENSESSION,1,1);
			sos=(SMB2_OPEN_SESSION*)(buf+sizeof(SMB2_HEADER)+4);
			sos->Size.size=0x19;
			sos->Flags=0;
			sos->Security=security;
			sos->Capabilities=1;
			sos->Channel=0;
			sos->PrevSessionID=0;
			if(security) {
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
				ntt.lenHostname=6*2;		// 6*2;		// pc_pic
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
				ZeroMemory(&ntt.versionUnused,sizeof(ntt.versionUnused));
				ntt.versionNTLMrev=NTLMSSP_REVISION_W2K3;
//				memcpy(ntt.MIC,"\xaf\x66\xa8\x5e\xd3\xa9\xbe\xc7\x61\x19\x99\x90\x87\xd5\x01\xc2",16);
				for(i=0; i<16; i++)
					ntt.MIC[i]=rand();
				// da qualche parte dice che è "Machine Identifier" generato casualmente
				uniEncode("PC_PIC",ntt.hostname);
//				uniEncode("GREGGIOD",ntt.hostname);
//				uniEncode("GUEST",ntt.username);
				ntt.lmresponse=security<2 ? 1 : 0;			// se metto 0 vuole auth key, altrimenti mi dà ok...

          // [MS-SMB2] 3.2.5.3.1 If the SMB2_SESSION_FLAG_IS_GUEST bit is set in the SessionFlags field of the SMB2
          // SESSION_SETUP Response and if RequireMessageSigning is FALSE, Session.SigningRequired MUST be set to FALSE.


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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 105 o 85 se non NTLMSSP
				goto fatto_errore;
			{SMB2_OPENSESSION_RESPONSE *sor=(SMB2_OPENSESSION_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);
			sor->Flags;
			NEG_TOKEN_TARG3 *ntlm=(NEG_TOKEN_TARG3*)(buf+ sor->BlobOffset+  0);

			if(security>1) {
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
		}

fatto:
	return 1;

fatto_errore:
	return 0;
	}

int CCIFSCliSocket::OpenShare(LPCTSTR s) {
	uint8_t buf[1024],buf2[256];
	int i,len;
	char *p;

	if(isConnected) {
		if(version==1) {

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

				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_TREECONNECT,1,1);
				stc=(SMB2_TREE_CONNECT*)(buf+sizeof(SMB2_HEADER)+4);
				stc->Size.size=0x9;
				stc->Flags=0;
				stc->BlobOffset=0x48;
				{char *s="\\\\SKYNET\\IPC$";			// sembra servire sempre
				stc->BlobLength=strlen(s)*2;		// Unicode;
				uniEncode(s,stc->Blob);
				}

				len=sh->Size+(stc->Size.size & 0xfffe)+stc->BlobLength;
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024))		// 105
					;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;
				treeid=rsh->TreeID;


				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
				scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
				scf->BlobFilenameLength=12;
				scf->BlobOffset=0;
				scf->BlobLength=0;
				{char *s="srvsvc";
				scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
				uniEncode(s,scf->Blob);
				}

				len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024))		// 152
					;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;
				{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
				memcpy(fileguid,scr->FileGUID,16);		// FINIRE!
				}

				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_GETINFO,1,1);
				sgi=(SMB2_GETINFO*)(buf+sizeof(SMB2_HEADER)+4);
				sgi->Size.size=0x29;
				sgi->Class=SMB2_FS_FILE_INFO;
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
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024))		// 96
					;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;


				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_WRITE,1,1);		// ossia DCERPC
				swf=(SMB2_WRITEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024))		// 80
					;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;


				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_READ,1,1);
				srf=(SMB2_READFILE*)(buf+sizeof(SMB2_HEADER)+4);
				srf->Size.size=0x31;
				srf->Padding=0x50;
				srf->Flags=0;
				srf->Length=1024;
				srf->Offset=0;
//				memcpy(srf->FileGUID,"\xf9\x00\x00\x00\x70\x00\x00\x00\xa9\x00\x30\x00\xff\xff\xff\xff",16);
				memcpy(srf->FileGUID,fileguid,16);
				srf->MinCount=0;
				srf->Channel=0;
				srf->RemainingBytes=0;
				srf->BlobOffset=0;
				srf->BlobLength=0;

				len=sh->Size+(srf->Size.size & 0xfffe)+srf->BlobLength;
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024))		// 196
					;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;


				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_WRITE,1,1);		// ossia NetShareEnumAll
				swf=(SMB2_WRITEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024))		// 80
					;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;

				
				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_READ,1,1);
				srf=(SMB2_READFILE*)(buf+sizeof(SMB2_HEADER)+4);
				srf->Size.size=0x31;
				srf->Padding=0x50;
				srf->Flags=0;
				srf->Length=1024;
				srf->Offset=0;
//				memcpy(srf->FileGUID,"\xf9\x00\x00\x00\x70\x00\x00\x00\xa9\x00\x30\x00\xff\xff\xff\xff",16);
				memcpy(srf->FileGUID,fileguid,16);
				srf->MinCount=0;
				srf->Channel=0;
				srf->RemainingBytes=0;
				srf->BlobOffset=0;
				srf->BlobLength=0;

				len=sh->Size+(srf->Size.size & 0xfffe)+srf->BlobLength;
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024))		// 196
					;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;


				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_CLOSE,1,1);
				sclf=(SMB2_CLOSEFILE*)(buf+sizeof(SMB2_HEADER)+4);
				sclf->Size.size=0x18;
				sclf->Flags=0;
//				memcpy(sclf->FileGUID,"\xf9\x00\x00\x00\x70\x00\x00\x00\xa9\x00\x30\x00\xff\xff\xff\xff",16);
				memcpy(sclf->FileGUID,fileguid,16);

				len=sh->Size+(sclf->Size.size & 0xfffe);
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024))		// 120
					;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;


				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_IOCTL,1,1);
				si=(SMB2_IOCTL*)(buf+sizeof(SMB2_HEADER)+4);
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
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024))		// 54
					;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;

				ZeroMemory(fileguid,16);
				ZeroMemory(dirguid,16);
				}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_TREECONNECT,1,1);
			stc=(SMB2_TREE_CONNECT*)(buf+sizeof(SMB2_HEADER)+4);
			stc->Size.size=0x9;
			stc->Flags=0;
			stc->BlobOffset=0x48;
			stc->BlobLength=strlen(s)*2;		// Unicode;
			uniEncode(s,stc->Blob);

			len=sh->Size+(stc->Size.size & 0xfffe)+stc->BlobLength;
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(readResponseSMB2(buf,1024)) {		// 105
				rsh=(SMB2_HEADER*)buf;
				treeid=rsh->TreeID;

				return 1;
				}

			}

		}

	return 0;
	}

int CCIFSCliSocket::FindFirst(LPCTSTR s) {
	uint8_t buf[2048],buf2[256];
	int i,len;
	char *p;
	CString Dir;
	int files=0;

	if(isConnected) {
		if(version==1) {

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

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 152
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// FINIRE!
			}



			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_FIND,1,1);
			sh->Flags;		// v. SMB2_FLAG_CHAINED   FIND in certi casi tipo la DIR da dos...

			sf=(SMB2_FIND*)(buf+sizeof(SMB2_HEADER)+4);
			sf->Size.size=0x21;
			sf->InfoLevel=FileBothDirectoryInformation  /*FileIdBothDirectoryInformation*/;		// 

			sf->FindFlags=0;
			sf->FileIndex=0;
			memcpy(sf->FileGUID,guid,16);
			sf->OutputBufferLength=4000 /*65536*/;
			sf->BlobOffset=0x00000060;
			sf->BlobLength=2;		// Unicode;
			uniEncode("*",sf->Blob);

			len=sh->Size+(sf->Size.size & 0xfffe)+sf->BlobLength;
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,2000))		// 1000
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_FIND_RESPONSE *sfr=(SMB2_FIND_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);
			SMB2_FIND_RESPONSE_INFO4 *sfri=(SMB2_FIND_RESPONSE_INFO4*)(buf+sizeof(SMB2_HEADER)+   8);		// ossia SMB2_FIND_RESPONSE
			do {			// il "." c'è sempre, anche se la Dir è vuota
					if(sfri->ShortNameLength) {
//						unidecode(sfri->ShortFileName);
						}
					else {
//						unidecode(sfri->FileName);
						}
					Dir+=sfri->FileName;
				files++;
				if(!sfri->NextOffset)
					break;
				sfri=(SMB2_FIND_RESPONSE_INFO4*)(((char*)sfri)+sfri->NextOffset);
				if((((uint8_t*)sfri)-buf)>=2000)		// patch per buffer piccolo!
					break;
				} while(1);
			{
				CString S;
				S.Format(" :%u",files);
AfxMessageBox(Dir+S);
			}
			}


			if(0) {		// SOLO se ho chiesto CHAINED sopra
				readResponseSMB2(buf,1024);		// 152
				if(rsh->Status != STATUS_NO_MORE_FILES)
					goto errore;
				}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)(buf+sizeof(SMB2_HEADER)+4);
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,guid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 120
				goto errore;
			rsh=(SMB2_HEADER*)buf;

			return 1;
			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::FindNext() {
	SMB2_FIND_RESPONSE_INFO4 *sfri;

	return 0;
	}

int CCIFSCliSocket::CloseShare() {
	uint8_t buf[1024],buf2[256];
	int i,len;

	if(isConnected) {
		if(version==1) {
			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_TREE_DISCONNECT *std;

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_TREEDISCONNECT,1,1);
			std=(SMB2_TREE_DISCONNECT*)(buf+sizeof(SMB2_HEADER)+4);
			std->Size.size=0x4;
			std->Flags=0;
			len=4+sh->Size+(std->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(readResponseSMB2(buf,1024))		// 68
				;
			rsh=(SMB2_HEADER*)buf;

			SMB2_TREEDISCONNECT_RESPONSE;
			}
		treeid=0;
		}

	return 0;
	}

int CCIFSCliSocket::ChDir(LPCTSTR s) {
	uint8_t buf[1024],buf2[256];
	int i,len;
	char *p;


//	no! usare dirguid, passare handle alla dir aperta quando si fanno le operazioni sui file
//		ergo qua salvare in dirguid la dir corrente

	if(isConnected) {
		if(version==1) {

			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_TREE_CONNECT *stc;
			SMB2_CREATEFILE *scf;
			SMB2_CLOSEFILE *sclf;
			uint8_t fileguid[16];


			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 152
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
			memcpy(dirguid,scr->FileGUID,16);		// FINIRE!
			}



			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)(buf+sizeof(SMB2_HEADER)+4);
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,dirguid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(readResponseSMB2(buf,1024))		// 120
				;		// se ok/completo
			rsh=(SMB2_HEADER*)buf;


			return 1;
			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::MkDir(LPCTSTR s) {
	uint8_t buf[1024];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;

	if(isConnected) {
		if(version==1) {
			}
		else {
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(readResponseSMB2(buf,1024)) {		// 152
				
				rsh=(SMB2_HEADER*)buf;
				{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
//				memcpy(fileguid,scr->FileGUID,16);		// FINIRE!
				}
				return 1;
				}

			}
		}

	return 0;
	}

int CCIFSCliSocket::RmDir(LPCTSTR s) {
	uint8_t buf[1024];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;
	SMB2_SETINFO *si;
	SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];

	if(isConnected) {
		if(version==1) {
			}
		else {
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 152
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// 
			}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_SETINFO,1,1);
			si=(SMB2_SETINFO*)(buf+sizeof(SMB2_HEADER)+4);
			si->Size.size=0x21;
			si->Class=SMB2_FS_FILE_INFO;
			si->InfoLevel=SMB2_FILE_DISPOSITION_INFO;
			si->InfoSize=1;
			si->InfoOffset=0x0060;
			si->Reserved=0;
			si->AdditionalInfo=0;
			memcpy(si->FileGUID,guid,16);
			si->Blob[0]=1;

			len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 196
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

			}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)(buf+sizeof(SMB2_HEADER)+4);
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,guid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 120
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CLOSE_RESPONSE *scr=(SMB2_CLOSE_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

			}

			return 1;
			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::OpenFile(LPCTSTR s,uint8_t mode,uint8_t share) {
	uint8_t buf[1024];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;

	fileoffset=0;

	if(isConnected) {
		if(version==1) {
			}
		else {
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CREATE,1,320);
			scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
			scf->Size.size=0x39;
			scf->SecurityFlags=0;
			scf->Oplock=SMB2_OPLOCK_LEVEL_LEASE;
			scf->Impersonation=2;
			scf->Flags=0;
			scf->Reserved=0;
			scf->AccessMask= 0x00000000 | /*0x0012019f*/
				(mode == OF_READ ? 1 : (mode == OF_WRITE ? 2 : (mode == OF_READWRITE ? 3 : 0)));		// 
//			scf->AccessMask= 0x00120089;
//			scf->AccessMask=SMB2_ACCESS_SYNCHRONIZE | SMB2_ACCESS_READCONTROL | SMB2_ACCESS_WRITEATTRIBUTES | 
//				SMB2_ACCESS_READATTRIBUTES | SMB2_ACCESS_WRITEEA | SMB2_ACCESS_READEA | SMB2_ACCESS_APPEND | 
//				SMB2_ACCESS_WRITE | SMB2_ACCESS_READ;	//0x0012019f

			scf->Attributes=SMB2_FILE_ATTRIB_NORMAL | (mode != OF_READ ? SMB2_FILE_ATTRIB_ARCHIVE : 0);			// diciamo
			scf->ShareAccess= 0x0000 | /*0x0007*/
				(share == OF_SHARE_DENY_NONE ? (SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE) :
				(share == OF_SHARE_DENY_WRITE ? SMB2_FILE_SHARE_READ : (share == OF_SHARE_DENY_READ ? 0 : 
				(SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE))));			//
			scf->Disposition= mode == OF_READ ? SMB2_FILE_OPEN : (mode == OF_WRITE ? SMB2_FILE_OVERWRITE_IF/*SMB2_FILE_CREATE*/ : 
				(mode == OF_READWRITE ? SMB2_FILE_OPEN_IF : 0));		// VERIFICARE specie RW
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 152
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
			if(rsh->Status==STATUS_OK) {
				memcpy(fileguid,scr->FileGUID,16);		// FINIRE!

				scr->EOFSize;

				return 1;
				}
			}

			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::ReadFile(uint8_t *data,uint32_t size) {
	uint8_t buf[4096];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_READFILE *srf;
	SMB2_READ_RESPONSE *srr;

	if(isConnected) {
		if(version==1) {
			}
		else {
			do {
				i=min(size,4096);

				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_READ,1,320);
				srf=(SMB2_READFILE*)(buf+sizeof(SMB2_HEADER)+4);
				srf->Size.size=0x31;
				srf->Padding=0x50;
				srf->Flags=0;
				srf->Length=i;
				srf->Offset=fileoffset;
				memcpy(srf->FileGUID,fileguid,16);
				srf->MinCount=0;
				srf->Channel=0;
				srf->RemainingBytes=0;
				srf->BlobOffset=0;
				srf->BlobLength=0;

				len=sh->Size+(srf->Size.size & 0xfffe)+srf->BlobLength  +1;
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(!readResponseSMB2(buf,4096))		// 64+16+i
					goto errore;		// se ok/completo
				rsh=(SMB2_HEADER*)buf;
				srr=(SMB2_READ_RESPONSE*)(buf+sizeof(SMB2_HEADER));

				memcpy(data,srr->Blob,i);

				size-=i;
				data+=i;
				} while(size>0);

			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::WriteFile(uint8_t *data,uint32_t size) {
	uint8_t buf[4096];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_WRITEFILE *swf;
	SMB2_WRITE_RESPONSE *swr;
	SMB2_SETINFO *si;

	if(isConnected) {
		if(version==1) {
			}
		else {
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_SETINFO,1,1);
			// bah questo non penso che serva davvero, allora credo solo lo spazio
			si=(SMB2_SETINFO*)(buf+sizeof(SMB2_HEADER)+4);
			si->Size.size=0x21;
			si->Class=SMB2_FS_FILE_INFO;
			si->InfoLevel=SMB2_FILE_ENDOFFILE_INFO;
			si->InfoSize=8;
			si->InfoOffset=0x0060;
			si->Reserved=0;
			si->AdditionalInfo=0;
			memcpy(si->FileGUID,fileguid,16);
			*(uint64_t*)(&si->Blob[0])=fileoffset+size;

			len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,4096))		// 196
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

			}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_WRITE,1,1);		// ossia NetShareEnumAll
			swf=(SMB2_WRITEFILE*)(buf+sizeof(SMB2_HEADER)+4);
			swf->Size.size=0x31;
			swf->DataOffset=0x70;
			swf->Offset=fileoffset;
			memcpy(swf->FileGUID,fileguid,16);
			swf->Channel=0;
			swf->RemainingBytes=0;
			swf->Flags=0;
			swf->BlobOffset=0;
			swf->BlobLength=0;

			swf->Length=size;
			fileoffset+=size;


//			i=min(1024,size);
			memcpy(&swf->Blob[-4],data,size);
//			data+=i;
//			size-=i;

			len=sh->Size+(swf->Size.size & 0xfffe)+size;
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(readResponseSMB2(buf,4096))		// 80
				;		// se ok/completo
			rsh=(SMB2_HEADER*)buf;
			swr=(SMB2_WRITE_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

			// COME SI FA se > 65535?!
	/*		if(size) do {
				i=min(1024,size);
				Send(data,i);
				data+=i;
				size-=i;
				} while(size>0);*/
			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::CloseFile() {
	uint8_t buf[1024];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CLOSEFILE *sclf;
	SMB2_CLOSE_RESPONSE *scr;

	if(isConnected) {
		if(version==1) {
			}
		else {
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)(buf+sizeof(SMB2_HEADER)+4);
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,fileguid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(readResponseSMB2(buf,1024))		// 120
				;		// se ok/completo
			rsh=(SMB2_HEADER*)buf;
			scr=(SMB2_CLOSE_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

			ZeroMemory(fileguid,16);
			}
		}

	return 0;
	}

int CCIFSCliSocket::DeleteFile(LPCTSTR s) {
	uint8_t buf[1024];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;
	SMB2_SETINFO *si;
	SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];

	if(isConnected) {
		if(version==1) {
			}
		else {
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 152
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// 
			}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_SETINFO,1,1);
			si=(SMB2_SETINFO*)(buf+sizeof(SMB2_HEADER)+4);
			si->Size.size=0x21;
			si->Class=SMB2_FS_FILE_INFO;
			si->InfoLevel=SMB2_FILE_DISPOSITION_INFO;
			si->InfoSize=1;
			si->InfoOffset=0x0060;
			si->Reserved=0;
			si->AdditionalInfo=0;
			memcpy(si->FileGUID,guid,16);
			si->Blob[0]=SMB2_SETINFO_DELETEONCLOSE;

			len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 196
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

			}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)(buf+sizeof(SMB2_HEADER)+4);
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,guid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 120
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CLOSE_RESPONSE *scr=(SMB2_CLOSE_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

			}

			return 1;

			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::RenameFile(LPCTSTR s,LPCTSTR d) {
	uint8_t buf[1024];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_CREATEFILE *scf;
	SMB2_SETINFO *si;
	SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];

	//non si capisce... fa delle Create ma boh idem... anche per le Dir
	if(isConnected) {
		if(version==1) {
			}
		else {
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))			// 152
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// 
			}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_SETINFO,1,1);
			si=(SMB2_SETINFO*)(buf+sizeof(SMB2_HEADER)+4);
			si->Size.size=0x21;
			si->Class=SMB2_FS_FILE_INFO;
			si->InfoLevel=SMB2_FILE_RENAME_INFO;
			si->InfoOffset=0x0060;
			si->Reserved=0;
			si->AdditionalInfo=0;
			memcpy(si->FileGUID,guid,16);
			{SMB2_FILERENAMEINFO *sfri=(SMB2_FILERENAMEINFO*)&si->Blob[0];
			sfri->ReplaceIf=0;
			ZeroMemory(&sfri->Reserved,7);
			*(uint32_t*)&sfri->Reserved=rand();
			sfri->RootDirHandle=0;		// mah com'è?
			sfri->FilenameLength=2*strlen(d);		//unicode
			uniEncode(d,sfri->Blob);
			si->InfoSize=sizeof(SMB2_FILERENAMEINFO)-256+sfri->FilenameLength;
			}

			len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))			// 196
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

			}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CLOSE,1,1);
			sclf=(SMB2_CLOSEFILE*)(buf+sizeof(SMB2_HEADER)+4);
			sclf->Size.size=0x18;
			sclf->Flags=0;
			memcpy(sclf->FileGUID,guid,16);

			len=sh->Size+(sclf->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(!readResponseSMB2(buf,1024))			// 120
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CLOSE_RESPONSE *scr=(SMB2_CLOSE_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

			}

			return 1;

			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::FileStat(LPCTSTR s,	struct stat *statbuf) {
	uint8_t buf[1024];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_GETINFO *sgi;
	SMB2_CREATEFILE *scf;
	SMB2_GETINFO_RESPONSE *sgir;
	uint8_t guid[16];

	//non si capisce... fa delle Create ma boh
	if(isConnected) {
		ZeroMemory(statbuf,sizeof(struct stat));
		if(version==1) {
			}
		else {
			if(s) {
				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
				scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
				scf->BlobFilenameLength=12;
				scf->BlobOffset=0;
				scf->BlobLength=0;
				{
				scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
				uniEncode(s,&scf->Blob[-8]);
				}

				len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024)) {		// 152
					rsh=(SMB2_HEADER*)buf;
					{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
					statbuf->st_size=scr->EOFSize;
					statbuf->st_atime=*(uint32_t*)&FiletimeToTime(scr->AccessTime);
					statbuf->st_ctime=*(uint32_t*)&FiletimeToTime(scr->WriteTime);
					statbuf->st_mtime=*(uint32_t*)&FiletimeToTime(scr->ModifiedTime);
					statbuf->st_mode=scr->Attrib;			// verificare...
					}
					return 1;
					}
				}
			else {
				memcpy(guid,fileguid,16);

				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_GETINFO,1,1);
				sgi=(SMB2_GETINFO*)(buf+sizeof(SMB2_HEADER)+4);
				sgi->Size.size=0x29;
				sgi->Class=SMB2_FS_FILE_INFO;
				sgi->InfoLevel=SMB2_FILE_FS_SIZE_INFO;		// 
				sgi->MaxSize=24;
				sgi->InputOffset=0x68;
				sgi->Reserved=0;
				sgi->InputSize=0;
				sgi->AdditionalInfo=0;
				sgi->Flags=0;
				memcpy(sgi->FileGUID,guid,16);
				len=sh->Size+(sgi->Size.size & 0xfffe);
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024)) {		// 96
					rsh=(SMB2_HEADER*)buf;
					{SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   8);
//					statbuf->st_size=sgir->EOFSize;
//					statbuf->st_atime=*(uint32_t*)&FiletimeToTime(scr->AccessTime);
//					statbuf->st_ctime=*(uint32_t*)&FiletimeToTime(scr->WriteTime);
//					statbuf->st_mtime=*(uint32_t*)&FiletimeToTime(scr->ModifiedTime);
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

int CCIFSCliSocket::SetFileTime(const char *s, CTime t) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_SETINFO *si;
	SMB2_CREATEFILE *scf;
	uint8_t guid[16];

	if(isConnected) {
		if(version==1) {
			}
		else {
			if(!*(int*)&t) 
        t=CTime::GetCurrentTime();
      sh=(SMB2_HEADER*)(buf+4);
      prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
      scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
      scf->BlobFilenameLength=12;
      scf->BlobOffset=0;
      scf->BlobLength=0;
      {
      scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
      uniEncode(s,&scf->Blob[-8]);
      }

      len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
      prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
      Send(buf,len+4);
      if(readResponseSMB2(buf,512)) {   // 152
        rsh=(SMB2_HEADER*)buf;
        {SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
        
				memcpy(guid,scr->FileGUID,16);		// 

        sh=(SMB2_HEADER*)(buf+4);
        prepareSMB2header(sh,SMB2_COM_SETINFO,1,1);
        si=(SMB2_SETINFO*)(buf+sizeof(SMB2_HEADER)+4);
        si->Size.size=0x21;
        si->Class=SMB2_FS_FILE_INFO;
        si->InfoLevel=SMB2_FILE_BASIC_INFO;
        si->InfoSize=sizeof(SMB2_FILEBASICINFO) /*0x40*/;
        si->InfoOffset=0x0060;
        si->Reserved=0;
        si->AdditionalInfo=0;
        memcpy(si->FileGUID,guid,16);
        {SMB2_FILEBASICINFO *sfbi=(SMB2_FILEBASICINFO*)((char*)si+si->InfoOffset);
        memset(sfbi,0,sizeof(SMB2_FILEBASICINFO));
        sfbi->WriteTime=TimeToFiletime(t);
        }

        len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
        prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
        Send(buf,len+4);
        if(!readResponseSMB2(buf,512))    // 196
          goto errore;
        rsh=(SMB2_HEADER*)buf;
        {SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

        }
        
        }
        return 1;
        }
			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::Attrib(const char *s,uint8_t attrAnd,uint8_t attrOr) {
	uint8_t buf[512];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_GETINFO *sgi;
	SMB2_SETINFO *si;
	SMB2_CREATEFILE *scf;
	uint8_t guid[16];

	if(isConnected) {
		if(version==1) {
			}
		else {
      sh=(SMB2_HEADER*)(buf+4);
      prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
      scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
      scf->BlobFilenameLength=12;
      scf->BlobOffset=0;
      scf->BlobLength=0;
      {
      scf->BlobFilenameLength /*BlobLength*/=strlen(s)*2;		// Unicode;
      uniEncode(s,&scf->Blob[-8]);
      }

      len=sh->Size+(scf->Size.size & 0xfffe)+scf->BlobLength+scf->BlobFilenameLength;
      prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
      Send(buf,len+4);
      if(readResponseSMB2(buf,512)) {   // 152
        SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
        rsh=(SMB2_HEADER*)buf;
				memcpy(guid,scr->FileGUID,16);		// 
        
// VERIFICARE!
				sh=(SMB2_HEADER*)(buf+4);
				prepareSMB2header(sh,SMB2_COM_GETINFO,1,1);
				sgi=(SMB2_GETINFO*)(buf+sizeof(SMB2_HEADER)+4);
				sgi->Size.size=0x29;
				sgi->Class=SMB2_FS_FILE_INFO;
				sgi->MaxSize=24;
				sgi->InputOffset=0x68;
				sgi->Reserved=0;
				sgi->InputSize=0;
				sgi->AdditionalInfo=0;
				sgi->Flags=0;
				memcpy(sgi->FileGUID,guid,16);
				len=sh->Size+(sgi->Size.size & 0xfffe);
				prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
				Send(&buf,len+4);
				if(readResponseSMB2(buf,1024)) {		// 96
					rsh=(SMB2_HEADER*)buf;
					{SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   8);
		      SMB2_FILEBASICINFO *sfbi=(SMB2_FILEBASICINFO*)((char*)sgir+sgir->BlobOffset);
					i=sfbi->Attrib;
					}

					sh=(SMB2_HEADER*)(buf+4);
					prepareSMB2header(sh,SMB2_COM_SETINFO,1,1);
					si=(SMB2_SETINFO*)(buf+sizeof(SMB2_HEADER)+4);
					si->Size.size=0x21;
					si->Class=SMB2_FS_FILE_INFO;
					si->InfoLevel=SMB2_FILE_BASIC_INFO;
					si->InfoSize=sizeof(SMB2_FILEBASICINFO) /*0x40*/;
					si->InfoOffset=0x0060;
					si->Reserved=0;
					si->AdditionalInfo=0;
					memcpy(si->FileGUID,guid,16);
					{SMB2_FILEBASICINFO *sfbi=(SMB2_FILEBASICINFO*)((char*)si+si->InfoOffset);
					memset(sfbi,0,sizeof(SMB2_FILEBASICINFO));
					sfbi->Attrib=(i & attrAnd) | attrOr;
					}

					len=sh->Size+(si->Size.size & 0xfffe)+si->InfoSize;
					prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
					Send(buf,len+4);
					if(!readResponseSMB2(buf,512))    // 196
						goto errore;
					rsh=(SMB2_HEADER*)buf;
					{SMB2_SETINFO_RESPONSE *ssr=(SMB2_SETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);

					}
        
					}
        return 1;
        }
			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::CloseSession() {
	uint8_t buf[1024],buf2[256];
	int i,len;

	if(isConnected) {
		if(version==1) {
			}
		else {
			SMB2_HEADER *sh,*rsh;
			SMB2_CLOSE_SESSION *scs;

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_ENDSESSION,1,1);
			scs=(SMB2_CLOSE_SESSION*)(buf+sizeof(SMB2_HEADER)+4);
			scs->Size.size=0x4;
			scs->Flags=0;
			len=4+sh->Size+(scs->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(&buf,len+4);
			if(readResponseSMB2(buf,1024))			// 68
				;
			rsh=(SMB2_HEADER*)buf;

			SMB2_CLOSESESSION_RESPONSE;		// usare...

			}
		sessionid=0;

		Disconnect();
		}

	return 0;
	}

int CCIFSCliSocket::GetVolumeInfo(char *d,CTime *t) {
	uint8_t buf[1024],buf2[256];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_GETINFO *sgi;
	SMB2_CREATEFILE *scf;
	SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];

	if(isConnected) {
		if(version==1) {
			}
		else {
// provare...
      // credo che serva una Create prima, con filename vuoto  v.wireshark
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(buf,len+4);
			if(!readResponseSMB2(buf,1024))			// 152
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// FINIRE!
			}

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_GETINFO,1,1);
			sgi=(SMB2_GETINFO*)(buf+sizeof(SMB2_HEADER)+4);
			sgi->Size.size=0x29;
			sgi->Class=SMB2_FS_INFO;
			sgi->InfoLevel=SMB2_FILE_FS_VOLUME_INFO;		// 
			sgi->MaxSize=88;
			sgi->InputOffset=0;
			sgi->Reserved=0;
			sgi->InputSize=0;
			sgi->AdditionalInfo=0;
			sgi->Flags=0;
			memcpy(&sgi->FileGUID,guid,16);
			len=sh->Size+(sgi->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 96
				goto errore;
			{rsh=(SMB2_HEADER*)buf;
			SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);
      SMB2_FILEVOLUMEINFO *sfvi=(SMB2_FILEVOLUMEINFO*)((char*)buf+sgir->BlobOffset);
      uniDecode(sfvi->Label,sfvi->LabelLength,d);
			*t=FiletimeToTime(sfvi->CreateTime);
      }

			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_GETINFO,1,1);
			sgi=(SMB2_GETINFO*)(buf+sizeof(SMB2_HEADER)+4);
			sgi->Size.size=0x29;
			sgi->Class=SMB2_FS_INFO;
			sgi->InfoLevel=SMB2_FILE_STANDARD_INFO;		// 
			sgi->MaxSize=80;
			sgi->InputOffset=0;
			sgi->Reserved=0;
			sgi->InputSize=0;
			sgi->AdditionalInfo=0;
			sgi->Flags=0;
			memcpy(&sgi->FileGUID,guid,16);
			len=sh->Size+(sgi->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(buf,len+4);
			if(!readResponseSMB2(buf,1024))			// 96
				goto errore;
			{rsh=(SMB2_HEADER*)buf;
			SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   8);
      SMB2_FILEFSINFO *sffi=(SMB2_FILEFSINFO*)((char*)sgir+sgir->BlobOffset);
// bah qua c'è FSname "NTFS" e attributi del file system...
      }

      sh=(SMB2_HEADER*)(buf+4);
      prepareSMB2header(sh,SMB2_COM_CLOSE,1,1);
      sclf=(SMB2_CLOSEFILE*)(buf+sizeof(SMB2_HEADER)+4);
      sclf->Size.size=0x18;
      sclf->Flags=0;
      memcpy(sclf->FileGUID,guid,16);

      len=sh->Size+(sclf->Size.size & 0xfffe);
      prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
      Send(buf,len+4);
      if(!readResponseSMB2(buf,1024))			// 120
				goto errore;
      rsh=(SMB2_HEADER*)buf;

			return 1;
			}
		}

errore:
	return 0;
	}

int CCIFSCliSocket::VolumeInfo(uint64_t *totalSectors,uint64_t *freeSectors,uint32_t *sectorSize) {
	uint8_t buf[1024],buf2[256];
	int i,len;
	SMB2_HEADER *sh,*rsh;
	SMB2_GETINFO *sgi;
	SMB2_CREATEFILE *scf;
	SMB2_CLOSEFILE *sclf;
	uint8_t guid[16];

	if(isConnected) {
		if(version==1) {
			}
		else {
// provare...
      // credo che serva una Create prima, con filename vuoto  v.wireshark
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_CREATE,1,1);
			scf=(SMB2_CREATEFILE*)(buf+sizeof(SMB2_HEADER)+4);
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
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(buf,len+4);
			if(!readResponseSMB2(buf,1024))			// 152
				goto errore;
			rsh=(SMB2_HEADER*)buf;
			{SMB2_CREATE_RESPONSE *scr=(SMB2_CREATE_RESPONSE*)(buf+sizeof(SMB2_HEADER));
			memcpy(guid,scr->FileGUID,16);		// FINIRE!
			}

			//PROVARE!!
			sh=(SMB2_HEADER*)(buf+4);
			prepareSMB2header(sh,SMB2_COM_GETINFO,1,1);
			sgi=(SMB2_GETINFO*)(buf+sizeof(SMB2_HEADER)+4);
			sgi->Size.size=0x29;
			sgi->Class=SMB2_FS_INFO;
			sgi->InfoLevel=SMB2_FILE_FULL_INFO;		// 
			sgi->MaxSize=32;
			sgi->InputOffset=68;
			sgi->Reserved=0;
			sgi->InputSize=0;
			sgi->AdditionalInfo=0;
			sgi->Flags=0;
			memcpy(&sgi->FileGUID,guid,16);
			len=sh->Size+(sgi->Size.size & 0xfffe);
			prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
			Send(buf,len+4);
			if(!readResponseSMB2(buf,1024))		// 96
				goto errore;
			{rsh=(SMB2_HEADER*)buf;
			SMB2_GETINFO_RESPONSE *sgir=(SMB2_GETINFO_RESPONSE*)(buf+sizeof(SMB2_HEADER)+   0);
      SMB2_FILEVOLUMESIZEINFO *sfvsi=(SMB2_FILEVOLUMESIZEINFO*)((char*)buf+sgir->BlobOffset);
			*totalSectors=sfvsi->ActualFreeUnits;		// o AllocSize??
			*freeSectors=sfvsi->CallerFreeUnits;
			*sectorSize=sfvsi->SectorsSize;
      }

      sh=(SMB2_HEADER*)(buf+4);
      prepareSMB2header(sh,SMB2_COM_CLOSE,1,1);
      sclf=(SMB2_CLOSEFILE*)(buf+sizeof(SMB2_HEADER)+4);
      sclf->Size.size=0x18;
      sclf->Flags=0;
      memcpy(sclf->FileGUID,guid,16);

      len=sh->Size+(sclf->Size.size & 0xfffe);
      prepareSMBcode(buf,NBSS_SESSION_MESSAGE,len);
      Send(buf,len+4);
      if(!readResponseSMB2(buf,1024))			// 120
				goto errore;
      rsh=(SMB2_HEADER*)buf;

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
char *CCIFSCliSocket::nbEncode(const char *name,char *encoded_name,bool mode) {
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

uint8_t *CCIFSCliSocket::uniEncode(const char *src,uint8_t *dst) {
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

char *CCIFSCliSocket::uniDecode(const uint8_t *src,uint16_t len,char *dst) {
	char *p=dst;
				// o usare 	i=MultiByteToWideChar(CP_ACP,MB_PRECOMPOSED,a,-1,p,n*2);
//	n=wcslen(p);
	while(*src) {
		*p++=*src++;
		src++;
    len-=2;
		}
	*p=0;

	return dst;
	}

CTime CCIFSCliSocket::FiletimeToTime(uint64_t value) {
	SYSTEMTIME sys = { 0 };
	FILETIME ft = { 0 };
	//The FILETIME structure is a 64-bit value that represents the number of 100-nanosecond intervals that have elapsed since January 1, 1601, Coordinated Universal Time (UTC).
#define FILETIME_EPOCH_VALUE 116444736000000000L

//  ft.dwHighDateTime = (value & 0xffffffff00000000) >> 32;
//  ft.dwLowDateTime = value & 0xffffffff;
//	FileTimeToSystemTime(&ft,&sys);
	{
//	CTime t(sys.wYear,sys.wMonth,sys.wDay,sys.wHour,sys.wMinute,sys.wSecond);
	CTime t;
	value-=FILETIME_EPOCH_VALUE;
	value /= 10000000UL;
	t=*(CTime*)&value;		// va uguale, ok per PC_PIC
//ff 61 8b 8c 4a a6 dc 01  25/2/2026 11:33:23 .000780700

	
	return t;
	}
	}
/*#define FILETIME_EPOCH_VALUE 116444736000000000ULL
uint64_t ntlm_timestamp_now(void)
{
    struct timeval tv;
    uint64_t filetime;

    gettimeofday(&tv, NULL);

    // set filetime to the time representing the epoch 
    filetime = FILETIME_EPOCH_VALUE;
    // add the number of seconds since the epoch 
    filetime += (uint64_t)tv.tv_sec * 10000000;
    // add the number of microseconds since the epoch 
    filetime += tv.tv_usec * 10;

    return filetime;
}*/

uint64_t CCIFSCliSocket::TimeToFiletime(CTime value) {
	//The FILETIME structure is a 64-bit value that represents the number of 100-nanosecond intervals that have elapsed since January 1, 1601, Coordinated Universal Time (UTC).

	uint64_t t=(*(uint32_t*)&value)*10000000UL;
	t+=FILETIME_EPOCH_VALUE;
	
	return t;
	}


// ---------------------------------------------------------------------------------------------------------------
CCIFSSrvSocket::CCIFSSrvSocket(UINT nPort,CTestsocketApp *p) {

	version=2;
	port=nPort;
	}

CCIFSSrvSocket::~CCIFSSrvSocket() {
	}

BOOL CCIFSSrvSocket::Create() {

//	CCIFSSrvSocket2::gettime();
	return CSocket::Create(port);
	}

void CCIFSSrvSocket::OnAccept(int nErr) {
	int i,j;
	CCIFSSrvSocket2 *s;
	char myBuf[128];

	if(maxConn < maxClientConnections) {
		s=new CCIFSSrvSocket2(this);
		if(s) {
			cSockRoot.AddTail(s);
			maxConn++;

			j=Accept(*s);
//			s->getPeer() ;
			return;
			}
		}
	{
	CCIFSSrvSocket2 tempSock(this);
	Accept(tempSock);
	tempSock.Close();			// questo forza il client a ri-richiedere la connessione!
	}
	}

void CCIFSSrvSocket::OnClose(int nErr) {

	Close();
	}

void CCIFSSrvSocket::doDelete(CCIFSSrvSocket2 *ss) {
	CCIFSSrvSocket2 *s;
	POSITION po;

	po=cSockRoot.Find(ss);
	if(po) {
		s=cSockRoot.GetAt(po);
		delete s;
		cSockRoot.RemoveAt(po);
		}

	maxConn--;
	}


void CCIFSSrvSocket2::OnReceive(int nErr) {
	char myBuf[4096],myBuf1[512],*s;
	int i,n;
	DWORD len,type;
	NBSS_HEADER nbsh;


	i=Receive(&len,4);

	if(m_Parent->version==1) {
		SMB1_HEADER sh;
		i=Receive(&sh,sizeof(SMB2_HEADER));		// ossia len  FINIRE!
		}
	else {
		SMB2_HEADER *sh;

		len=htonl(len);
		i=Receive(myBuf,len /*sizeof(SMB2_HEADER)*/);		// ossia len
		sh=(SMB2_HEADER*)((char*)myBuf);

		if(sessionid && sessionid != sh->SessionID)
			goto errore_sid;
		if(treeid && treeid != sh->TreeID)
			goto errore_tid;
		if(processid && processid != sh->ProcessID)
			goto errore_pid;

		switch(sh->Command) {
			case SMB2_COM_NEGOTIATE:
				{
				SMB2_NEGOTIATE_PROTOCOL *snp;
				SMB2_NEGOTIATE_RESPONSE *snr;
//				i=Receive(&myBuf,i /*sizeof(SMB2_NEGOTIATE_PROTOCOL)*/);
				snp=(SMB2_NEGOTIATE_PROTOCOL*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(snp->Size.size != 0x24)
					goto errore_size;
				n=snp->DialectCount;
				processid=sh->ProcessID;
				msgcntR=sh->MessageID;
				msgcntS=msgcntR;

				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_NEGOTIATE,STATUS_OK,sessionid,1,1);

				snr=(SMB2_NEGOTIATE_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				snr->Size.dynamicPart=1;  snr->Size.fixedPart=32;
				snr->Security=SMB2_FLAG_SIGNING;
				snr->Dialect=0x210;
				snr->Capabilities=SMB2_NEGOTIATE_DFS | SMB2_NEGOTIATE_LEASING;
				snr->NegotiateContextcount=0;
				getGUID(serverguid);
				memcpy(snr->ServerGUID,serverguid,16);
				snr->MaxTransactionSize=65536;
				snr->MaxReadSize=65536;
				snr->MaxWriteSize=65536;
				snr->CurrentTime=gettime();
				snr->BootTime=gettime()-(((uint64_t)timeGetTime())*10000);
				snr->BlobOffset=0x80;
				snr->BlobLength=42;
				snr->NegotiateContextoffset=0x53534d4c;		//LMSS
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_NEGOTIATE_RESPONSE)-sizeof(snr->Blob)+snr->BlobLength);
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_NEGOTIATE_RESPONSE)-sizeof(snr->Blob)+snr->BlobLength);
				}
				break;
			case SMB2_COM_OPENSESSION:
				switch(sessionstate) {
					SMB2_OPEN_SESSION *sos;
					SMB2_OPENSESSION_RESPONSE *sosr;
					case 0:
						if(sh->SessionID==sessionid)
							;

		//				i=Receive(&myBuf,i /*sizeof(SMB2_OPEN_SESSION)*/);
						sos=(SMB2_OPEN_SESSION*)((char*)myBuf+sizeof(SMB2_HEADER));
						if(sos->Size.size != 0x19)
							goto errore_size;

						msgcntR=sh->MessageID;
						msgcntS=msgcntR;
						sh=(SMB2_HEADER*)((char*)myBuf+4);
						prepareSMB2header(sh,SMB2_COM_OPENSESSION,STATUS_MORE_PROCESSING_REQUIRED,
							rand() | ((uint32_t)rand() << 16),1,32);

						sosr=(SMB2_OPENSESSION_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
						sosr->Size.dynamicPart=1;		sosr->Size.fixedPart=8;
						sosr->Flags=0;
						sosr->BlobOffset=0x48;
						sosr->BlobLength=179;
						*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_OPENSESSION_RESPONSE)-sizeof(sosr->Blob)+sosr->BlobLength);
						Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_OPENSESSION_RESPONSE)-sizeof(sosr->Blob)+sosr->BlobLength);
						sessionstate++;
						break;
					case 1:
		//				i=Receive(&myBuf,i /*sizeof(SMB2_OPEN_SESSION)*/);
						sos=(SMB2_OPEN_SESSION*)((char*)myBuf+sizeof(SMB2_HEADER));
						sessionid=sh->SessionID;
						if(sos->Size.size != 0x19)
							goto errore_size;

						msgcntR=sh->MessageID;
						msgcntS=msgcntR;
						sh=(SMB2_HEADER*)((char*)myBuf+4);
						prepareSMB2header(sh,SMB2_COM_OPENSESSION,STATUS_OK,sessionid,1,1);

						sosr=(SMB2_OPENSESSION_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
						sosr->Size.dynamicPart=1;		sosr->Size.fixedPart=8;
						sosr->Flags=0;
						sosr->BlobOffset=0x48;
						sosr->BlobLength=29;
						*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_OPENSESSION_RESPONSE)-sizeof(sosr->Blob)+sosr->BlobLength);
						Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_OPENSESSION_RESPONSE)-sizeof(sosr->Blob)+sosr->BlobLength);

						sessionstate++;
						break;
					}
				break;
			case SMB2_COM_ENDSESSION:
				{
				SMB2_CLOSE_SESSION *scs;
				SMB2_CLOSESESSION_RESPONSE *scsr;
//				i=Receive(&myBuf,sizeof(SMB2_CLOSE_SESSION));
				scs=(SMB2_CLOSE_SESSION*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(scs->Size.size != 0x4)
					goto errore_size;

				msgcntR=sh->MessageID;
				msgcntS=msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_ENDSESSION,STATUS_OK,sessionid,1,1);

				scsr=(SMB2_CLOSESESSION_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				scsr->Size.dynamicPart=0;		scsr->Size.fixedPart=2;
				scsr->Reserved=0;
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_CLOSESESSION_RESPONSE));
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_CLOSESESSION_RESPONSE));

				sessionstate=0;
				}
				break;
			case SMB2_COM_TREECONNECT:
				{
				SMB2_TREE_CONNECT *stc;
				SMB2_TREE_CONNECT_RESPONSE *stcr;
				uint8_t *p;
				char nome[256],*p2;
				CFileFind finder;
				char realPath[512];
				int n;

//				i=Receive(&myBuf,sizeof(SMB2_FIND));
				msgcntR=sh->MessageID;
				msgcntS=msgcntR;

//				i=Receive(&myBuf,sizeof(SMB2_TREE_CONNECT));
				stc=(SMB2_TREE_CONNECT*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(stc->Size.size != 0x9)
					goto errore_size;

				p=(uint8_t*)myBuf+stc->BlobOffset;
				CCIFSCliSocket::uniDecode(p,stc->BlobLength,nome);
				p2=strrchr(nome,'\\');
				if(p2)
					/* p2++ */;		// vado in root cmq
				else			// beh NON deve accadere!
					p2=nome;

//				AfxMessageBox(p2);

				strcpy(curtree,p2);
				strcat(p2,"\\*.*");
//				AfxMessageBox(p2);
				BOOL bWorking = finder.FindFile(p2);
				n=0;
				if(bWorking) {
					bWorking = finder.FindNextFile();
					if(bWorking) {
//						AfxMessageBox(finder.GetFileName());
						n=1;
						}
					}
				if(!n)
					*curtree=0;
				finder.Close();

				treeid=rand();		// VERIFICARE! o mettere un progressivo su finder
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_TREECONNECT,n ? STATUS_OK : STATUS_NO_SUCH_FILE,sessionid,1,1);

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
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_TREE_CONNECT_RESPONSE));
				}
				break;
			case SMB2_COM_TREEDISCONNECT:
				{
				SMB2_TREE_DISCONNECT *std;
				SMB2_TREEDISCONNECT_RESPONSE *stdr;
//				i=Receive(&myBuf,sizeof(SMB2_TREE_DISCONNECT));
				std=(SMB2_TREE_DISCONNECT*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(std->Size.size != 0x4)
					goto errore_size;

				msgcntR=sh->MessageID;
				msgcntS=msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_TREEDISCONNECT,STATUS_OK,sessionid,1,1);

				stdr=(SMB2_TREEDISCONNECT_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				stdr->Size.dynamicPart=0;		stdr->Size.fixedPart=2;
				stdr->Reserved=0;
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_TREEDISCONNECT_RESPONSE));
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_TREEDISCONNECT_RESPONSE));

				*curtree=0;
				treeid=0;
				}
				break;
			case SMB2_COM_CREATE:
				{
				SMB2_CREATEFILE *scf;
				SMB2_CREATE_RESPONSE *scr;
				char nomefile[256],nometemp[512];
				uint8_t *p;
				int i;
				CFileStatus fs;
				char myguid[16];

//				i=Receive(&myBuf,sizeof(SMB2_CREATEFILE));
				scf=(SMB2_CREATEFILE*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(scf->Size.size != 0x39)
					goto errore_size;

				msgcntR=sh->MessageID;
				msgcntS=msgcntR;

				createflags=scf->Flags;
				createoptions=scf->CreateOptions;
				p=(uint8_t*)myBuf+scf->BlobFilenameOffset;

/*				CString S;
				S.Format(scf->BlobFilenameOffset);
				AfxMessageBox(S);*/
				if(scf->BlobFilenameLength)
					CCIFSCliSocket::uniDecode(p,scf->BlobFilenameLength,nomefile);
				else
					*nomefile=0;

				sh=(SMB2_HEADER*)((char*)myBuf+4);

				scr=(SMB2_CREATE_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				scr->Size.dynamicPart=1;		scr->Size.fixedPart=44;		// OCCHIO è variabile a seconda del tipo di create!

				strcpy(nometemp,curtree);
				strcat(nometemp,"\\");
				strcat(nometemp,nomefile);

//				AfxMessageBox(nometemp);
				/*CString S;
				S.Format("%08x %08x",createoptions,scf->AccessMask);
				AfxMessageBox(S);*/
				getGUID(myguid);
				if(*nomefile) {
					i=0;
					if(createoptions & SMB2_OPTION_DIRECTORY) {
						strcpy(curdir,nomefile);
						i=mkdir(nometemp);
						memcpy(dirguid,myguid,16);
						}
					else {
						CFileException e;
						strcpy(curfile,nomefile);
						if(scf->AccessMask & SMB2_ACCESS_READ) {
							i=file.Open(nometemp,CFile::modeRead     | CFile::shareDenyWrite);
							scr->Action=i ? 1 : 0;			// 
							}
						else if(scf->AccessMask & SMB2_ACCESS_WRITE) {
							i=file.Open(nometemp,CFile::modeWrite | CFile::modeCreate    | CFile::shareDenyNone);
//					AfxMessageBox(e.m_cause);
							scr->Action=i ? 2 : 0;			// FINIRE con create opp no
							}
						memcpy(fileguid,myguid,16);
						}

					file.GetStatus(fs);
					scr->Attrib=fs.m_attribute;
					scr->EOFSize=file.GetLength();
					scr->FileSize=file.GetLength();
					scr->AccessTime=gettime(fs.m_atime);
					scr->CreateTime=gettime(fs.m_ctime);
					scr->ModifiedTime=gettime(fs.m_mtime);
					scr->WriteTime=gettime(fs.m_mtime);
					}
				else {
					i=2;		// casi speciali con Blob...
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

				prepareSMB2header(sh,SMB2_COM_CREATE,i ? STATUS_OK : STATUS_OBJECT_NAME_NOT_FOUND,sessionid,1,1);

//				AfxMessageBox(nometemp);
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_CREATE_RESPONSE)-sizeof(scr->Blob)+scr->BlobLength);
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_CREATE_RESPONSE)-sizeof(scr->Blob)+scr->BlobLength);
				}
				break;
			case SMB2_COM_CLOSE:
				{
				SMB2_CLOSEFILE *scs;
				SMB2_CLOSE_RESPONSE *scsr;

//				i=Receive(&myBuf,sizeof(SMB2_CLOSEFILE));
				scs=(SMB2_CLOSEFILE*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(scs->Size.size != 0x18)
					goto errore_size;

				msgcntR=sh->MessageID;
				msgcntS=msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);

				scsr=(SMB2_CLOSE_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				scsr->Size.dynamicPart=0;		scsr->Size.fixedPart=30;
				if(*curfile) {
					CFileStatus fs;
					file.GetStatus(fs);
					scsr->Attrib=fs.m_attribute;
					scsr->EOFSize=file.GetLength();
					scsr->FileSize=file.GetLength();
					scsr->AccessTime=gettime(fs.m_atime);
					scsr->CreationTime=gettime(fs.m_ctime);
					scsr->ModifiedTime=gettime(fs.m_mtime);
					scsr->WriteTime=gettime(fs.m_mtime);
					file.Close();
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
				if(createoptions & SMB2_OPTION_DELETEONCLOSE)
					CFile::Remove(curfile);

				prepareSMB2header(sh,SMB2_COM_CLOSE,STATUS_OK,sessionid,1,1);

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_CLOSE_RESPONSE));
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_CLOSE_RESPONSE));

				*curfile=0;		// occhio se le cose si sovrappongono
				createflags=0;
				createoptions=0;
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
				uint8_t buf[65536];			// v. max Transaction ecc

//				i=Receive(&myBuf,sizeof(SMB2_READFILE));
				srf=(SMB2_READFILE*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(srf->Size.size != 0x31)
					goto errore_size;
				if(memcmp(srf->FileGUID,fileguid,16))
					goto errore_guid;

				msgcntR=sh->MessageID;
				msgcntS=msgcntR;
				sh=(SMB2_HEADER*)((char*)buf+4);
				prepareSMB2header(sh,SMB2_COM_READ,STATUS_OK,sessionid,1,1);

				srr=(SMB2_READ_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
				srr->Size.dynamicPart=1;		srr->Size.fixedPart=8;
				file.Seek(srf->Offset,CFile::begin);
				srr->BlobOffset=0x50;
				srr->BlobLength=file.Read((char*)buf+4+srr->BlobOffset,srf->Length);		// v. sopra
				fileoffset=file.Seek(0,CFile::current);

				*(DWORD*)buf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_READ_RESPONSE)-sizeof(srr->Blob)+srr->BlobLength);
				Send(buf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_READ_RESPONSE)-sizeof(srr->Blob)+srr->BlobLength);
				}
				break;
			case SMB2_COM_WRITE:
				{
				SMB2_WRITEFILE *swf;
				SMB2_WRITE_RESPONSE *swr;
//				i=Receive(&myBuf,sizeof(SMB2_WRITEFILE));
				swf=(SMB2_WRITEFILE*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(swf->Size.size != 0x31)
					goto errore_size;
				if(memcmp(swf->FileGUID,fileguid,16))
					goto errore_guid;

				msgcntR=sh->MessageID;
				msgcntS=msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_WRITE,STATUS_OK,sessionid,1,1);

				swr=(SMB2_WRITE_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				swr->Size.dynamicPart=1;		swr->Size.fixedPart=8;
				/*CString S;
				S.Format("%08x %08x",swf->Offset,swf->Length);
				AfxMessageBox(S);*/
				file.Seek(swf->Offset,CFile::begin);
				file.Write(swf->Blob,swf->Length);		// 
				swr->Count=swf->Length;
				fileoffset=file.Seek(0,CFile::current);

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_WRITE_RESPONSE));
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_WRITE_RESPONSE));
				}
				break;
			case SMB2_COM_LOCK:
				break;
			case SMB2_COM_IOCTL:
				{
				SMB2_IOCTL *si;
				SMB2_IOCTL_RESPONSE *sir;
//				i=Receive(&myBuf,sizeof(SMB2_WRITEFILE));
				si=(SMB2_IOCTL*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(si->Size.size != 0x31)
					goto errore_size;

				msgcntR=sh->MessageID;
				msgcntS=msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);
				prepareSMB2header(sh,SMB2_COM_IOCTL,STATUS_OK,sessionid,1,1);

				sir=(SMB2_IOCTL_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
				sir->Size.dynamicPart=1;		sir->Size.fixedPart=8;		// FINIRE!

				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_IOCTL_RESPONSE));
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_IOCTL_RESPONSE));
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
				CFileFind finder;
				char realPath[512],mask[256],*p2;
				uint8_t *p;
				uint8_t buf[65536];			// v. MaxTransactionSize cmq
				uint32_t bufsize;
				int i,n;
				uint32_t flags;

//				i=Receive(&myBuf,sizeof(SMB2_FIND));
				sf=(SMB2_FIND*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(sf->Size.size != 0x21)
					goto errore_size;

				msgcntR=sh->MessageID;
				flags=sh->Flags;		// se SMB2_FLAG_CHAINED è un comando identico a quello prima... v. FIND in certi casi tipo la DIR da dos...
				msgcntS=msgcntR;

				p=(uint8_t*)myBuf+sf->BlobOffset;
				CCIFSCliSocket::uniDecode(p,sf->BlobLength,mask);

//				AfxMessageBox(p2);

				strcpy(realPath,curtree);
				strcat(realPath,curdir);
				strcat(realPath,"\\");
				strcat(realPath,"*.*");
//				strcat(p2,mask);

//				AfxMessageBox(realPath);

				BOOL bWorking = finder.FindFile(realPath);
				n=0;
				bufsize=0;
				while(bWorking) {
					CTime t;
					uint32_t ofs;

					bWorking = finder.FindNextFile();

					sfri1=(SMB2_FIND_RESPONSE_INFO1*)((char*)buf+4+sizeof(SMB2_HEADER)+sizeof(SMB2_FIND_RESPONSE)-8-sizeof(sfr->Blob)+bufsize);
					sfri2=(SMB2_FIND_RESPONSE_INFO2*)sfri1;
					sfri3=(SMB2_FIND_RESPONSE_INFO3*)sfri1;
					sfri4=(SMB2_FIND_RESPONSE_INFO4*)sfri1;
					sfri5=(SMB2_FIND_RESPONSE_INFO5*)sfri1;
					sfri6=(SMB2_FIND_RESPONSE_INFO6*)sfri1;

					switch(sf->InfoLevel) {
						case FileNamesInformation:
							CCIFSCliSocket::uniEncode(finder.GetFileName(),(uint8_t*)sfri6->FileName);
							sfri6->FilenameLength=strlen(finder.GetFileName())*2;
							break;
						case FileFullDirectoryInformation:
							CCIFSCliSocket::uniEncode(finder.GetFileName(),(uint8_t*)sfri2->FileName);
							sfri2->FilenameLength=strlen(finder.GetFileName())*2;
							break;
						case FileIdFullDirectoryInformation:
							CCIFSCliSocket::uniEncode(finder.GetFileName(),(uint8_t*)sfri3->FileName);
							sfri3->FilenameLength=strlen(finder.GetFileName())*2;
							break;
						case FileBothDirectoryInformation:
							CCIFSCliSocket::uniEncode(finder.GetFileName(),(uint8_t*)sfri4->FileName);
							sfri4->FilenameLength=strlen(finder.GetFileName())*2;
							break;
						case FileInformationClass_Reserved:
							break;
						default:
							CCIFSCliSocket::uniEncode(finder.GetFileName(),(uint8_t*)sfri1->FileName);
							sfri1->FilenameLength=strlen(finder.GetFileName())*2;
							break;
						}
					switch(sf->InfoLevel) {
						case FileNamesInformation:
							break;
						case FileInformationClass_Reserved:
							break;
						default:
							sfri1->Attrib=finder.IsHidden() ? 2 : 0 |
								finder.IsArchived() ? 8 : 0 |
								finder.IsCompressed() ? 16 : 0 |        
								finder.IsReadOnly() ? 1 : 0 |
								finder.IsSystem() ? 4 : 0 |
								finder.IsTemporary() ? 32 : 0 |
								finder.IsDots() ? 64 : 0 |
								finder.IsDirectory() ? 128 : 0;
							sfri1->EOFSize=finder.GetLength();
							finder.GetCreationTime(t);
							sfri1->CreationTime=gettime(t);
							finder.GetLastWriteTime(t);
							sfri1->WriteTime=gettime(t);
							sfri1->ModifiedTime=gettime(t);
							finder.GetLastAccessTime(t);
							sfri1->AccessTime=gettime(t);
							break;
						}
					switch(sf->InfoLevel) {
						case FileBothDirectoryInformation:
						case FileIdBothDirectoryInformation:
						case FileIdAllExtdBothDirectoryInformation:
							CCIFSCliSocket::uniEncode("",sfri4->ShortFileName);		// fare!
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
					sfri1->NextOffset=ofs;

					n++;
					}
				sfri1->NextOffset=0;
				finder.Close();

				sh=(SMB2_HEADER*)((char*)buf+4);
				prepareSMB2header(sh,SMB2_COM_FIND,i,sessionid,1,1);
				sfr=(SMB2_FIND_RESPONSE*)((char*)buf+4+sizeof(SMB2_HEADER));
				sfr->Size.dynamicPart=1;		sfr->Size.fixedPart=4;
				sfr->BlobOffset=0x00000048;
				sfr->BlobLength=bufsize;

				*(DWORD*)buf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_FIND_RESPONSE)-8-sizeof(sfr->Blob)+bufsize);
				Send(buf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_FIND_RESPONSE)-8-sizeof(sfr->Blob)+bufsize);

				if(flags & SMB2_FLAG_CHAINED) {		// verificare come e quando...
					sh=(SMB2_HEADER*)((char*)myBuf+4);
					prepareSMB2header(sh,SMB2_COM_FIND,STATUS_NO_MORE_FILES,sessionid,1,1);
					sfr=(SMB2_FIND_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));
					sfr->Size.dynamicPart=1;		sfr->Size.fixedPart=4;
					sfr->BlobOffset=0;
					sfr->BlobLength=0;

					*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_FIND_RESPONSE)-sizeof(sfr->Blob)+sfr->BlobLength);
					Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_FIND_RESPONSE)-sizeof(sfr->Blob)+sfr->BlobLength);
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
				sgi=(SMB2_GETINFO*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(sgi->Size.size != 0x29)
					goto errore_size;

				msgcntR=sh->MessageID;
				msgcntS=msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);

				sgr=(SMB2_GETINFO_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));

				/*CString S;
				S.Format("%08x %08x",sgi->Class,sgi->InfoLevel);
				AfxMessageBox(S);*/
				switch(sgi->Class) {
					case SMB2_FS_FILE_INFO:
						break;
					case SMB2_FS_INFO:
						break;
					case SMB2_SEC_INFO:
						break;
					}
				switch(sgi->InfoLevel) {
					case SMB2_SEC_INFO_00:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=20;
						sgr->BlobLength=0;
						sgr->BlobOffset=0;
						break;
					case SMB2_FILE_FS_VOLUME_INFO:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
						sgr->BlobOffset=0x0048;
						{
						SMB2_FILEVOLUMEINFO *sfvi=(SMB2_FILEVOLUMEINFO*)((char*)myBuf+4+sgr->BlobOffset);
						CTime t(1985,1,1,14,8,0);
						CCIFSCliSocket::uniEncode("frocius",sfvi->Label);
						sfvi->LabelLength=7*2;
						sfvi->CreateTime=gettime(t);
						sfvi->Reserved=0;
						sfvi->SerialNumber=MAKELONG(0/*VERNUML*/,1/*VERNUMH*/);
						sgr->BlobLength=18+sfvi->LabelLength;
						}
						break;
					case SMB2_FILE_FS_SIZE_INFO:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
						sgr->BlobLength=0;
						sgr->BlobOffset=0;
						break;
					case SMB2_FILE_BASIC_INFO:		// verificare
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
						sgr->BlobLength=sizeof(SMB2_FILEBASICINFO);
						sgr->BlobOffset=0x0048;
						{
						SMB2_FILEBASICINFO *sfbi=(SMB2_FILEBASICINFO*)((char*)myBuf+4+sgr->BlobOffset);
						sfbi->AccessTime=0;
						sfbi->Attrib=0;
						sfbi->FileSize=0;
						sfbi->ModifiedTime=0;
						sfbi->Unknown=0;
						sfbi->WriteTime=0;
						}
						break;
					case SMB2_FILE_STANDARD_INFO:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=20;
						sgr->BlobOffset=0x0048;
						{
			      SMB2_FILEFSINFO *sffi=(SMB2_FILEFSINFO*)((char*)myBuf+4+sgr->BlobOffset);
						CCIFSCliSocket::uniEncode("FAT",sffi->Label);
						sffi->Attrib=0;		// case-sensitive, LFN, compression, quotas, OID, ACL, Encrypt...
						sffi->LabelLength=3*2;
						sffi->MaxLabelLength=3*2;
						sgr->BlobLength=12+sffi->LabelLength;
						}
						break;
					case SMB2_FILE_FULL_INFO:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
						sgr->BlobLength=sizeof(SMB2_FILEVOLUMESIZEINFO);
						sgr->BlobOffset=0x0048;
						{
						SMB2_FILEVOLUMESIZEINFO *sfvsi=(SMB2_FILEVOLUMESIZEINFO*)((char*)myBuf+4+sgr->BlobOffset);
						sfvsi->ActualFreeUnits=100;		// o AllocSize??
						sfvsi->CallerFreeUnits=101;
						sfvsi->SectorsSize=512;
						sfvsi->AllocSize=1;
						sfvsi->SectorsPerUnit=1;
						}
						break;
					case SMB2_FILE_OID_INFO:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
						sgr->BlobLength=0;
						sgr->BlobOffset=0;
						break;
					case SMB2_FILE_RENAME_INFO:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
						sgr->BlobLength=0;
						sgr->BlobOffset=0;
						break;
					case SMB2_FILE_DISPOSITION_INFO:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
						sgr->BlobLength=0;
						sgr->BlobOffset=0;
						break;
					case SMB2_FILE_ALLOCATION_INFO:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
						sgr->BlobLength=0;
						sgr->BlobOffset=0;
						break;
					case SMB2_FILE_NETWORK_OPEN_INFO:
						sgr->Size.dynamicPart=1;		sgr->Size.fixedPart=4;
						sgr->BlobLength=0;
						sgr->BlobOffset=0;
						{
						SMB2_NETWORKOPENINFO *snoi=(SMB2_NETWORKOPENINFO*)((char*)myBuf+4+sgr->BlobOffset);
						}
						break;
					}

				prepareSMB2header(sh,SMB2_COM_GETINFO,STATUS_OK,sessionid,1,1);
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_GETINFO_RESPONSE)-sizeof(sgr->Blob)+sgr->BlobLength);
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_GETINFO_RESPONSE)-sizeof(sgr->Blob)+sgr->BlobLength);
				}
				break;
			case SMB2_COM_SETINFO:
				{
				SMB2_SETINFO *ssi;
				SMB2_SETINFO_RESPONSE *ssr;
				char nometemp[256],nometemp2[256];
//				i=Receive(&myBuf,sizeof(SMB2_SETINFO));
				ssi=(SMB2_SETINFO*)((char*)myBuf+sizeof(SMB2_HEADER));
				if(ssi->Size.size != 0x21)
					goto errore_size;

				msgcntR=sh->MessageID;
				msgcntS=msgcntR;
				sh=(SMB2_HEADER*)((char*)myBuf+4);

				ssr=(SMB2_SETINFO_RESPONSE*)((char*)myBuf+4+sizeof(SMB2_HEADER));

				/*CString S;
				S.Format("%08x %08x",ssi->Class,ssi->InfoLevel);
				AfxMessageBox(S);*/
				switch(ssi->Class) {
					case SMB2_FS_FILE_INFO:
						break;
					case SMB2_FS_INFO:
						break;
					case SMB2_SEC_INFO:
						break;
					}
				switch(ssi->InfoLevel) {
					case SMB2_SEC_INFO_00:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=20;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_FS_VOLUME_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_FS_SIZE_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_BASIC_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_STANDARD_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=20;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_FULL_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_OID_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_RENAME_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
						{
						SMB2_FILERENAMEINFO *sfri=(SMB2_FILERENAMEINFO*)((char*)myBuf+4+ssi->InfoOffset);

						strcpy(nometemp,curtree);
						strcat(nometemp,"\\");
						strcat(nometemp,curfile);
						CCIFSCliSocket::uniDecode((uint8_t*)sfri->Blob,sfri->FilenameLength,nometemp2);		//
						i=1;
						try {
							CFile::Rename(nometemp,nometemp2);
							}
						catch (CFileException* pEx) {
							i=0;
							}
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						}
						break;
					case SMB2_FILE_DISPOSITION_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_ENDOFFILE_INFO:
						ssr->Size.dynamicPart=0;		ssr->Size.fixedPart=1;
						file.Seek((uint32_t)*(uint64_t*)((char*)myBuf+ssi->InfoOffset),CFile::current);		// mah verificare
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_ALLOCATION_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					case SMB2_FILE_NETWORK_OPEN_INFO:
						ssr->Size.dynamicPart=1;		ssr->Size.fixedPart=4;
						ssr->BlobLength=0;
						ssr->BlobOffset=0;
						break;
					}

				prepareSMB2header(sh,SMB2_COM_SETINFO,i ? STATUS_OK : STATUS_OBJECT_NAME_NOT_FOUND,sessionid,1,1);
				*(DWORD*)myBuf=htonl(sizeof(SMB2_HEADER)+sizeof(SMB2_SETINFO_RESPONSE)-sizeof(ssr->Blob)+ssr->BlobLength);
				Send(myBuf,sizeof(SMB2_HEADER)+4+sizeof(SMB2_SETINFO_RESPONSE)-sizeof(ssr->Blob)+ssr->BlobLength);
				}
				break;
			case SMB2_COM_BREAK:
				break;
			}
		}

errore_sid:
errore_tid:
errore_pid:
errore_size:
errore_guid:
		;
	}

void CCIFSSrvSocket2::OnClose(int nErr) {

	Close();
	m_Parent->doDelete(this);
	}

void CCIFSSrvSocket2::getGUID(uint8_t *p) {
	int8_t i;

	for(i=0; i<16; i++)
		p[i]=rand();
	}

uint64_t CCIFSSrvSocket2::gettime(CTime t) {
	uint64_t n=FILETIME_EPOCH_VALUE;
	uint32_t t2=*(DWORD*)&t;

	if(!t2)
		t2=*(DWORD*)&CTime::GetCurrentTime();
	n+=((uint64_t)t2)*10000000UL;

	return n;
	}



SMB2_HEADER *CCIFSSrvSocket2::prepareSMB2header(SMB2_HEADER *sh,uint32_t command,uint32_t status,uint32_t session,
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
	sh->MessageID=msgcntS;
	sh->ProcessID=processid;
	sh->TreeID=treeid;
	sh->SessionID=session;
	ZeroMemory(sh->Signature,sizeof(sh->Signature));

	return sh;
	}



CCIFSSrvSocket2::CCIFSSrvSocket2(CCIFSSrvSocket *p) : m_Parent(p) {

	msgcntS=msgcntR=0;
	dialect=0;		// 
	processid=0;
	sessionid=0;
	treeid=0;
	security=0;
	ZeroMemory(&fileguid,16);
	ZeroMemory(&dirguid,16);
	fileoffset=0;
	createflags=0;
	createoptions=0;
	accessmask=0;
	shareaccess=0;
	fileattributes=0;
	*curfile=0;
	*curdir=0;
	*curtree=0;

	sessionstate=0;
	}

CCIFSSrvSocket2::~CCIFSSrvSocket2() {
	}

