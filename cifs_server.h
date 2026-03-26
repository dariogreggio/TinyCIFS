/*
 * SMBPUB.DOC
 * */


#ifndef _CIFS_DEFINED
#define _CIFS_DEFINED

#include <stdint.h>
#include "wifi_penusb.h"
#ifdef SDFILE
#include "fsconfig.h"       
#include "fsio.h"       
#endif
#ifdef WIFI
#include "at_winc1500.h"
#endif

typedef unsigned char UCHAR;		// 8 unsigned bits
typedef unsigned short USHORT;		// 16 unsigned bits
typedef unsigned long ULONG;		// 32 unsigned bits


typedef struct __attribute__((__packed__)) {
  ULONG LowPart;
  LONG HighPart;
	} LARGE_INTEGER_2;				// 64 bits of data			c'è già in windows!

typedef struct __attribute__((__packed__)) {
	ULONG LowTime;
	LONG HighTime;
	} TIME;


// Header

// https://grokipedia.com/page/NetBIOS_over_TCP%2FIP#general-netbios-header
typedef struct __attribute__((__packed__)) {
	uint8_t Type;
	uint8_t Flags;
	uint16_t Length;
	} NBSS_HEADER;


//#define WordCount 1			// sistemare
//#define ByteCount 1
typedef struct __attribute__((__packed__)) {
  UCHAR Protocol[4];                  // Contains 0xFF,'SMB' 
  UCHAR Command;                      // Command code
  union __attribute__((__packed__)) {
    struct __attribute__((__packed__)) {
      UCHAR ErrorClass;           // Error class
      UCHAR Reserved;             // Reserved for future use
      USHORT Error;        		// Error code
			} DosError;
		ULONG NtStatus;                 // NT-style 32-bit error code
		} Status;
  UCHAR Flags;                        // Flags
  USHORT Flags2;   	             // More flags
  union __attribute__((__packed__)) {
    USHORT Pad[6];        	       // Ensure this section is 12 bytes
    struct __attribute__((__packed__)) {
      USHORT PidHigh;             // High part of PID (NT Create And X)
      struct __attribute__((__packed__)) {
        ULONG  HdrReserved;     // Not used
        USHORT Sid;             // Session ID
        USHORT SequenceNumber;  // Sequence number
		    } Connectionless;           // IPX
      };
		};
  USHORT Tid;                     	// Tree identifier
  USHORT Pid;                     	// Caller's process id
  USHORT Uid;                     	// Unauthenticated user id
  USHORT Mid;                     	// multiplex id
  UCHAR  WordCount;			// Count of parameter words
  USHORT ParameterWords[1 /*WordCount*/];	// The parameter words
  USHORT ByteCount;			// Count of bytes
  UCHAR  Buffer[1 /*ByteCount*/];		// The bytes
	} SMB1_HEADER;

typedef struct __attribute__((__packed__)) {
  UCHAR Protocol[4];                  // Contains 0xFE,'SMB'
  USHORT Size;                      // 
  USHORT CreditCharge;
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
		  USHORT ChannelSequence;
		  USHORT Reserved;
			};
	  ULONG Status;                      // (ChannelSequence,Reserved)/Status
		};
  USHORT Command;                      // Command code
	USHORT CreditsRequested;
	ULONG Flags;
	ULONG ChainOffset;			// Next
	uint64_t MessageID;
	ULONG ProcessID;
	ULONG TreeID;
	uint64_t SessionID;
	UCHAR Signature[16];
//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79
//https://github.com/hierynomus/smbj/blob/f62e50fc/src/main/java/com/hierynomus/mssmb2/SMB2Packet.java#L25-L32
	} SMB2_HEADER;

#define SMB2_FLAG_RESPONSE 0x00000001
#define SMB2_FLAG_ASYNCCOMMAND 0x00000002
#define SMB2_FLAG_CHAINED 0x00000004
#define SMB2_FLAG_SIGNING 0x00000008
// 10h..40h: priority
#define SMB2_FLAG_DFSOP 0x10000000
#define SMB2_FLAG_REPLAYOP 0x20000000
    
#define SMB2_FLAG_SIGNING_ENABLED 0x00000001
#define SMB2_FLAG_SIGNING_REQUIRED 0x00000002


typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT DialectCount;
	USHORT /*UCHAR*/ Security;		// wireshark lo dà come 1 byte ma poi ne segue uno a 0, froci
  USHORT Reserved;
	ULONG Capabilities;
	UCHAR ClientGUID[16];
	ULONG NegotiateContextOffset;
	USHORT NegotiateContextCount;
  USHORT Reserved2;
	USHORT Dialect[2];			// ev. ampliare...
	} SMB2_NEGOTIATE_PROTOCOL;

#define SMB2_NEGOTIATE_SECURITY_SIGN_EN 0x01
#define SMB2_NEGOTIATE_SECURITY_SIGN_REQ 0x02

#define SMB2_NEGOTIATE_DFS 0x00000001
#define SMB2_NEGOTIATE_LEASING 0x00000002
#define SMB2_NEGOTIATE_LARGEMTU 0x00000004
#define SMB2_NEGOTIATE_MULTICHANNEL 0x00000008
#define SMB2_NEGOTIATE_PERSISTHANDLES 0x00000010
#define SMB2_NEGOTIATE_DIRLEASING 0x00000020
#define SMB2_NEGOTIATE_ENCRYPTION 0x00000040

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR Flags;
	UCHAR Security;
	ULONG Capabilities;
	ULONG Channel;
	USHORT BlobOffset;
	USHORT BlobLength;
	uint64_t PrevSessionID;
	UCHAR SecurityBlob[  256];		// forse andrebbe dinamico..
	} SMB2_OPEN_SESSION;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT Flags;		// wireshark non lo indica
	} SMB2_CLOSE_SESSION,SMB2_TREE_DISCONNECT,
		SMB2_ECHO_REQUEST,SMB2_ECHO_RESPONSE,		// vabbe' :)
		SMB2_CANCEL_REQUEST;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT Flags;
	USHORT BlobOffset;
	USHORT BlobLength;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
	} SMB2_TREE_CONNECT;
    
#define SMB2_TREE_NAMEDPIPE 0x02
#define SMB2_TREE_PHYSICALDISK 0x01

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR InfoLevel;
	UCHAR FindFlags;
	ULONG FileIndex;
	UCHAR FileGUID[16];
	USHORT BlobOffset;
	USHORT BlobLength;
	ULONG OutputBufferLength;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
	} SMB2_FIND;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR SecurityFlags;		// NON usare, mettere a 0
	UCHAR Oplock;
	ULONG Impersonation;
	uint64_t Flags;
	uint64_t Reserved;
	ULONG AccessMask;
	ULONG Attributes;
	ULONG ShareAccess;
	ULONG Disposition;
	ULONG CreateOptions;
	USHORT BlobFilenameOffset;
	USHORT BlobFilenameLength;
	ULONG BlobOffset;
	ULONG BlobLength;
	uint8_t boh[8];		// serve se NON c'è blob come estensione di Create... verificare (v.CreateFile
	UCHAR Blob[  256];		// forse andrebbe dinamico..
	} SMB2_CREATEFILE;
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e8fb45c1-a03d-44ca-b7ae-47385cfd7997

#define SMB2_ACCESS_READ 0x00000001
#define SMB2_ACCESS_WRITE 0x00000002
#define SMB2_ACCESS_APPEND 0x00000004
#define SMB2_ACCESS_READEA 0x00000008
#define SMB2_ACCESS_WRITEEA 0x00000010
#define SMB2_ACCESS_EXECUTEEA 0x00000020
#define SMB2_ACCESS_DELETECHILD 0x00000040
#define SMB2_ACCESS_READATTRIBUTES 0x00000080
#define SMB2_ACCESS_WRITEATTRIBUTES 0x00000100
#define SMB2_ACCESS_DELETE 0x00010000
#define SMB2_ACCESS_READCONTROL 0x00020000
#define SMB2_ACCESS_WRITEDAC 0x00040000
#define SMB2_ACCESS_WRITEOWNER 0x00080000
#define SMB2_ACCESS_SYNCHRONIZE 0x00100000
#define SMB2_ACCESS_SYSTEMSEC 0x01000000
#define SMB2_ACCESS_MAXIMUMALLWED 0x02000000
#define SMB2_ACCESS_GENERICALL 0x10000000
#define SMB2_ACCESS_GENERICEXEC 0x20000000
#define SMB2_ACCESS_GENERICWRITE 0x40000000
#define SMB2_ACCESS_GENERICREAD 0x80000000

#define SMB2_FILE_ATTRIB_READONLY 0x00000001
#define SMB2_FILE_ATTRIB_HIDDEN 0x00000002
#define SMB2_FILE_ATTRIB_SYSTEM 0x00000004
#define SMB2_FILE_ATTRIB_DIR 0x00000010
#define SMB2_FILE_ATTRIB_ARCHIVE 0x00000020
#define SMB2_FILE_ATTRIB_NORMAL 0x00000080
#define SMB2_FILE_ATTRIB_TEMPORARY 0x00000100
#define SMB2_FILE_ATTRIB_SPARSE 0x00000200
#define SMB2_FILE_ATTRIB_REPARSE 0x00000400
#define SMB2_FILE_ATTRIB_COMPRESSED 0x00000800
#define SMB2_FILE_ATTRIB_OFFLINE 0x00001000
#define SMB2_FILE_ATTRIB_NOTINDEXED 0x00002000
#define SMB2_FILE_ATTRIB_ENCRYPTED 0x00004000
#define SMB2_FILE_ATTRIB_INTEGRITY 0x00008000
#define SMB2_FILE_ATTRIB_NOSCRUBDATA 0x00020000

#define SMB2_FILE_SHARE_READ 0x00000001
#define SMB2_FILE_SHARE_WRITE 0x00000002
#define SMB2_FILE_SHARE_DELETE 0x00000004

#define SMB2_OPTION_DIRECTORY 0x00000001
#define SMB2_OPTION_WRITETHROUGH 0x00000002
#define SMB2_OPTION_SEQUENTIAL 0x00000004
#define SMB2_OPTION_BUFFERING 0x00000008
#define SMB2_OPTION_SYNCIO 0x00000010
#define SMB2_OPTION_SYNCIONO 0x00000020
#define SMB2_OPTION_NONDIRECTORY 0x00000040
#define SMB2_OPTION_CREATETREE 0x00000080
#define SMB2_OPTION_COMPLETELOCKED 0x00000100
#define SMB2_OPTION_NOEA 0x00000200
#define SMB2_OPTION_8_3 0x00000400
#define SMB2_OPTION_RANDOM 0x00000800
#define SMB2_OPTION_DELETEONCLOSE 0x00001000
#define SMB2_OPTION_OPENBYID 0x00002000
#define SMB2_OPTION_FORBACKUP 0x00004000
#define SMB2_OPTION_NOCOMPESS 0x00008000
#define SMB2_OPTION_OPFILTER 0x00100000
#define SMB2_OPTION_REPARSE 0x00200000
#define SMB2_OPTION_NORECALL 0x00400000
#define SMB2_OPTION_FREESPACEQUERY 0x00800000

#define SMB2_OPLOCK_LEVEL_NONE 0x00			//No oplock is requested.
#define SMB2_OPLOCK_LEVEL_II 0x01 //A level II oplock is requested.
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE 0x08 //An exclusive oplock is requested.
#define SMB2_OPLOCK_LEVEL_BATCH 0x09	//A batch oplock is requested.
#define SMB2_OPLOCK_LEVEL_LEASE 0xFF	//A lease is requested

enum {
	Anonymous=0x00000000,	//The application-requested impersonation level is Anonymous.
	Identification=0x00000001,		// The application-requested impersonation level is Identification.
	Impersonation=0x00000002,	// The application-requested impersonation level is Impersonation.
	Delegate=0x00000003	//The application-requested impersonation level is Delegate.
	};

#define SMB2_FILE_SUPERSEDE 0x00000000		//If the file already exists, supersede it. Otherwise, create the file. This value SHOULD NOT be used for a printer object.<38>
#define SMB2_FILE_OPEN 0x00000001		//If the file already exists, return success; otherwise, fail the operation. MUST NOT be used for a printer object.
#define SMB2_FILE_CREATE 0x00000002	//If the file already exists, fail the operation; otherwise, create the file.
#define SMB2_FILE_OPEN_IF 0x00000003	//Open the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object.<39>
#define SMB2_FILE_OVERWRITE 0x00000004	//Overwrite the file if it already exists; otherwise, fail the operation. MUST NOT be used for a printer object.
#define SMB2_FILE_OVERWRITE_IF 0x00000005		//Overwrite the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object.<40>

#define SMB2_FILE_INFO 1
#define SMB2_FS_INFO 2
#define SMB2_SEC_INFO 3

// per SMB2_FS_FILE_INFO
#define SMB2_FILE_BASIC_INFO 4
#define SMB2_FILE_STANDARD_INFO 5		// ossia Attribute
#define SMB2_FILE_INTERNAL_INFO 6		// 
#define SMB2_FILE_EA_INFO 7
#define SMB2_FILE_ACCESS_INFO 8   
#define SMB2_FILE_RENAME_INFO 0xA
#define SMB2_FILE_DISPOSITION_INFO 0xD
#define SMB2_FILE_POSITION_INFO 0xE
#define SMB2_FILE_INFO_0F 0xF       // FULL_EA
#define SMB2_FILE_MODE_INFO 0x10
#define SMB2_FILE_ALIGNMENT_INFO 0x11
#define SMB2_FILE_ALL_INFO 0x12
#define SMB2_FILE_ALLOCATION_INFO 0x13
#define SMB2_FILE_ENDOFFILE_INFO 0x14
#define SMB2_FILE_ALTERNATE_NAME_INFO 0x15
#define SMB2_FILE_STREAM_INFO 0x16
#define SMB2_FILE_PIPE_INFO 0x17
#define SMB2_FILE_COMPRESSION_INFO 0x1C
#define SMB2_FILE_NETWORK_OPEN_INFO 0x22
#define SMB2_FILE_ATTRIBUTE_TAG_INFO 0x23

// per SMB2_FS_INFO
#define SMB2_FS_VOLUME_INFO 1
#define SMB2_FS_LABEL_INFO 2        // pare non supportato da windows...
#define SMB2_FS_SIZE_INFO 3
#define SMB2_FS_DEVICE_INFO 4
#define SMB2_FS_ATTRIBUTE_INFO 5
#define SMB2_FS_QUOTA_INFO 6		// 
#define SMB2_FS_FULL_SIZE_INFO 7
#define SMB2_FS_OID_INFO 8        // anche ACCESS__INFO

// per SMB2_SEC_INFO
#define SMB2_SEC_INFO_00 0
    

enum {
	FileDirectoryInformation=0x01,		//Basic information of a file or directory. Basic information is defined as the file's name, time stamp, size and attributes. 
	FileFullDirectoryInformation=0x02,	//Full information of a file or directory. Full information is defined as all the basic information plus extended attribute size.
	FileIdFullDirectoryInformation=0x26,	//Full information, plus 64-bit file ID of a file or directory, 
	FileBothDirectoryInformation=0x03,	//Basic information plus extended attribute size and short name of a file or directory.
	FileIdBothDirectoryInformation=0x25,	//FileBothDirectoryInformation plus 64-bit file ID of a file or directory.
	FileNamesInformation=0x0C,	//Detailed information of ONLY the (long)names of files and directories in a directory.
	FileIdExtdDirectoryInformation=0x3C,	//Extended information of a file or directory, including reparse point tag, if any
	FileId64ExtdDirectoryInformation=0x4E,	//Extended information of a file or directory, including a 64-bit file ID and a reparse point tag, if any.
	FileId64ExtdBothDirectoryInformation=0x4F,	//FileBothDirectoryInformation plus 64-bit file ID and a reparse point tag, if any
	FileIdAllExtdDirectoryInformation=0x50,		//FileId64ExtdDirectoryInformation plus a 128-bit file ID.
	FileIdAllExtdBothDirectoryInformation=0x51,		//FileId64ExtdBothDirectoryInformation plus a 128-bit file ID.
	FileInformationClass_Reserved=0x64	//This value MUST be reserved and MUST be ignored on receipt
	};
#define SMB2_RESTART_SCANS 0x01 //The server is requested to restart the enumeration from the beginning as specified in section 3.3.5.18.
#define SMB2_RETURN_SINGLE_ENTRY 0x02 // The server is requested to only return the first entry of the search results.
#define SMB2_INDEX_SPECIFIED 0x04 //The server is requested to return entries beginning at the byte number specified by FileIndex.
#define SMB2_REOPEN 0x10 //The server is requested to restart the enumeration from the beginning, and the search pattern is to be changed to the provided value.

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR Padding;
	UCHAR Flags;
	ULONG Length;
	uint64_t Offset;
	UCHAR FileGUID[16];
	ULONG MinCount;
	ULONG Channel;
	ULONG RemainingBytes;
	ULONG BlobOffset;
	ULONG BlobLength;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
	} SMB2_READFILE;


typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT DataOffset;
	ULONG Length;
	uint64_t Offset;
	UCHAR FileGUID[16];
	ULONG Channel;
	ULONG RemainingBytes;
	USHORT BlobOffset;
	USHORT BlobLength;
	ULONG Flags;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
	} SMB2_WRITEFILE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT Flags;
	ULONG Reserved;		// c'è nei byte di wireshark ma non li mostra...
	UCHAR FileGUID[16];
	} SMB2_CLOSEFILE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT Reserved;
	ULONG Function;
	UCHAR GUID[16];
	ULONG BlobInOffset;
	ULONG BlobInLength;
	ULONG MaxInSize;
	ULONG BlobOutOffset;
	ULONG BlobOutLength;
	ULONG MaxOutSize;
	ULONG Flags;
	ULONG Reserved2;
	USHORT MaxInReferralLevel;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
	} SMB2_IOCTL;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR Class;
	UCHAR InfoLevel;
	ULONG MaxSize;
	USHORT InputOffset;
	USHORT Reserved;
	ULONG InputSize;
	ULONG AdditionalInfo;
	ULONG Flags;
	UCHAR FileGUID[16];
	} SMB2_GETINFO;

typedef struct __attribute__((__packed__)) {
	uint8_t ReplaceIf;
	uint8_t Reserved[7];
	uint64_t RootDirHandle;
	ULONG FilenameLength;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
  } SMB2_FILERENAMEINFO;

typedef struct __attribute__((__packed__)) {
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t FileSize;
	ULONG Attrib;
	ULONG Unknown;		// ...wireshark
  } SMB2_FILEBASICINFO;

typedef struct __attribute__((__packed__)) {
	uint64_t AllocSize;
	uint64_t EOFSize;
	ULONG LinkCount;
    uint8_t DeletePending;
    uint8_t IsDirectory;
	USHORT Unknown;		// ...wireshark
  } SMB2_FILESTANDARDINFO;

typedef struct {
	uint64_t CreateTime;
	ULONG SerialNumber;
	uint32_t LabelLength;
	USHORT Reserved;
	UCHAR Label[  256];		// forse andrebbe dinamico..
  } SMB2_FILEVOLUMEINFO;
  
typedef struct {
	uint64_t AllocSize;
	uint64_t CallerFreeUnits;
	uint64_t ActualFreeUnits;
	ULONG SectorsPerUnit;
	ULONG SectorsSize;
  } SMB2_FILEVOLUMESIZEINFO;
  
typedef struct {
	ULONG Attrib;
	uint32_t MaxLabelLength;
	uint32_t LabelLength;
	UCHAR Label[  256];		// forse andrebbe dinamico..
  } SMB2_FSINFO;
  
typedef struct {
	uint32_t Type;
	uint32_t Attributes;
  } SMB2_FSDEVICEINFO;
  
typedef struct {
	uint8_t boh[24];
	uint64_t Threshold;
	uint64_t Limit;
	uint8_t Flags;
	uint8_t boh2[7];
  }   SMB2_FSQUOTAINFO;
  
typedef struct __attribute__((__packed__)) {
	uint64_t CreationTime;
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t Size;
	uint64_t EOFSize;
	ULONG Attrib;
	ULONG Reserved;
  } SMB2_NETWORKOPENINFO;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR Class;
	UCHAR InfoLevel;
	ULONG InfoSize;
	USHORT InfoOffset;
	USHORT Reserved;
	ULONG AdditionalInfo;
	UCHAR FileGUID[16];
	UCHAR Blob[  256];		// forse andrebbe dinamico..
	} SMB2_SETINFO;

#define SMB2_SETINFO_DELETEONCLOSE 1


typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR Security;
	UCHAR Reserved;		// non c'è, è un pad
	USHORT Dialect;
	USHORT NegotiateContextcount;
	UCHAR ServerGUID[16];
	ULONG Capabilities;
	ULONG MaxTransactionSize;
	ULONG MaxReadSize;
	ULONG MaxWriteSize;
	uint64_t CurrentTime;
	uint64_t BootTime;
	USHORT BlobOffset;
	USHORT BlobLength;
	ULONG NegotiateContextoffset;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
  } SMB2_NEGOTIATE_RESPONSE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT Flags;
	USHORT BlobOffset;
	USHORT BlobLength;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
  } SMB2_OPENSESSION_RESPONSE;

#define SMB2_SESSION_GUEST 0x00000001
#define SMB2_SESSION_NULL 0x00000002
#define SMB2_SESSION_ENCRYPT 0x00000004

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT Reserved;
  } SMB2_CLOSESESSION_RESPONSE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR Type;
	UCHAR Reserved;
	ULONG Flags;
	ULONG Capabilities;
	ULONG AccessMask;
	} SMB2_TREE_CONNECT_RESPONSE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT Reserved;
  } SMB2_TREEDISCONNECT_RESPONSE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT BlobOffset;
	ULONG BlobLength;
//	ULONG RemainingBytes; boh ma ci sono??
//	ULONG Reserved;
	UCHAR Blob[  256];		// v. SMB2_FIND_RESPONSE_INFO
  } SMB2_FIND_RESPONSE;

typedef struct {
	ULONG NextOffset;
	ULONG FileIndex;
	uint64_t CreationTime;
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t EOFSize;
	uint64_t Size;
	ULONG Attrib;
	ULONG FilenameLength;
	uint8_t FileName[  256];		// 
  } SMB2_FIND_RESPONSE_INFO1;		// FileDirectoryInformation
typedef struct {
	ULONG NextOffset;
	ULONG FileIndex;
	uint64_t CreationTime;
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t EOFSize;
	uint64_t Size;
	ULONG Attrib;
	ULONG FilenameLength;
	ULONG EASize;
	uint8_t FileName[  256];		// dinamico/su più pacchetti, basato su Length (unicode) e paddato a 4 o forse 8
  } SMB2_FIND_RESPONSE_INFO2;		// FileFullDirectoryInformation
typedef struct {
	ULONG NextOffset;
	ULONG FileIndex;
	uint64_t CreationTime;
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t EOFSize;
	uint64_t Size;
	ULONG Attrib;
	ULONG FilenameLength;
	ULONG EASize;
	UCHAR Reserved;
	uint64_t FileID;		// SOLO se richiesto! occhio al tipo richiesta, fare diverse struct...
	uint8_t FileName[  256];		// dinamico/su più pacchetti, basato su Length (unicode) e paddato a 4 o forse 8
  } SMB2_FIND_RESPONSE_INFO3;		// FileIdFullDirectoryInformation
typedef struct {
	ULONG NextOffset;
	ULONG FileIndex;
	uint64_t CreationTime;
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t EOFSize;
	uint64_t Size;
	ULONG Attrib;
	ULONG FilenameLength;
	ULONG EASize;
	UCHAR ShortNameLength;
	UCHAR Reserved;
	uint8_t ShortFileName[12*2];		// unicode; anche se richiesto, c'è SOLO se il nome lungo è > 12 char
    // 94 byte fin qua
//	uint64_t FileID;		// SOLO se richiesto! occhio al tipo richiesta, fare diverse struct...
	uint8_t FileName[  256];		// dinamico/su più pacchetti, basato su Length (unicode) e paddato a 4 o forse 8
  } SMB2_FIND_RESPONSE_INFO4;		// FileBothDirectoryInformation; sono 104byte + len(Filename) paddato a 8, ciascuna, v. NextOffset
typedef struct {
	ULONG NextOffset;
	ULONG FileIndex;
	uint64_t CreationTime;
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t EOFSize;
	uint64_t Size;
	ULONG Attrib;
	ULONG FilenameLength;
	ULONG EASize;
	UCHAR ShortNameLength;
	UCHAR Reserved;
	uint8_t ShortFileName[12*2];		// unicode; anche se richiesto, c'è SOLO se il nome lungo è > 12 char
	USHORT Reserved2;
	uint64_t FileID;		// SOLO se richiesto! occhio al tipo richiesta, fare diverse struct...
	uint8_t FileName[  256];		// dinamico/su più pacchetti, basato su Length (unicode) e paddato a 4 o forse 8
  } SMB2_FIND_RESPONSE_INFO5;		// FileIdBothDirectoryInformation
typedef struct {
	ULONG NextOffset;
	ULONG FileIndex;
	ULONG FilenameLength;
	uint8_t FileName[  256];		// dinamico/su più pacchetti, basato su Length (unicode) e paddato a 4 o forse 8
  } SMB2_FIND_RESPONSE_INFO6;		// FileNamesInformation
typedef struct {
	ULONG NextOffset;
	ULONG FileIndex;
	uint64_t CreationTime;
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t EOFSize;
	uint64_t Size;
	ULONG Attrib;
	ULONG FilenameLength;
	ULONG EASize;
	UCHAR ShortNameLength;
	UCHAR Reserved;
	uint8_t ShortFileName[12*2];		// unicode; anche se richiesto, c'è SOLO se il nome lungo è > 12 char
	USHORT Reserved2;
	uint64_t FileID;		// SOLO se richiesto! occhio al tipo richiesta, fare diverse struct...
	uint8_t FileName[  256];		// dinamico/su più pacchetti, basato su Length (unicode) e paddato a 4 o forse 8
  } SMB2_FIND_RESPONSE_INFO7;		// FileIdBothDirectoryInformation NON SI SA , Windows 7 non la supporta... idem FileId64ExtdDirectoryInformation e FileId64ExtdBothDirectoryInformation e FileIdAllExtdDirectoryInformation e FileIdAllExtdBothDirectoryInformation

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR Oplock;
	UCHAR Flags;
	ULONG Action;
	uint64_t CreateTime;
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t FileSize;
	uint64_t EOFSize;
	ULONG Attrib;
	ULONG Reserved;
	UCHAR FileGUID[16];
	ULONG BlobOffset;
	ULONG BlobLength;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
  } SMB2_CREATE_RESPONSE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR BlobOffset;
	UCHAR Reserved2;		// verificare... è strano
	ULONG BlobLength;
	ULONG RemainingBytes;
	ULONG Reserved;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
  } SMB2_READ_RESPONSE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT Reserved;
	ULONG Count;
	ULONG RemainingBytes;
	USHORT ChannelInfoOffset;
	USHORT ChannelInfoLength;
  } SMB2_WRITE_RESPONSE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT Flags;
	ULONG Reserved;
	uint64_t CreationTime;
	uint64_t AccessTime;
	uint64_t WriteTime;
	uint64_t ModifiedTime;
	uint64_t FileSize;
	uint64_t EOFSize;
	ULONG Attrib;
  } SMB2_CLOSE_RESPONSE;

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	UCHAR ErrorCount;
	UCHAR Reserved;
	ULONG Count;
	UCHAR ErrorData;
  } SMB2_IOCTL_RESPONSE;

#define FSCTL_CREATE_GET_OID 0x000900c0
#define FSCTL_CREATE_GET_REPARSEPOINT 0x000900a8


typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT BlobOffset;
	ULONG BlobLength;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
  } SMB2_GETINFO_RESPONSE;			// dipende dal tipo di Info richiesta...

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT BlobOffset;
	ULONG BlobLength;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
  } SMB2_SETINFO_RESPONSE;			// dipende dal tipo di Info impostata...

typedef struct __attribute__((__packed__)) {
	union __attribute__((__packed__)) {
		struct __attribute__((__packed__)) {
			unsigned short dynamicPart:1;
			unsigned short fixedPart:15;
			};
		USHORT size;
		} Size;
	USHORT BlobOffset;
	ULONG BlobLength;
	UCHAR Blob[  256];		// forse andrebbe dinamico..
  } SMB2_LOGOFF_RESPONSE;


typedef struct __attribute__((__packed__)) {
	USHORT Length;
	UCHAR Data[1/*Length*/];
  } SMB_RESPONSE;


typedef struct __attribute__((__packed__)) {
  USHORT Day : 5;
  USHORT Month : 4;
  USHORT Year : 7;
	} SMB_DATE;
//The Year field has a range of 0-119, which represents years 1980 - 2099.  The Month is encoded as 1-12, and the day ranges from 1-31.

typedef struct __attribute__((__packed__)) {
  USHORT TwoSeconds : 5;
  USHORT Minutes : 6;
  USHORT Hours : 5;
	} SMB_TIME;
//Hours ranges from 0-23, Minutes range from 0-59, and TwoSeconds ranges from 0-29 representing two second increments within the minute.


enum __attribute__((__packed__)) {
    HintNameTag = 0xA0,
    NegStateTag = 0xA0,
    HintAddressTag = 0xA1,
    NegTokenRespTag = 0xA1,
    SupportedMechanismTag = 0xA1,
    ResponseTokenTag = 0xA2,
    NegHintsTag = 0xA3,
    MechanismListMICTag = 0xA3
// dipende...!    MechanismListMICTag = 0xA4,
    };
// 06 -- identifier octet for primitive OBJECT IDENTIFIER, segue dim.
// A0 -- identifier octet for constructed [0]
// 30 -- identifier octet for constructed SEQUENCE
typedef struct __attribute__((__packed__)) {
    uint8_t type;
    uint8_t dim;
    } ITU_ID;
    
enum __attribute__((__packed__)) NEGSTATE {
    AcceptCompleted = 0x00,
    AcceptIncomplete = 0x01,
    Reject = 0x02,
    RequestMic = 0x03
    };
typedef struct __attribute__((__packed__)) {
    ITU_ID  hdr;     // 60 28
    ITU_ID  oi1;    // 06 06
    uint8_t OID[6];     // SPNEGO 2b 06 01 05 05 02
    uint8_t boh3[2];    // a0 1e  (06 0a
    uint8_t boh4[6];    // 30 1c a0 1a0 30 18
    ITU_ID  mt1;    // 06 0a
    uint8_t mechType1[10];     // 2b 06 01 04 01 82 37 02 02 1e
    ITU_ID  mt2;    // 06 0a
    uint8_t mechType2[10];     // 2b 06 01 04 01 82 37 02 02 0a
	} NEG_TOKEN_RESPONSE;		// =len 42 in BlobLength
    
typedef struct __attribute__((__packed__)) {
	ITU_ID  hdr;		// boh 60 48 06 06
    ITU_ID  oi1;        // 06 06
	uint8_t OID[6];		// boh SPNEGO 2b 06 01 05 05 02
	uint8_t boh[2];			// boh a0 3e
	uint8_t boh2[6];			// boh 30 3c a0 0e 30 0c
	ITU_ID  mt;			// boh 06 0a
	uint8_t mechType[10];		//  1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)  2b 06 01 04 01 82 37 02 02 0a
	uint8_t boh4[4];			// boh a2 2a 04 28
	char id[8];				// NTLMSSP<0>
	uint32_t messageType;		// 1=NTLMSSP_NEGOTIATE
	uint32_t negotiateFlags;		// e2088297
	uint16_t lenCallingdomain;
	uint16_t maxlenCallingdomain;
	uint32_t ofsCallingdomain;
	uint16_t lenCallingname;
	uint16_t maxlenCallingname;
	uint32_t ofsCallingname;
	uint8_t versionMaj;		// major[1], minor[1], build[2], NTLMrev[4]
	uint8_t versionMin;
	uint16_t versionBuild;
	uint8_t versionUnused[3];
	uint8_t versionNTLMrev;
	} NEG_TOKEN_INIT;

typedef struct __attribute__((__packed__)) {
	uint8_t hdr[3];		// boh a1 81 99
	uint8_t hdr2[7];		// boh 30 81 96 a0 03 0a 01
	uint8_t negResult;	// 1 = incomplete
	uint8_t boh[4];			// boh a2 7b 04 79
	char id[8];				// NTLMSSP<0>
	uint32_t messageType;		// 3=NTLMSSP_AUTH; 2=CHALLENGE
	uint16_t lenLMResponse;
	uint16_t maxlenLMResponse;
	uint32_t ofsLMResponse;
	uint16_t lenNTResponsename;
	uint16_t maxlenNTResponsename;
	uint32_t ofsNTResponsename;
	uint16_t lenDomainname;
	uint16_t maxlenDomainname;
	uint32_t ofsDomainname;
	uint16_t lenUsername;
	uint16_t maxlenUsername;
	uint32_t ofsUsername;
	uint16_t lenHostname;
	uint16_t maxlenHostname;
	uint32_t ofsHostname;
	uint16_t lenSessionkey;
	uint16_t maxlenSessionkey;
	uint32_t ofsSessionkey;
	uint32_t negotiateFlags;		// e2888a15 
//	uint8_t NTLMchallenge[16];		// 
//	uint8_t reserved[16];		// 
	uint8_t versionMaj;		// major[1], minor[1], build[2], NTLMrev[4]
	uint8_t versionMin;
	uint16_t versionBuild;
	uint8_t versionUnused[3];
	uint8_t versionNTLMrev;
	uint8_t MIC[16];		// 
	uint8_t hostname[16];		// ovviamente v.sopra
//	uint8_t username[10];		// provare v.sopra
	uint8_t lmresponse;		// 
	uint8_t key[16];		// idem v.sopra
//	uint8_t mechListMIC[10];		// 
	uint8_t boh2[4];			// boh a3 12 04 10
	uint32_t verifierVersionNumber;			// 
	uint8_t verifierBody[12];		// 
	} NEG_TOKEN_TARG2;		// in risposta

enum {
    MsvAvEOL=0x0000,     //Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
    MsvAvNbComputerName=0x0001,  //The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
    MsvAvNbDomainName=0x0002, //The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
    MsvAvDnsComputerName=0x0003, //The fully qualified domain name (FQDN) of the computer. The name MUST be in Unicode, and is not null-terminated.
    MsvAvDnsDomainName=0x0004,  //The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
    MsvAvDnsTreeName=0x0005,  //The FQDN of the forest. The name MUST be in Unicode, and is not null-terminated.<13>
    MsvAvFlags=0x0006,  //A 32-bit value indicating server or client configuration.
        //0x00000001: Indicates to the client that the account authentication is constrained.
        //0x00000002: Indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.<14>
        //0x00000004: Indicates that the client is providing a target SPN generated from an untrusted source.<15>
    MsvAvTimestamp=0x0007,  //A FILETIME structure ([MS-DTYP] section 2.3.3) in little-endian byte order that contains the server local time. This structure is always sent in the CHALLENGE_MESSAGE.<16>
    MsvAvSingleHost=0x0008, //A Single_Host_Data (section 2.2.2.2) structure. The Value field contains a platform-specific blob, as well as a MachineID created at computer startup to identify the calling machine.<17>
    MsvAvTargetName=0x0009, //The SPN of the target server. The name MUST be in Unicode and is not null-terminated.<18>
    MsvAvChannelBindings=0x000A
    };
typedef struct __attribute__((__packed__)) {
	uint8_t hdr[3];		// boh a1 81 b0
	uint8_t hdr2[7];		// boh 30 81 ad a0 03 0a 01
	uint8_t negResult;	// 1 = incomplete
	uint8_t boh[2];			// boh a1 0c
    ITU_ID  smt;            // 06 0a
	uint8_t supportedMech[10];		// 1.3.6.1.4.1.311.2.2.10 (NTLMSSP - Microsoft NTLM Security Support Provider)  2b 06 01 04 01 82 37 02 02 0a
	uint8_t boh2[6];			// boh a2 81 97 04 81 94
	char id[8];				// NTLMSSP<0>
	uint32_t messageType;		// 2=NTLMSSP_CHALLENGE
	uint16_t lenName;
	uint16_t maxlenName;
	uint32_t ofsName;
	uint32_t negotiateFlags;		// e28a8a15 
    uint64_t NTLMchallenge;
	uint64_t reserved;
	uint16_t lenInfo;
	uint16_t maxlenInfo;
	uint32_t ofsInfo;
	uint8_t versionMaj;		// major[1], minor[1], build[2], NTLMrev[4]
	uint8_t versionMin;
	uint16_t versionBuild;
	uint8_t versionUnused[3];
	uint8_t versionNTLMrev;
    uint8_t info[12];		// in effetti è dinamico basato v. lenInfo...
	struct __attribute__((__packed__)) {        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
		uint16_t type;
		uint16_t length;
		uint8_t name[12];		// in effetti è dinamico basato su length...
		} attribute[6];
	} SESS_TOKEN_TARG;			// FINIRE

typedef struct __attribute__((__packed__)) {
	ITU_ID  hdr;		// boh a1 1b;  se guest  a1 07
	uint8_t hdr2[6];		// boh 30 19 a0 03 0a 01;  se guest 30 05 a0 03 0a 01
	uint8_t negResult;	// 0 = accept complete
	uint8_t boh[4];		// boh a3 12 04 10 
	uint32_t verifierVersionNumber;
	uint8_t verifierBody[12];   // 23 61 4e e4 c4 ff 33 79 00 00 00 00
	} SESS_TOKEN_TARG2;		// in conferma dal server

    
/* Negotiate Flags */
#define NTLMSSP_NEGOTIATE_56                        (1U << 31)		//
#define NTLMSSP_NEGOTIATE_KEY_EXCH                  (1U << 30)
#define NTLMSSP_NEGOTIATE_128                       (1U << 29)
#define UNUSED_R1                                   (1U << 28)
#define UNUSED_R2                                   (1U << 27)
#define UNUSED_R3                                   (1U << 26)
#define NTLMSSP_NEGOTIATE_VERSION                   (1U << 25)
#define UNUSED_R4                                   (1U << 24)
#define NTLMSSP_NEGOTIATE_TARGET_INFO               (1U << 23)		//
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY          (1U << 22)
#define UNUSED_R5 /* Davenport: NEGOTIATE_ACCEPT */ (1U << 21)
#define NTLMSSP_NEGOTIATE_IDENTIFY                  (1U << 20)
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY  (1U << 19)
#define UNUSED_R6 /* Davenport:TARGET_TYPE_SHARE */ (1U << 18)
#define NTLMSSP_TARGET_TYPE_SERVER                  (1U << 17)
#define NTLMSSP_TARGET_TYPE_DOMAIN                  (1U << 16)
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN               (1U << 15)		//
#define UNUSED_R7 /* Davenport:LOCAL_CALL */        (1U << 14)
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED  (1U << 13)
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED       (1U << 12)
#define NTLMSSP_ANONYMOUS                           (1U << 11)
#define UNUSED_R8                                   (1U << 10)
#define NTLMSSP_NEGOTIATE_NTLM                      (1U << 9)
#define UNUSED_R9                                   (1U << 8)
#define NTLMSSP_NEGOTIATE_LM_KEY                    (1U << 7)		//
#define NTLMSSP_NEGOTIATE_DATAGRAM                  (1U << 6)
#define NTLMSSP_NEGOTIATE_SEAL                      (1U << 5)
#define NTLMSSP_NEGOTIATE_SIGN                      (1U << 4)
#define UNUSED_R10                                  (1U << 3)
#define NTLMSSP_REQUEST_TARGET                      (1U << 2)
#define NTLMSSP_NEGOTIATE_OEM                       (1U << 1)
#define NTLMSSP_NEGOTIATE_UNICODE                   (1U << 0)

/* (2.2.2.10 VERSION) */
#define WINDOWS_MAJOR_VERSION_5 0x05
#define WINDOWS_MAJOR_VERSION_6 0x06
#define WINDOWS_MAJOR_VERSION_10 0x0A
#define WINDOWS_MINOR_VERSION_0 0x00
#define WINDOWS_MINOR_VERSION_1 0x01
#define WINDOWS_MINOR_VERSION_2 0x02
#define WINDOWS_MINOR_VERSION_3 0x03
#define NTLMSSP_REVISION_W2K3 0x0F

#define NTLMSSP_VERSION_MAJOR WINDOWS_MAJOR_VERSION_6
#define NTLMSSP_VERSION_MINOR WINDOWS_MINOR_VERSION_2
#define NTLMSSP_VERSION_BUILD 0
#define NTLMSSP_VERSION_REV NTLMSSP_REVISION_W2K3

#define NTLM_NEGOTIATE_MESSAGE       0x00000001
#define NTLM_CHALLENGE_MESSAGE       0x00000002
#define NTLM_AUTHENTICATE_MESSAGE    0x00000003



#define NBSS_SESSION_MESSAGE 0x00
#define NBSS_SESSION_REQUEST 0x81
#define NBSS_POSITIVE_SESSION_RESPONSE 0x82
#define NBSS_NEGATIVE_SESSION_RESPONSE 0x83


    
//Manager name Code Description Status Earliest dialect
#define SMB_COM_CREATE_DIRECTORY 0x00			//(section 2.2.4.1)
//SMBmkdir		Create a new directory.	D	
//CORE

#define SMB_COM_DELETE_DIRECTORY 0x01			//(section 2.2.4.2)
//SMBrmdir  Delete an empty directory. C 
//CORE

#define SMB_COM_OPEN 0x02		//(section 2.2.4.3)
//SMBopen  Open a file. D 
//CORE

#define SMB_COM_CREATE 0x03		//(section 2.2.4.4)
//SMBcreate  Create or open a file. D 
//CORE

#define SMB_COM_CLOSE 0x04			//(section 2.2.4.5)
//SMBclose  Close a file. C 
//CORE

#define SMB_COM_FLUSH 0x05			//(section 2.2.4.6)
//SMBflush  Flush data for a file, or all files associated with a client, PID pair. C 
//CORE

#define SMB_COM_DELETE 0x06		//(section 2.2.4.7)
//SMBunlink  Delete a file. C 
//CORE

#define SMB_COM_RENAME 0x07		//(section 2.2.4.8)
//SMBmv  Rename a file or set of files. C 
//CORE

#define SMB_COM_QUERY_INFORMATION 0x08		//(section 2.2.4.9)
//SMBgetattr  Get file attributes. D 
//CORE

#define SMB_COM_SET_INFORMATION 0x09			//(section 2.2.4.10)
//SMBsetattr  Set file attributes. D 
//CORE

#define SMB_COM_READ 0x0A		//(section 2.2.4.11)
//SMBread  Read from a file. D 
//CORE

#define SMB_COM_WRITE 0x0B		//(section 2.2.4.12)
//SMBwrite  Write to a file. D 
//CORE

#define SMB_COM_LOCK_BYTE_RANGE 0x0C		//(section 2.2.4.13)
//SMBlock  Request a byte-range lock on a file. D 
//CORE

#define SMB_COM_UNLOCK_BYTE_RANGE 0x0D			//(section 2.2.4.14)
//SMBunlock  Release a byte-range lock on a file. D 
//CORE

#define SMB_COM_CREATE_TEMPORARY 0x0E			//(section 2.2.4.15)
//SMBctemp  Create a temporary file. O 
//CORE

#define SMB_COM_CREATE_NEW 0x0F		//(section 2.2.4.16)
//SMBmknew  Create and open a new file. D 
//CORE

#define SMB_COM_CHECK_DIRECTORY 0x10		//(section 2.2.4.17)
//SMBchkpth  Verify that the specified pathname resolves to a directory.Listed as SMBchkpath in some documentation. C 
//CORE

#define SMB_COM_PROCESS_EXIT 0x11		//(section 2.2.4.18)
//SMBexit  Indicate process exit. O 
//CORE

#define SMB_COM_SEEK 0x12		//(section 2.2.4.19)
//SMBlseek  Set the current file pointer within a file. O 
//CORE

#define SMB_COM_LOCK_AND_READ 0x13		//(section 2.2.4.20)
//SMBlockread Lock and read a byte-range within a file. D 
//CorePlus

#define SMB_COM_WRITE_AND_UNLOCK 0x14		//(section 2.2.4.21)
//SMBwriteunlock  Write and unlock a byte-range within a file. D 
//CorePlus

//Unused
//0x15..0x19

#define SMB_COM_READ_RAW 0x1A		//(section 2.2.4.22)
//SMBreadBraw Read a block in raw mode. D 
//CorePlus

#define SMB_COM_READ_MPX 0x1B		//(section 2.2.4.23)
//SMBreadBmpx Multiplexed block read. Listed as SMBreadmpx in some documentation. O
//LANMAN 1.0

        
  //      NT LAN Manager name and pre-NT LAN
//Manager name	Code	Description	Status	Earliest dialect

#define SMB_COM_READ_MPX_SECONDARY 0x1C		//(section 2.2.4.24)
//SMBreadBs Multiplexed block read,secondary request. X
//LANMAN 1.0

#define SMB_COM_WRITE_RAW 0x1D		//(section 2.2.4.25)
//SMBwriteBraw Write a block in raw mode. D
//CorePlus

#define SMB_COM_WRITE_MPX 0x1E		//(section 2.2.4.26)
//SMBwriteBmpx Multiplexed block write. O
//LANMAN 1.0

#define SMB_COM_WRITE_MPX_SECONDARY 0x1F		//(section2.2.4.27)
//SMBwriteBs Multiplexed block write, secondary request. X
//LANMAN 1.0

#define SMB_COM_WRITE_COMPLETE 0x20		//(section 2.2.4.28)
//SMBwriteC  Raw block write, final response. D
//LANMAN 1.0

#define SMB_COM_QUERY_SERVER 0x21		//(section 2.2.4.29)
//Reserved, but not implemented. Also known as SMB_COM_QUERY_INFORMATION_SRV.
//N

#define SMB_COM_SET_INFORMATION2 0x22		//(section 2.2.4.30)
//SMBsetattrE Set an extended set of file attributes. D
//LANMAN 1.0

#define SMB_COM_QUERY_INFORMATION2 0x23		//(section 2.2.4.31)
//SMBgetattrE Get an extended set of file attributes. D
//LANMAN 1.0

#define SMB_COM_LOCKING_ANDX 0x24		//(section 2.2.4.32)
//SMBlockingX Lock multiple byte ranges; AndX chaining. C
//LANMAN 1.0

#define SMB_COM_TRANSACTION 0x25		//(section 2.2.4.33)
//SMBtrans Transaction. C
//LANMAN 1.0

#define SMB_COM_TRANSACTION_SECONDARY 0x26		//(section 2.2.4.34)
//SMBtranss Transaction secondary request. C
//LANMAN 1.0

#define SMB_COM_IOCTL 0x27		//(section 2.2.4.35)
//SMBioctl Pass an I/O Control function request to the server. O
//LANMAN 1.0

#define SMB_COM_IOCTL_SECONDARY 0x28		//(section 2.2.4.36)
//SMBioctls IOCTL secondary request. N
//LANMAN 1.0

#define SMB_COM_COPY 0x29		//(section 2.2.4.37)
//SMBcopy Copy a file or directory. X
//LANMAN 1.0

#define SMB_COM_MOVE 0x2A		//(section 2.2.4.38)
//SMBmove Move a file or directory. X
//LANMAN 1.0

#define SMB_COM_ECHO 0x2B		//(section 2.2.4.39)
//SMBecho Echo request (ping). C
//LANMAN 1.0

        
  //      NT LAN Manager name and pre-NT LAN

//Manager name	Code	Description	Status	Earliest dialect


#define SMB_COM_WRITE_AND_CLOSE 0x2C		//(section 2.2.4.40)
//SMBwriteclose Write to and close a file. D
//LANMAN 1.0

#define SMB_COM_OPEN_ANDX 0x2D		//(section 2.2.4.41)
//SMBopenX Extended file open with AndX chaining. D
//LANMAN 1.0

#define SMB_COM_READ_ANDX 0x2E		//(section 2.2.4.42)
//SMBreadX Extended file read with AndX chaining. C
//LANMAN 1.0

#define SMB_COM_WRITE_ANDX 0x2F		//(section 2.2.4.43)
//SMBwriteX Extended file write with AndX chaining. C
//LANMAN 1.0

#define SMB_COM_NEW_FILE_SIZE 0x30		//(section 2.2.4.44)
//Reserved, but not implemented.Also known as SMB_COM_SET_NEW_SIZE. N

#define SMB_COM_CLOSE_AND_TREE_DISC 0x31		//(section 2.2.4.45)
//Close an open file and tree disconnect. N
//NT LANMAN

#define SMB_COM_TRANSACTION2 0x32		//(section 2.2.4.46)
//SMBtrans2 Transaction 2 format request/response. C
//LANMAN 1.2

#define SMB_COM_TRANSACTION2_SECONDARY 0x33		//(section 2.2.4.47)
//SMBtranss2 Transaction 2 secondary request. C
//LANMAN 1.2

#define SMB_COM_FIND_CLOSE2 0x34		//(section 2.2.4.48)
//SMBfindclose Close an active search. C
//LANMAN 1.2

#define SMB_COM_FIND_NOTIFY_CLOSE 0x35		//(section 2.2.4.49)
//SMBfindnclose Notification of the closure of an active search. N
//LANMAN 1.2

//Unused
//0x36...0x5F

//Reserved
//0x60...0x6F

/*This range of codes was reserved for use by the "xenix1.1" dialect of SMB. See [MSFT-XEXTNP]. [XOPEN-SMB]
page 41 lists this range as "Reserved for proprietary dialects." X */
//XENIX

#define SMB_COM_TREE_CONNECT 0x70		//(section 2.2.4.50)
//SMBtcon Tree connect. D
//CORE

#define SMB_COM_TREE_DISCONNECT 0x71		//(section 2.2.4.51)
//SMBtdis Tree disconnect. C
//CORE

#define SMB_COM_NEGOTIATE 0x72		//(section 2.2.4.52)
//Negotiate protocol dialect. C
//CORE

    
typedef struct __attribute__((__packed__)) {
    UCHAR WordCount;
    USHORT ByteCount;
    UCHAR  Buffer[1 /*ByteCount*/];		// il primo byte è sempre 0x02 poi segue stringa char 0-term
	} SMB_NEGOTIATE_PROTOCOL;
    


#define SMB2_COM_NEGOTIATE 0x0000		//
//Negotiate protocol dialect. C
//SMB2

#define SMB2_COM_OPENSESSION 0x0001		//
//Start session. C
//SMB2

#define SMB2_COM_ENDSESSION 0x0002		//
//End session. C
//SMB2

#define SMB2_COM_TREECONNECT 0x0003		//
//open tree. C
//SMB2

#define SMB2_COM_TREEDISCONNECT 0x0004		//
//close tree. C
//SMB2

#define SMB2_COM_CREATE 0x0005		//
//create file  C
//SMB2

#define SMB2_COM_CLOSE 0x0006		//
//close file  C
//SMB2

#define SMB2_COM_FLUSH 0x0007		//
//flush C
//SMB2

#define SMB2_COM_READ 0x0008		//
//read file  C
//SMB2

#define SMB2_COM_WRITE 0x0009		//
//write file  C
//SMB2

#define SMB2_COM_LOCK 0x000A		//
//lock  C
//SMB2

#define SMB2_COM_IOCTL 0x000B		//
//ioctl  C
//SMB2

#define SMB2_COM_CANCEL 0x000C		//
//cancel C
//SMB2

#define SMB2_COM_KEEPALIVE 0x000D		//
//keep alive C
//SMB2

#define SMB2_COM_FIND 0x000E		//
//find C
//SMB2

#define SMB2_COM_NOTIFY 0x000F		//
//notify  C
//SMB2

#define SMB2_COM_GETINFO 0x0010		// QueryInfo in MS SMB2...
//get info  C
//SMB2

#define SMB2_COM_SETINFO 0x0011		//
//set info  C
//SMB2

#define SMB2_COM_BREAK 0x0012		//
//break C
//SMB2



//NT LAN Manager name and pre-NT LAN


//Manager name	Code	Description	Status	Earliest dialect

//SMBnegprot

#define SMB_COM_SESSION_SETUP_ANDX 0x73		//(section 2.2.4.53)
//SMBsesssetupX Session Setup with AndX chaining. C
//LANMAN 1.0

#define SMB_COM_LOGOFF_ANDX 0x74		//(section 2.2.4.54)
//SMBulogoffX User logoff with AndX chaining. C
//LANMAN 1.2

#define SMB_COM_TREE_CONNECT_ANDX 0x75		//(section 2.2.4.55)
//SMBtconX Tree connect with AndX chaining. C
//LANMAN 1.0

//Unused
//0x76...0x7D

#define SMB_COM_SECURITY_PACKAGE_ANDX 0x7E		//(section 2.2.4.56)
//SMBsecpkgX Negotiate security packages with AndX chaining. X
//LANMAN 1.0

//Unused
//0x7F

#define SMB_COM_QUERY_INFORMATION_DISK 0x80		//(section 2.2.4.57)
//SMBdskattr Retrieve file system information from the server. D
//CORE

#define SMB_COM_SEARCH 0x81		//(section 2.2.4.58)
//SMBsearch Directory wildcard search. D
//CORE

#define SMB_COM_FIND 0x82		//(section 2.2.4.59)
//SMBffirst Start or continue an extended wildcard directory search. D
//LANMAN 1.0

#define SMB_COM_FIND_UNIQUE 0x83		//(section 2.2.4.60)
//SMBfunique Perform a one-time extended wildcard directory search. D
//LANMAN 1.0

#define SMB_COM_FIND_CLOSE 0x84		//(section 2.2.4.61)
//SMBfclose End an extended wildcard directory search. D
//LANMAN 1.0

//Unused
//0x85...0x9F

#define SMB_COM_NT_TRANSACT 0xA0		//(section 2.2.4.62)
//NT format transaction request/response. C
//NT LANMAN

#define SMB_COM_NT_TRANSACT_SECONDARY 0xA1		//(section 2.2.4.63) 
//NT format transaction secondary request. C
//NT LANMAN

#define SMB_COM_NT_CREATE_ANDX 0xA2		//(section 2.2.4.64) 
//Create or open a file or a directory. C
//NT LANMAN

//Unused
//0xA3


//NT LAN Manager name and pre-NT LAN

//Manager name	Code	Description	Status	Earliest dialect


#define SMB_COM_NT_CANCEL 0xA4		//(section 2.2.4.65) 
//Cancel a request currently pending at the server. C
//NT LANMAN

#define SMB_COM_NT_RENAME 0xA5		//(section 2.2.4.66) 
//File rename with extended semantics. O
//NT LANMAN

//Unused
//0xA6...0xBF

#define SMB_COM_OPEN_PRINT_FILE 0xC0		//(section 2.2.4.67)
//SMBsplopen Create a print queue spool file. C
//CORE

#define SMB_COM_WRITE_PRINT_FILE 0xC1		//(section 2.2.4.68)
//SMBsplwr Write to a print queue spool file. D
//CORE

#define SMB_COM_CLOSE_PRINT_FILE 0xC2		//(section 2.2.4.69)
//SMBsplclose Close a print queue spool file. D
//CORE

#define SMB_COM_GET_PRINT_QUEUE 0xC3		//(section 2.2.4.70) 
//SMBsplretq Request print queue information. X
//CORE

//Unused
//0xC4...0xCF

//Reserved
//0xD0...0xD7


/*Messenger Service command codes.
This range is reserved for use by the SMB Messenger Service.
See [MS-MSRP], and section 6 of [SMB-CORE].
O
CORE*/

#define SMB_COM_READ_BULK 0xD8		//(section 2.2.4.71) 
//Reserved, but not implemented. N

#define SMB_COM_WRITE_BULK 0xD9		//(section 2.2.4.72) 
//Reserved, but not implemented. N

#define SMB_COM_WRITE_BULK_DATA 0xDA		//(section 2.2.4.73) 
//Reserved, but not implemented.N

//Unused
//0xDB...0xFD


//Manager name	Code	Description	Status	Earliest dialect

#define SMB_COM_INVALID 0xFE		//(section 2.2.4.74) 
//SMBinvalid As the name suggests, this command code is a designated invalid command and SHOULD NOT be used. C
//LANMAN 1.0

#define SMB_COM_NO_ANDX_COMMAND 0xFF		//(section 2.2.4.75) 




//2.2.2.2 Transaction Subcommand Codes
//Transaction Codes used with SMB_COM_TRANSACTION (section 2.2.4.46):

//Name	Code	Description	Status	Earliest dialect

#define TRANS_MAILSLOT_WRITE 0x0001		//(section 2.2.5.12) 
//Allows a client to write data to a specific mailslot on the server. C
//LANMAN1.0

#define TRANS_SET_NMPIPE_STATE 0x0001		//(section 2.2.5.1) 
//Used to set the read mode and non-blocking mode of a specified named pipe. C
//LANMAN1.0

#define TRANS_RAW_READ_NMPIPE 0x0011		//(section 2.2.5.2) 
//Allows for a raw read of data from a named pipe. This method of reading data from a named pipe
//ignores message boundaries even if the pipe was set up as a message mode pipe. D
//LANMAN1.0

#define TRANS_QUERY_NMPIPE_STATE 0x0021		//(section 2.2.5.3) 
//Allows for a client to retrieve information about a specified named pipe. C
//LANMAN1.0

#define TRANS_QUERY_NMPIPE_INFO 0x0022		//(section 2.2.5.4) 
//Used to retrieve pipe information about a named pipe. C
//LANMAN1.0

#define TRANS_PEEK_NMPIPE 0x0023		//(section 2.2.5.5) 
//Used to copy data out of a named pipe without removing it from the named pipe. C
//LANMAN1.0

#define TRANS_TRANSACT_NMPIPE 0x0026		//(section 2.2.5.6) 
//Used to execute a transacted exchange against a named pipe. This transaction has a constraint that it can be used only on a duplex, message-type pipe. C
//LANMAN1.0
#define TRANS_RAW_WRITE_NMPIPE 0x0031		//(section 2.2.5.7) 
//Allows for a raw write of data to a named pipe. Raw writes to named pipes put bytes directly into a pipe, regardless of whether it is a message mode pipe or byte mode pipe. D
//LANMAN1.0

        
//        Name	Code	Description	Status	Earliest dialect



#define TRANS_READ_NMPIPE 0x0036		//(section 2.2.5.8) 
//Allows a client to read data from a named pipe. C
//NT LANMAN

#define TRANS_WRITE_NMPIPE 0x0037		//(section 2.2.5.9) 
//Allows a client to write data to a named pipe. C
//NT LANMAN

#define TRANS_WAIT_NMPIPE 0x0053		//(section 2.2.5.10) 
//Allows a client to be notified when the specified named pipe is available to be connected to. C
//LANMAN1.0

#define TRANS_CALL_NMPIPE 0x0054		//(section 2.2.5.11) 
//Connect to a named pipe, issue a write to the named pipe, issue a read from the named pipe, and close the named pipe. C
//LANMAN1.0

/*The meaning of the SMB_COM_TRANSACTION subcommand codes is defined by the resource being
accessed. For example, the 0x0001 subcommand code is interpreted as TRANS_MAILSLOT_WRITE if
the operation is being performed on a mailslot. The same code is interpreted as a
TRANS_SET_NMPIPE_STATE (section 2.2.5.1) if the operation is performed on a named pipe.
Transaction Codes used with SMB_COM_TRANSACTION2 (section 2.2.4.46):*/


//Name	Code	Description	Status	Earliest dialect

#define TRANS2_OPEN2 0x0000		//(section 2.2.6.1) 
//Open or create a file and set extended attributes on the file. C
//NT LANMAN

#define TRANS2_FIND_FIRST2 0x0001		//(section 2.2.6.2) 
//Begin a search for files within a directory or for a directory. C
//NT LANMAN

#define TRANS2_FIND_NEXT2 0x0002		//(section 2.2.6.3) 
//Continue a search for files within a directory or for a directory. C
//NT LANMAN

#define TRANS2_QUERY_FS_INFORMATION 0x0003		//(section 2.2.6.4) 
//Request information about a file system on the server. C
//LANMAN2.0

#define TRANS2_SET_FS_INFORMATION 0x0004		//(section 2.2.6.5) 
//N
//LANMAN2.0
#define TRANS2_QUERY_PATH_INFORMATION 0x0005		//(section 2.2.6.6) 
//Get information about a specific file or directory  C
//LANMAN2.0

        
//        Name	Code	Description	Status	Earliest	dialect using a path.

#define TRANS2_SET_PATH_INFORMATION 0x0006		//(section 2.2.6.7) 
//Set the standard and extended attribute information of a specific file or directory using a path. C
//LANMAN2.0
#define TRANS2_QUERY_FILE_INFORMATION 0x0007		//(section 2.2.6.8) 
//Get information about a specific file or directory using a FID. C
//LANMAN2.0

#define TRANS2_SET_FILE_INFORMATION 0x0008		//(section 2.2.6.9) 
//Set the standard and extended attribute information of a specific file or directory using a FID. C
//LANMAN2.0

#define TRANS2_FSCTL 0x0009		//(section 2.2.6.10) 
//N
//LANMAN2.0

#define TRANS2_IOCTL2 0x000a		//(section 2.2.6.11) 
//N
//NT LANMAN

#define TRANS2_FIND_NOTIFY_FIRST 0x000b		//(section 2.2.6.12) 
//X
//LANMAN2.0

#define TRANS2_FIND_NOTIFY_NEXT 0x000c		//(section 2.2.6.13) 
//X
//LANMAN2.0

#define TRANS2_CREATE_DIRECTORY 0x000d		//(section 2.2.6.14) 
//Create a new directory and optionally set the extended attribute information. C
//LANMAN2.0

#define TRANS2_SESSION_SETUP 0x000e		//(section 2.2.6.15) 
//N
//NT LANMAN

#define TRANS2_GET_DFS_REFERRAL 0x0010		//(section 2.2.6.16) 
//Request a DFS referral for a file or directory.
//See [MS-DFSC] section 2.2.2 for details.
//C
//NT LANMAN

#define TRANS2_REPORT_DFS_INCONSISTENCY 0x0011		//(section 2.2.6.17) 
//N
//NT LANMAN


//Transaction codes used with SMB_COM_NT_TRANSACT (section 2.2.4.62):


//Name	Code	Description	Status	Earliest	dialect

#define NT_TRANSACT_CREATE 0x0001		//(section 2.2.7.1) 
//Used to create or open a file or directory when extended attributes (EAs) or a security descriptor (SD) are to be applied. C
//NT LANMAN


//Name	Code	Description	Status	Earliest	dialect

#define NT_TRANSACT_IOCTL 0x0002		//(section 2.2.7.2) 
//Allows device and file system control functions to be transferred transparently from client to server. C
//NT LANMAN

#define NT_TRANSACT_SET_SECURITY_DESC 0x0003		//(section 2.2.7.3) 
//Allows a client to change the security descriptor for a file. C
//NT LANMAN

#define NT_TRANSACT_NOTIFY_CHANGE 0x0004		//(section 2.2.7.4) 
//Notifies the client when the directory specified by FID is modified. It also returns the names of any files that changed. C
//NT LANMAN

#define NT_TRANSACT_RENAME 0x0005		//(section 2.2.7.5) 
//N

#define NT_TRANSACT_QUERY_SECURITY_DESC 0x0006		//(section 2.2.7.6) 
//Allows a client to retrieve the security descriptor for a file. C
//NT LANMAN


/*2.2.2.3 Information Level Codes
The SMB protocol uses information levels in several Transaction2 subcommands to allow clients to
query or set information about files, devices, and underlying object stores on servers. The following
lists of information levels are organized based on their intended purpose: finding files or devices and
related information, querying a specific file or device for information, setting file or device information,
and querying object store information.
A small number of information levels (most notably SMB_INFO_STANDARD and the other LANMAN2.0
information levels) share the same name across multiple categories. This indicates that these
information levels share similar, or at times identical, structures, but are distinct in their intended
purposes.*/
/*2.2.2.3.1 FIND Information Level Codes
FIND information levels are used in TRANS2_FIND_FIRST2 (section 2.2.6.2) and
TRANS2_FIND_NEXT2 (section 2.2.6.3) subcommand requests to indicate the level of information that
a server MUST respond with for each file matching the request's search criteria.*/

//Name	Code	Meaning	Dialect

#define SMB_INFO_STANDARD 0x0001		//Return creation, access, and last write timestamps, size and file attributes along with the file name.
//LANMAN2.0
#define SMB_INFO_QUERY_EA_SIZE 0x0002		//Return the SMB_INFO_STANDARD data along with the size of a file's extended attributes (EAs).
//LANMAN2.0
#define SMB_INFO_QUERY_EAS_FROM_LIST 0x0003		//Return the SMB_INFO_QUERY_EA_SIZE data along with a specific list of a file's EAs.
//LANMAN2.0


        
//        Name	Code	Meaning	Dialect
//The requested EAs are provided in the Trans2_Data block of the request.

#define SMB_FIND_FILE_DIRECTORY_INFO 0x0101		//Return 64-bit format versions of: creation, access, last write, and last attribute change timestamps; size. In addition, return extended file attributes and file name.
//NT LANMAN
#define SMB_FIND_FILE_FULL_DIRECTORY_INFO 0x0102		//Returns the SMB_FIND_FILE_DIRECTORY_INFO data along with the size of a file's EAs.
//NT LANMAN
#define SMB_FIND_FILE_NAMES_INFO 0x0103
//Returns the name(s) of the file(s).
//NT LANMAN
#define SMB_FIND_FILE_BOTH_DIRECTORY_INFO 0x0104		//Returns a combination of the data from SMB_FIND_FILE_FULL_DIRECTORY_INFO and SMB_FIND_FILE_NAMES_INFO.
//NT LANMAN

/*2.2.2.3.2 QUERY_FS Information Level Codes
QUERY_FS information levels are used in TRANS2_QUERY_FS_INFORMATION (section 2.2.6.4)
subcommand requests to indicate the level of information that a server MUST respond with for the
underlying object store indicated in the request.*/

//Name	Code	Meaning	Dialect

#define SMB_INFO_ALLOCATION 0x0001		//Query file system allocation unit information.
//LANMAN2.0
#define SMB_INFO_VOLUME 0x0002		//Query volume name and serial number.
//LANMAN2.0
#define SMB_QUERY_FS_VOLUME_INFO 0x0102		//Query the creation timestamp, serial number, and Unicode-encoded volume label.
//NT LANMAN
#define SMB_QUERY_FS_SIZE_INFO 0x0103		//Query 64-bit file system allocation unit information.
//NT LANMAN
#define SMB_QUERY_FS_DEVICE_INFO 0x0104		//Query a file system's underlying device type and characteristics.
//NT LANMAN
#define SMB_QUERY_FS_ATTRIBUTE_INFO 0x0105		//Query file system attributes.
//NT LANMAN

/*2.2.2.3.3 QUERY Information Level Codes
QUERY information levels are used in TRANS2_QUERY_PATH_INFORMATION (section 2.2.6.6) and
TRANS2_QUERY_FILE_INFORMATION (section 2.2.6.8) subcommand requests to indicate the level of
information that a server MUST respond with for the file or directory indicated in the request.*/

//Name	Code	Description	Dialect

#define SMB_INFO_STANDARD 0x0001		//Query creation, access, and last write timestamps, size and file attributes.
//LANMAN2.0
#define SMB_INFO_QUERY_EA_SIZE 0x0002		//Query the SMB_INFO_STANDARD data along with the size of the file's extended attributes
//LANMAN2.0

        
        //Name	Code	Description	Dialect	(EAs).

#define SMB_INFO_QUERY_EAS_FROM_LIST 0x0003		//Query a file's specific EAs by attribute name.
//LANMAN2.0
#define SMB_INFO_QUERY_ALL_EAS 0x0004		//Query all of a file's EAs.
//LANMAN2.0
#define SMB_INFO_IS_NAME_VALID 0x0006		//Validate the syntax of the path provided in the request. Not supported for TRANS2_QUERY_FILE_INFORMATION.
//LANMAN2.0
#define SMB_QUERY_FILE_BASIC_INFO 0x0101			//Query 64-bit create, access, write, and change timestamps along with extended file attributes.
//NT LANMAN
#define SMB_QUERY_FILE_STANDARD_INFO 0x0102		//Query size, number of links, if a delete is pending, and if the path is a directory.
//NT LANMAN
#define SMB_QUERY_FILE_EA_INFO 0x0103		//Query the size of the file's EAs.
//NT LANMAN
#define SMB_QUERY_FILE_NAME_INFO 0x0104		//Query the long file name in Unicode format.
//NT LANMAN
#define SMB_QUERY_FILE_ALL_INFO 0x0107		//Query the SMB_QUERY_FILE_BASIC_INFO,
//SMB_QUERY_FILE_STANDARD_INFO,
//SMB_QUERY_FILE_EA_INFO, and
//SMB_QUERY_FILE_NAME_INFO data as well as access flags, access mode, and alignment information in a single request.
//NT LANMAN
#define SMB_QUERY_FILE_ALT_NAME_INFO 0x0108		//Query the 8.3 file name.<22>
//NT LANMAN
#define SMB_QUERY_FILE_STREAM_INFO 0x0109		//Query file stream information.
//NT LANMAN
#define SMB_QUERY_FILE_COMPRESSION_INFO 0x010B		//Query file compression information.
//NT LANMAN

//2.2.2.3.4 SET Information Level Codes
/*SET information levels are used in TRANS2_SET_PATH_INFORMATION (section 2.2.6.7) and
TRANS2_SET_FILE_INFORMATION (section 2.2.6.9) subcommand requests to indicate what level of
information is being set on the file or directory in the request.*/

//Name	Code	Description	Dialect
#define SMB_INFO_STANDARD 0x0001		//Set creation, access, and last write timestamps.
//LANMAN2.0
#define SMB_INFO_SET_EAS 0x0002		//Set a specific list of extended attributes (EAs).
//LANMAN2.0
#define SMB_SET_FILE_BASIC_INFO 0x0101		//Set 64-bit create, access, write, and change timestamps along with extended file attributes.
//NT LANMAN
#define SMB_SET_FILE_DISPOSITION_INFO 0x0102		//Set whether or not the file is marked for deletion.
//NT LANMAN
#define SMB_SET_FILE_ALLOCATION_INFO 0x0103			//Set file allocation size.
//NT LANMAN


//Name	Code	Description	Dialect
#define SMB_SET_FILE_END_OF_FILE_INFO 0x0104		//Set file EOF offset.
//NT
//LANMAN



//2.2.2.4 SMB Error Classes and Codes
/*This section provides an overview of status codes that can be returned by the SMB commands listed in
this document, including mappings between the NTSTATUS codes used in the NT LAN Manager
dialect, the SMBSTATUS class/code pairs used in earlier SMB dialects, and common POSIX
equivalents. The POSIX error code mappings are based upon those used in the Xenix server
implementation. This is not an exhaustive listing and MUST NOT be considered normative.
Each command and subcommand description also includes a list of status codes that are returned by
CIFS-compliant servers. Individual implementations can return status codes from their underlying
operating systems; it is up to the implementer to decide how to interpret those status codes.
The listing below is organized by SMBSTATUS Error Class. It shows SMBSTATUS Error Code values and
a general description, as well as mappings from NTSTATUS values ([MS-ERREF] section 2.3.1) and
POSIX-style error codes where possible. Note that multiple NTSTATUS values can map to a single SMBSTATUS value.*/
//SUCCESS Class 0x00
//Error code	NTSTATUS values	POSIX equivalent	Description
#define SUCCESS 0x0000
// c'è già  #define STATUS_OK 0x00000000		//Everything worked, no problems.

//ERRDOS Class 0x01
//Error code	NTSTATUS values	POSIX equivalent	Description

//ERRbadfunc 0x0001
#define STATUS_NOT_IMPLEMENTED 0xC0000002
#define STATUS_INVALID_DEVICE_REQUEST 0xC0000010
#define STATUS_ILLEGAL_FUNCTION 0xC00000AF		//Invalid Function.
//EINVAL

//ERRbadfile 0x0002
#define STATUS_NO_SUCH_FILE 0xC000000F
#define STATUS_NO_SUCH_DEVICE 0xC000000E
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034		//File not found.
//ENOENT

//ERRbadpath 0x0003
#define STATUS_OBJECT_PATH_INVALID 0xC0000039
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A		//A component in the path prefix is not a directory.
//ENOENT


//Error code	NTSTATUS values	POSIX equivalent	Description

#define STATUS_OBJECT_PATH_SYNTAX_BAD 0xC000003B
#define STATUS_DFS_EXIT_PATH_FOUND 0xC000009B
#define STATUS_REDIRECTOR_NOT_STARTED 0xC00000FB
//ERRnofids

//0x0004
#define STATUS_TOO_MANY_OPENED_FILES 0xC000011F		//Too many open files. No FIDs are available.
//EMFILE

//ERRnoaccess 0x0005
#define STATUS_ACCESS_DENIED 0xC0000022

#define STATUS_INVALID_LOCK_SEQUENCE 0xC000001E
#define STATUS_INVALID_VIEW_SIZE 0xC000001F
#define STATUS_ALREADY_COMMITTED 0xC0000021
#define STATUS_PORT_CONNECTION_REFUSED 0xC0000041
#define STATUS_THREAD_IS_TERMINATING 0xC000004B
#define STATUS_DELETE_PENDING 0xC0000056
#define STATUS_PRIVILEGE_NOT_HELD 0xC0000061
#define STATUS_LOGON_FAILURE 0xC000006D
#define STATUS_FILE_IS_A_DIRECTORY 0xC00000BA
#define STATUS_FILE_RENAMED 0xC00000D5
#define STATUS_PROCESS_IS_TERMINATING 0xC000010A
#define STATUS_DIRECTORY_NOT_EMPTY 0xC0000101
#define STATUS_CANNOT_DELETE 0xC0000121
#define STATUS_FILE_DELETED 0xC0000123	//EPERM Access denied.

//ERRbadfid 0x0006
#define STATUS_SMB_BAD_FID 0x00060001
#define STATUS_SMB_INVALID_HANDLE 0xC0000008
#define STATUS_OBJECT_TYPE_MISMATCH 0xC0000024		// EBADF Invalid FID.

        
//        Error code	NTSTATUS values	POSIX equivalent	Description

#define STATUS_PORT_DISCONNECTED 0xC0000037
#define STATUS_INVALID_PORT_HANDLE 0xC0000042
#define STATUS_FILE_CLOSED 0xC0000128
#define STATUS_HANDLE_NOT_CLOSABLE 0xC0000235
//ERRbadmcb
//0x0007
//Memory Control Blocks were destroyed.

//ERRnomem 0x0008
#define STATUS_SECTION_TOO_BIG 0xC0000040
#define STATUS_TOO_MANY_PAGING_FILES 0xC0000097
#define STATUS_INSUFF_SERVER_RESOURCES 0xC0000205		//Insufficient server memory to perform the requested operation.
//ENOMEM
//ERRbadmem 0x0009
//EFAULT
//The server performed an invalid memory access (invalid address).
//ERRbadenv 0x000A
//Invalid environment.
//ERRbadformat 0x000B
//Invalid format.
//ERRbadaccess 0x000C
#define STATUS_OS2_INVALID_ACCESS 0x000C0001
#define STATUS_CIFS_ACCESS_DENIED 0xC00000CA		//Invalid open mode.

//ERRbaddata 0x000D
#define STATUS_CIFS_DATA_ERROR 0xC000009C		//E2BIG Bad data. (May be generated by IOCTL calls on the server.)

//ERRbaddrive 0x000FENXIO		//Invalid drive specified.
//ERRremcd 0x0010
#define STATUS_DIRECTORY_NOT_EMPTY 0xC0000101		//Remove of directory failed because it was not empty.

//Error code	NTSTATUS values	POSIX equivalent	Description

//ERRdiffdevice 0x0011
#define STATUS_NOT_SAME_DEVICE 0xC00000D4		//A file system operation (such as a rename) across two devices was attempted.
//EXDEV

//ERRnofiles 0x0012
#define STATUS_NO_MORE_FILES 0x80000006		//No (more) files found following a file search command.

//ERRgeneral 0x001F
#define STATUS_UNSUCCESSFUL 0xC0000001		//General error.

//ERRbadshare 0x0020
#define STATUS_SHARING_VIOLATION 0xC0000043		//Sharing violation. A requested open mode conflicts with the sharing mode of an existing file handle.
//ETXTBSY

//ERRlock 0x0021
#define STATUS_FILE_LOCK_CONFLICT 0xC0000054
#define STATUS_LOCK_NOT_GRANTED 0xC0000055		//A lock request specified an invalid locking mode, or conflicted with an existing file lock.
//EDEADLOCK

//ERReof 0x0026
#define STATUS_END_OF_FILE 0xC0000011		//EEOF Attempted to read beyond the end of the file.

//ERRunsup 0x0032
#define STATUS_NOT_SUPPORTED 0XC00000BB		//This command is not supported by the server.

//ERRfilexists 0x0050
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035		//An attempt to create a file or directory failed because an object with the same pathname already exists.
//EEXIST

//Error code	NTSTATUS values	POSIX equivalent	Description


//ERRinvalidparam 0x0057
#define STATUS_INVALID_PARAMETER 0xC000000D		//A parameter supplied with the message is invalid.

//ERRunknownlevel 0x007C
#define STATUS_OS2_INVALID_LEVEL 0x007C0001		//Invalid information level.

//ERRinvalidseek 0x0083
#define STATUS_OS2_NEGATIVE_SEEK 0x00830001		//An attempt was made to seek to a negative absolute offset within a file.

//ERROR_NOT_LOCKED 0x009E
#define STATUS_RANGE_NOT_LOCKED 0xC000007E		//The byte range specified in an unlock request was not locked.

//ERROR_NO_MORE_SEARCH_HANDLES 0x0071
#define STATUS_OS2_NO_MORE_SIDS 0x00710001		//Maximum number of searches has been exhausted.

//ERROR_CANCEL_VIOLATION 0x00AD
#define STATUS_OS2_CANCEL_VIOLATION 0x00AD0001		//No lock request was outstanding for the supplied cancel region.

//ERROR_ATOMIC_LOCKS_NOT_SUPPORTED 0x00AE
#define STATUS_OS2_ATOMIC_LOCKS_NOT_SUPPORTED 0x00AE0001		//The file system does not support atomic changes to the lock type.

        
        //Error code	NTSTATUS values	POSIX equivalent	Description
//ERRbadpipe 0x00E6
#define STATUS_INVALID_INFO_CLASS 0xC0000003
#define STATUS_INVALID_PIPE_STATE 0xC00000AD
#define STATUS_INVALID_READ_MODE 0xC00000B4
//Invalid named pipe.

//ERROR_CANNOT_COPY 0x010A
#define STATUS_OS2_CANNOT_COPY 0x010A0001		//The copy functions cannot be used.

//ERRpipebusy 0x00E7
#define STATUS_INSTANCE_NOT_AVAILABLE 0xC00000AB
#define STATUS_PIPE_NOT_AVAILABLE 0xC00000AC
#define STATUS_PIPE_BUSY 0xC00000AE		//All instances of the designated named pipe are busy.

//ERRpipeclosing 0x00E8
#define STATUS_PIPE_CLOSING 0xC00000B1
#define STATUS_PIPE_EMPTY 0xC00000D9		//The designated named pipe is in the process of being closed.

//ERRnotconnected
//0x00E9
#define STATUS_PIPE_DISCONNECTED 0xC00000B0		//The designated named pipe exists, but there is no server process listening on the server side.

//ERRmoredata 0x00EA
#define STATUS_BUFFER_OVERFLOW 0x80000005
#define STATUS_MORE_PROCESSING_REQUIRED 0xC0000016		//There is more data available to read on the designated named pipe.
//ERRbadealist 0x00FF
//Inconsistent extended attribute list.
//ERROR_EAS_DIDNT_FIT 0x0113
#define STATUS_EA_TOO_LARGE 0xC0000050
#define STATUS_OS2_EAS_DIDNT_FIT 0x01130001
//Either there are no extended attributes, or the available extended attributes did not fit into the response.
//Error code	NTSTATUS values	POSIX equivalent	Description 

//ERROR_EAS_NOT_SUPPORTED 0x011A
#define STATUS_EAS_NOT_SUPPORTED 0xC000004F
//The server file system does not support Extended Attributes.

//ERROR_EA_ACCESS_DENIED 0x03E2
#define STATUS_OS2_EA_ACCESS_DENIED 0x03E20001		//Access to the extended attribute was denied.

//ERR_NOTIFY_ENUM_DIR 0x03FE
#define STATUS_NOTIFY_ENUM_DIR 0x0000010C		//More changes have occurred within the directory than will fit within the specified Change Notify response buffer.
//ERRSRV Class 0x02
//Error code	NTSTATUS values	POSIX equivalent	Description ERRerror 0x0001
#define STATUS_INVALID_SMB 0x00010002		//Unspecified server error.<23>

//ERRbadpw 0x0002
#define STATUS_WRONG_PASSWORD 0xC000006A		//Invalid password.

//ERRbadpath 0x0003
#define STATUS_PATH_NOT_COVERED 0xC0000257
//DFS pathname not on local server.
//ERRaccess
//0x0004
#define STATUS_NETWORK_ACCESS_DENIED 0xC00000CA		//EACCES Access denied. The specified UID does not have permission to execute the requested command within the current context (TID).
//ERRinvtid
//0x0005
#define STATUS_NETWORK_NAME_DELETED 0xC00000C9
#define STATUS_SMB_BAD_TID 0x00050002
//The TID specified in the command was invalid. Earlier documentation, with the exception of [SNIA],
//refers to this error code as ERRinvnid (Invalid Network Path Identifier). [SNIA] uses 
        

//        Error code	NTSTATUS values	POSIX equivalent Description both names.<24>

//ERRinvnetname 0x0006
#define STATUS_BAD_NETWORK_NAME 0xC00000CC		//Invalid server name in Tree
//Connect.

//ERRinvdevice 0x0007
#define STATUS_BAD_DEVICE_TYPE 0xC00000CB			//A printer request was made to a non-printer device or,
//conversely, a non-printer request was made to a printer device.
//ERRinvsess 0x0010
//Invalid Connection ID (CID).
//This error code is only defined when the Direct IPX connectionless transport is in use.
//ERRworking 0x0011
//A command with matching MID or SequenceNumber is currently being processed.
//This error code is defined only when the Direct IPX connectionless transport is in use.
//ERRnotme
//0x0012
//Incorrect NetBIOS Called
//Name when starting an SMB session over Direct IPX. This error code is only defined when the Direct IPX connectionless transport is in use.

//ERRbadcmd 0x0016
#define STATUS_SMB_BAD_COMMAND 0x00160002		//An unknown SMB command code was received by the server.

//ERRqfull 0x0031
#define STATUS_PRINT_QUEUE_FULL 0xC00000C6		//Print queue is full - too many queued items.

//ERRqtoobig 0x0032
#define STATUS_NO_SPOOL_SPACE 0xC00000C7		//Print queue is full - no space for queued item, or queued item too big.
//ERRqeof 0x0033
//End Of File on print queue dump.

//ERRinvpfid 0x0034
#define STATUS_PRINT_CANCELLED 0xC00000C8		//Invalid FID for print file.

//ERRsmbcmd 0x0040
#define STATUS_NOT_IMPLEMENTED 0xC0000002		//Unrecognized SMB command code.

//ERRsrverror 0x0041
#define STATUS_UNEXPECTED_NETWORK_ERROR 0xC00000C4			//Internal server error.

//ERRfilespecs 0x0043
//The FID and pathname contain incompatible values.
//ERRbadpermits
#define STATUS_NETWORK_ACCESS_DENIED	0xC00000CA
//An invalid combination of access permissions for a file or directory was presented.
//Error code	NTSTATUS values	POSIX equivalent	Description
//0x0045
//The server cannot set the requested attributes.
//ERRsetattrmode 0x0047
//The attribute mode presented in a set mode request was invalid.
//ERRtimeout 0x0058
#define STATUS_UNEXPECTED_NETWORK_ERROR 0xC00000C4
#define STATUS_IO_TIMEOUT 0xC00000B5		//Operation timed out.

//ERRnoresource 0x0059
#define STATUS_REQUEST_NOT_ACCEPTED 0xC00000D0		//No resources currently available for this SMB request.

//ERRtoomanyuids 0x005A
#define STATUS_TOO_MANY_SESSIONS 0xC00000CE		//Too many UIDs active for this SMB connection.

//ERRbaduid 0x005B
#define STATUS_SMB_BAD_UID 0x005B0002		//The UID specified is not known as a valid ID on this server session.

//ERRnotconnected 0x00E9
#define STATUS_PIPE_DISCONNECTED 0xC00000B0		// EPIPE Write to a named pipe with no reader.

//ERRusempx 0x00FA
#define STATUS_SMB_USE_MPX 0x00FA0002		//Temporarily unable to support RAW mode transfers. Use MPX mode.

//ERRusestd 0x00FB
#define STATUS_SMB_USE_STANDARD 0x00FB0002		//Temporarily unable to support RAW or MPX mode transfers. Use standard read/write.

//ERRcontmpx 0x00FC
#define STATUS_SMB_CONTINUE_MPX 0x00FC0002		//Continue in MPX mode.
//This error code is reserved for future use.

//ERRaccountExpired 0x08BF
#define STATUS_ACCOUNT_DISABLED 0xC0000072
#define STATUS_ACCOUNT_EXPIRED 0xC0000193		//User account on the target machine is disabled or has expired.

//ERRbadClient 0x08C0
#define STATUS_INVALID_WORKSTATION 0xC0000070		//The client does not have permission to access this server.

//ERRbadLogonTime 0x08C1
#define STATUS_INVALID_LOGON_HOURS 0xC000006F		//Access to the server is not permitted at this time.

//ERRpasswordExpired 0x08C2
#define STATUS_PASSWORD_EXPIRED 0xC0000071
#define STATUS_PASSWORD_MUST_CHANGE 0xC0000224		//The user's password has expired.

//ERRnosupport
#define STATUS_SMB_NO_SUPPORT			//Function not supported by the

//Error code	NTSTATUS values	POSIX equivalent	Description
//0xFFFF
//0XFFFF0002
//server.
//ERRHRD Class 0x03
//Error code	NTSTATUS values	POSIX equivalent	Description
//ERRnowrite 0x0013
#define STATUS_MEDIA_WRITE_PROTECTED 0xC00000A2		//Attempt to modify a read-only file system.
//EROFS
//ERRbadunit 0x0014
//ENODEV
//Unknown unit.

//ERRnotready 0x0015
#define STATUS_NO_MEDIA_IN_DEVICE 0xC0000013		//EUCLEAN Drive not ready.
//ERRbadcmd 0x0016
#define STATUS_INVALID_DEVICE_STATE 0xC0000184		//Unknown command.
//ERRdata 0x0017
#define STATUS_DATA_ERROR 0xC000003E
#define STATUS_CRC_ERROR 0xC000003F		//EIO Data error (incorrect CRC).

//ERRbadreq 0x0018
#define STATUS_DATA_ERROR 0xC000003E		// Bad request structure length.
//ERANGE
//ERRseek 0x0019
//Seek error.

//ERRbadmedia 0x001A
#define STATUS_DISK_CORRUPT_ERROR 0xC0000032
//Unknown media type.

//ERRbadsector 0x001B
#define STATUS_NONEXISTENT_SECTOR 0xC0000015		//Sector not found.

//ERRnopaper 0x001C
#define STATUS_DEVICE_PAPER_EMPTY 0x8000000E		//Printer out of paper.
//ERRwrite 0x001D
//Write fault.
//ERRread 0x001E
//Read fault.
//ERRgeneral 0x001F
//General hardware failure.

//ERRbadshare 0x0020
#define STATUS_SHARING_VIOLATION 0xC0000043	//ETXTBSY An attempted open operation conflicts with an existing open.

//ERRlock 0x0021
#define STATUS_FILE_LOCK_CONFLICT 0xC0000054	//A lock request specified an invalid locking mode, or conflicted with an existing file lock.
//EDEADLOCK

//ERRwrongdisk
#define STATUS_WRONG_VOLUME	0xC0000012	//The wrong disk was found in a drive.
        
//       Error code	NTSTATUS values	POSIX equivalent	Description

//0x0022
//
//ERRFCBUnavail 0x0023
//No server-side File Control Blocks are available to process the request.
//ERRsharebufexc 0x0024
//A sharing buffer has been exceeded.

//ERRdiskfull 0x0027
#define STATUS_DISK_FULL 0xC000007F		//No space on file system.
//ENOSPC
//ERRCMD Class 0xFF

    
typedef struct __attribute__((__packed__)) _NETWORKDISK_STRUCT NETWORKDISK_STRUCT;

	int8_t CIFSConnect(NETWORKDISK_STRUCT *, const char *);
	BOOL CIFSDisconnect(NETWORKDISK_STRUCT *);
	static int CIFSSend(NETWORKDISK_STRUCT *, const uint8_t *,uint16_t);
	static int CIFSreadResponseNBSS(NETWORKDISK_STRUCT *, uint8_t *buf,uint16_t len);
	static int CIFSreadResponseSMB2(NETWORKDISK_STRUCT *, uint8_t *buf,uint16_t len);
	static SMB2_HEADER *CIFSprepareSMB2header(NETWORKDISK_STRUCT *, SMB2_HEADER *,uint16_t,uint8_t,uint16_t);
	static uint8_t *CIFSprepareSMBcode(uint8_t *,uint8_t,uint32_t);
	char *nbEncode(const char *,char *,BOOL mode);
	uint8_t *uniEncode(const char *,uint8_t *);
    char *uniDecode(const uint8_t *src,int16_t len,char *dst);
    char *nbEncode(const char *name,char *encoded_name,BOOL mode);
    uint32_t FiletimeToTime(uint64_t value);
    uint64_t TimeToFiletime(uint32_t value);
    FILETIMEPACKED FiletimeToPackedTime(uint64_t value);

	int8_t CIFSOpenSession(NETWORKDISK_STRUCT *,const char *server,const char *user,const char *pasw);
	int8_t CIFSCloseSession(NETWORKDISK_STRUCT *);
	int8_t CIFSOpenShare(NETWORKDISK_STRUCT *,const char *share);
	int8_t CIFSCloseShare(NETWORKDISK_STRUCT *);
	int8_t CIFSFindFirst(NETWORKDISK_STRUCT *,const char *,uint8_t,void *);
	int8_t CIFSFindNext(NETWORKDISK_STRUCT *);
	int8_t CIFSChDir(NETWORKDISK_STRUCT *,const char *);
	int8_t CIFSMkDir(NETWORKDISK_STRUCT *,const char *);
	int8_t CIFSRmDir(NETWORKDISK_STRUCT *,const char *);
	int8_t CIFSOpenFile(NETWORKDISK_STRUCT *,const char *s,uint8_t mode,uint8_t share);
	int8_t CIFSReadFile(NETWORKDISK_STRUCT *,uint8_t *buf,uint32_t size);
	int8_t CIFSWriteFile(NETWORKDISK_STRUCT *,const uint8_t *buf,uint32_t size);
	int8_t CIFSCloseFile(NETWORKDISK_STRUCT *);
	int8_t CIFSDeleteFile(NETWORKDISK_STRUCT *,const char *s);
	int8_t CIFSRenameFile(NETWORKDISK_STRUCT *,const char *s,const char *d);
	int8_t CIFSGetVolumeInfo(NETWORKDISK_STRUCT *,char *,FILETIMEPACKED *);
	int8_t CIFSVolumeInfo(NETWORKDISK_STRUCT *,uint64_t *,uint64_t *,uint32_t *);
	int8_t CIFSFileStat(NETWORKDISK_STRUCT *,const char *s,struct FSstat *);
    int8_t CIFSSetFileTime(NETWORKDISK_STRUCT *cifs,const char *,uint32_t);
    int8_t CIFSAttrib(NETWORKDISK_STRUCT *cifs,const char *,uint8_t,uint8_t);

	void CIFSCliSocket(NETWORKDISK_STRUCT *,uint8_t ver,uint8_t mode,uint8_t sec/* 1=signing-on (se no ti rimbalza), 2=NTLMSSP fisso per ora,v.*/);
		// mode=1 per TCP diretto su 445, 0 per Netbios/139
    

    
#define CIFS_TIMEOUT 2000      // 
    
#define MAX_CLIENT_CONNECTIONS 1

	static void getGUID(uint8_t *);
    static inline BOOL cmpGUID(uint8_t *,uint8_t *);
	static uint64_t gettime();
    static uint64_t PackedTimeToFiletime(FILETIMEPACKED);
	SMB2_HEADER *prepareSMB2header(SMB2_HEADER *sh,uint32_t command,uint32_t status,uint32_t session,uint8_t ccharge,uint16_t crequest);
    BOOL SMB2CreateServer();
    BOOL SMB2CloseServer();
    void SMB2OnReceive();

    
typedef struct __attribute__((__packed__)) _SMB2_SERVER_DATA {
	uint32_t msgcntS;       // ok 32bit qua!
	uint32_t msgcntR;
	uint32_t processid;
	uint64_t sessionid;
	uint32_t treeid;
	uint16_t dialect;		// 
	uint32_t fileoffset;
	uint64_t createflags;
	uint8_t signature[16];
	uint8_t serverguid[16];
	uint8_t fileguid[16];
	uint8_t dirguid[16];
	uint8_t sessionstate;
	uint32_t createoptions;
	uint32_t accessmask;
	uint32_t shareaccess;
	uint32_t fileattributes;
#ifdef SUPPORT_LFN
#endif
	char curtree[64];
	char curfile[32];
	char curdir[64];
	FSFILE *file;
	DWORD cliTimeOut;
	uint32_t startConn;			// il momento di inizio connessione...
   
	uint16_t port;
    SOCKET sock;
	uint8_t security;
	uint8_t version;
	int8_t totConn;
    } SMB2_SERVER_DATA;

BOOL advertizeNetbiosName(const char *);
    
#endif

