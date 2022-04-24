#pragma once
#include <stdint.h>

#define PAYLOAD_PATTERN_MAX_LENGTH 1024
#define RULE_MAX_LENGTH 16
#define NAME_MAX_LENGTH 64

typedef uint8_t UByte;

typedef uint16_t UShort;

typedef uint32_t UInt;

typedef uint64_t ULong;

// ReSharper disable CppInconsistentNaming
typedef enum {
	Any = 0,
	PPP,
	L2TP,
	IP,
	ICMP,
	IPSec,
	ARP,
	TCP,
	UDP,
	DNS,
	HTTP,
	FTP,
	SMTP,
	Telnet
} Protocol;

// ReSharper restore CppInconsistentNaming

typedef enum {
	In = 1 << 0,
	Out = 1 << 1,
	InOut = In | Out
} Direction;

typedef struct {
	UByte mac[6];

	UByte mask[6];
} MacRule;

typedef struct {
	UByte version;

	UByte ip[16];

	UByte mask[16];
} IpRule;

typedef struct {
	UShort startPort;

	UShort endPort;
} PortRule;

typedef struct {
	UShort length;

	UByte pattern[PAYLOAD_PATTERN_MAX_LENGTH];

	UByte mask[PAYLOAD_PATTERN_MAX_LENGTH];
} PayloadRule;

typedef struct {
	UInt id;

	char name[NAME_MAX_LENGTH];

	Direction direction;

	Protocol protocol;

	MacRule srcMacs[RULE_MAX_LENGTH], dstMacs[RULE_MAX_LENGTH];

	IpRule srcIps[RULE_MAX_LENGTH], dstIps[RULE_MAX_LENGTH];

	PortRule srcPorts[RULE_MAX_LENGTH], dstPorts[RULE_MAX_LENGTH];

	PayloadRule payloads[RULE_MAX_LENGTH];
} FirewallRule;
