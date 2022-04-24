// ReSharper disable IdentifierTypo
// ReSharper disable CommentTypo
// ReSharper disable CppInconsistentNaming
#pragma once

enum {
	CNBL_SEND,
	CNBL_RECEIVE
};

typedef struct {
	UCHAR DestinationAddress[6];
	UCHAR SourceAddress[6];
	USHORT EthType;
} ETHERNET_HEADER;

typedef struct {
	/*
	UCHAR Version : 4;
	UCHAR IHL : 4;
	UCHAR DSCP : 6;
	UCHAR ECN : 2;
	*/
	USHORT VIDE;
	USHORT TotalLength;
	USHORT Identification;
	/*
	USHORT Flags:3;
	USHORT FragmentOffset : 13;
	*/
	USHORT FFO;
	UCHAR TTL;
	UCHAR Protocol;
	USHORT HeaderChecksum;
	UCHAR SourceAddress[4];
	UCHAR DestinationAddress[4];
} IPV4_HEADER;

typedef enum {
	IPHP_ICMP = 1,
	IPHP_IGMP = 2,
	IPHP_TCP = 6,
	IPHP_UDP = 17,
	IPHP_ENCAP = 41,
	IPHP_OSPF = 89,
	IPHP_SCTP = 132
} NETWORK_INTERFACE_PROTOCOL;

typedef struct {
	USHORT SourcePort;
	USHORT DestinationPort;
	USHORT TotalLength;
	USHORT Checksum;
} UDP_HEADER;

typedef struct {
	USHORT FlagsAndVersion;
	USHORT Length;
	USHORT TunnelId;
	USHORT SessionId;
	USHORT Ns;
	USHORT Nr;
	USHORT OffsetSize;
	USHORT OffsetPad;
} L2TP_HEADER;

typedef enum {
	Control = 1 << 15,
	HasLength = 1 << 14,
	HasSequence = 1 << 11,
	HasOffset = 1 << 9,
	Priority = 1 << 8
} L2TP_FLAGS;

#define L2TP_PORT 16540
