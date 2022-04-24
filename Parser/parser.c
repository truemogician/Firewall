#include <string.h>
#include "rule.h"

UShort readUShort(UByte** p) {
	const UShort result = (UShort)((*p)[0] << 8) | (*p)[1];
	*p += 2;
	return result;
}

UInt readUInt(UByte** p) {
	UInt result = readUShort(p);
	result = result << 16 | readUShort(p);
	return result;
}

ULong readULong(UByte** p) {
	ULong result = readUInt(p);
	result = result << 32 | readUInt(p);
	return result;
}

void parseMacRule(UByte** pointer, MacRule* const dst) {
	const UByte* p = *pointer;
	memcpy(dst->mac, p, sizeof(UByte) * 6);
	memcpy(dst->mask, p + 6, sizeof(UByte) * 6);
	*pointer += 12;
}

void parseIpRule(UByte** pointer, IpRule* const dst) {
	UByte* p = *pointer;
	dst->version = *p++;
	const int length = dst->version == 4 ? 4 : 16;
	memcpy(dst->ip, p, sizeof(UByte) * length);
	memcpy(dst->mask, p + length, sizeof(UByte) * length);
	*pointer = p + (length << 1);
}

void parsePortRule(UByte** pointer, PortRule* const dst) {
	dst->startPort = readUShort(pointer);
	dst->endPort = readUShort(pointer);
}

void parsePayloadRule(UByte** pointer, PayloadRule* const dst) {
	dst->length = readUShort(pointer);
	memcpy(dst->pattern, *pointer, sizeof(UByte) * dst->length);
	memcpy(dst->mask, *pointer + dst->length, sizeof(UByte) * dst->length);
	*pointer += dst->length << 1;
}

#define PARSE_ARRAY(target, type, func)\
	size = readULong(&p);\
	for (UInt i = 0; i < size; ++i)\
		(func)(&p, (target) + i)\


void parse(UByte** pointer, FirewallRule* const dst) {
	UByte* p = *pointer;
	dst->id = readUInt(&p);
	size_t length = 0;
	for (; *p != 0; ++p, ++length) {}
	memcpy(dst->name, p - length, length);
	UByte b = *++p;
	dst->direction = b >> 6;
	dst->protocol = b & 63;
	++p;
	ULong size;
	PARSE_ARRAY(dst->srcMacs, MacRule, parseMacRule);
	PARSE_ARRAY(dst->dstMacs, MacRule, parseMacRule);
	PARSE_ARRAY(dst->srcIps, IpRule, parseIpRule);
	PARSE_ARRAY(dst->dstIps, IpRule, parseIpRule);
	PARSE_ARRAY(dst->srcPorts, PortRule, parsePortRule);
	PARSE_ARRAY(dst->dstPorts, PortRule, parsePortRule);
	PARSE_ARRAY(dst->payloads, PayloadRule, parsePayloadRule);
	*pointer = p;
}
