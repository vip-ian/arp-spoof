#pragma once
#include "ip.h"

#pragma pack(push, 1)
struct IPv4_hdr final{
	uint8_t version:4;
	uint8_t IHL:4;
	uint8_t Ip_tos;
	uint16_t Ip_total_length;
	uint8_t dummy[4];
	uint8_t TTL;
	uint8_t Protocol;
	uint8_t dummy2[2];
	Ip sip;
	Ip dip;
};
