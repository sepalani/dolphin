// Copyright 2014 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "Common/CommonTypes.h"

struct sockaddr_in;

namespace Common
{
enum class MACConsumer
{
  BBA,
  IOS
};

enum
{
  BBA_HARDWARE_TYPE = 1,
  MAC_ADDRESS_SIZE = 6,
  IPV4_HEADER_TYPE = 8
};

enum DHCPConst
{
  MESSAGE_QUERY = 1,
  MESSAGE_REPLY = 2
};

using MACAddress = std::array<u8, MAC_ADDRESS_SIZE>;
constexpr std::size_t IPV4_ADDR_LEN = 4;
using IPAddress = std::array<u8, IPV4_ADDR_LEN>;
constexpr IPAddress IP_ADDR_ANY = {0, 0, 0, 0};
constexpr IPAddress IP_ADDR_BROADCAST = {255, 255, 255, 255};
constexpr IPAddress IP_ADDR_SSDP = {239, 255, 255, 250};
constexpr u16 IPV4_ETHERTYPE = 0x800;
constexpr u16 ARP_ETHERTYPE = 0x806;

struct EthernetHeader
{
  EthernetHeader();
  explicit EthernetHeader(u16 ether_type);
  u16 Size() const;

  static constexpr std::size_t SIZE = 14;

  MACAddress destination = {};
  MACAddress source = {};
  u16 ethertype = 0;
};
static_assert(sizeof(EthernetHeader) == EthernetHeader::SIZE);

struct IPv4Header
{
  IPv4Header();
  IPv4Header(u16 data_size, u8 ip_proto, const sockaddr_in& from, const sockaddr_in& to);
  u16 Size() const;

  static constexpr std::size_t SIZE = 20;

  u8 version_ihl = 0;
  u8 dscp_esn = 0;
  u16 total_len = 0;
  u16 identification = 0;
  u16 flags_fragment_offset = 0;
  u8 ttl = 0;
  u8 protocol = 0;
  u16 header_checksum = 0;
  std::array<u8, IPV4_ADDR_LEN> source_addr{};
  std::array<u8, IPV4_ADDR_LEN> destination_addr{};
};
static_assert(sizeof(IPv4Header) == IPv4Header::SIZE);

struct TCPHeader
{
  TCPHeader();
  TCPHeader(const sockaddr_in& from, const sockaddr_in& to, u32 seq, const u8* data, u16 length);
  TCPHeader(const sockaddr_in& from, const sockaddr_in& to, u32 seq, u32 ack, u16 flags);
  u16 Size() const;
  u8 IPProto() const;

  static constexpr std::size_t SIZE = 20;

  u16 source_port = 0;
  u16 destination_port = 0;
  u32 sequence_number = 0;
  u32 acknowledgement_number = 0;
  u16 properties = 0;
  u16 window_size = 0;
  u16 checksum = 0;
  u16 urgent_pointer = 0;
};
static_assert(sizeof(TCPHeader) == TCPHeader::SIZE);

struct UDPHeader
{
  UDPHeader();
  UDPHeader(const sockaddr_in& from, const sockaddr_in& to, u16 data_length);
  u16 Size() const;
  u8 IPProto() const;

  static constexpr std::size_t SIZE = 8;

  u16 source_port = 0;
  u16 destination_port = 0;
  u16 length = 0;
  u16 checksum = 0;
};
static_assert(sizeof(UDPHeader) == UDPHeader::SIZE);

#pragma pack(push, 1)
struct ARPHeader
{
  ARPHeader();
  ARPHeader(u32 from_ip, MACAddress from_mac, u32 to_ip, MACAddress to_mac);
  u16 Size() const;

  static constexpr std::size_t SIZE = 28;

  u16 hardware_type = 0;
  u16 protocol_type = 0;
  u8 hardware_size = 0;
  u8 protocol_size = 0;
  u16 opcode = 0;
  MACAddress sender_address{};
  u32 sender_ip = 0;
  MACAddress targer_address{};
  u32 target_ip = 0;
};
static_assert(sizeof(ARPHeader) == ARPHeader::SIZE);
#pragma pack(pop)

struct DHCPBody
{
  DHCPBody();
  DHCPBody(u32 transaction, MACAddress client_address, u32 new_ip, u32 serv_ip);
  bool AddDHCPOption(u8 size, u8 fnc, const std::vector<u8>& params);
  static constexpr std::size_t SIZE = 540;
  u8 message_type = 0;
  u8 hardware_type = 0;
  u8 hardware_addr = 0;
  u8 hops = 0;
  u32 transaction_id = 0;
  u16 secondes = 0;
  u16 boot_flag = 0;
  u32 client_ip = 0;
  u32 your_ip = 0;
  u32 server_ip = 0;
  u32 relay_ip = 0;
  MACAddress client_mac{};
  unsigned char padding[10]{};
  unsigned char hostname[0x40]{};
  unsigned char boot_file[0x80]{};
  u32 magic_cookie = 0x63538263;
  u8 options[300]{};
};
static_assert(sizeof(DHCPBody) == DHCPBody::SIZE);

// The compiler might add 2 bytes after EthernetHeader to enforce 16-bytes alignment
#pragma pack(push, 1)
struct ARPPacket
{
  ARPPacket();
  u16 Size() const;

  EthernetHeader eth_header;
  ARPHeader arp_header;

  static constexpr std::size_t SIZE = EthernetHeader::SIZE + ARPHeader::SIZE;
};
static_assert(sizeof(ARPPacket) == ARPPacket::SIZE);


struct TCPPacket
{
  TCPPacket();
  u16 Size() const;

  EthernetHeader eth_header;
  IPv4Header ip_header;
  TCPHeader tcp_header;

  // TODO: Support IPv4 IHL and TCP options
  static constexpr std::size_t SIZE = EthernetHeader::SIZE + IPv4Header::SIZE + TCPHeader::SIZE;
};
static_assert(sizeof(TCPPacket) == TCPPacket::SIZE);

struct UDPPacket
{
  UDPPacket();
  u16 Size() const;

  EthernetHeader eth_header;
  IPv4Header ip_header;
  UDPHeader udp_header;

  static constexpr std::size_t SIZE = EthernetHeader::SIZE + IPv4Header::SIZE + UDPHeader::SIZE;
};
static_assert(sizeof(UDPPacket) == UDPPacket::SIZE);
#pragma pack(pop)

class PacketView
{
public:
  PacketView(const u8* ptr, std::size_t size);

  std::optional<u16> GetEtherType() const;
  std::optional<ARPPacket> GetARPPacket() const;
  std::optional<u8> GetIPProto() const;
  std::optional<TCPPacket> GetTCPPacket() const;
  std::vector<u8> GetTCPData() const;
  std::optional<UDPPacket> GetUDPPacket() const;
  std::vector<u8> GetUDPData() const;

private:
  const u8* m_ptr;
  std::size_t m_size;
};

MACAddress GenerateMacAddress(MACConsumer type);
std::string MacAddressToString(const MACAddress& mac);
std::optional<MACAddress> StringToMacAddress(std::string_view mac_string);
u16 ComputeNetworkChecksum(const void* data, u16 length, u32 initial_value = 0);
u16 ComputeTCPNetworkChecksum(const sockaddr_in& from, const sockaddr_in& to, const void* data,
                              u16 length, u8 protocol);
}  // namespace Common
