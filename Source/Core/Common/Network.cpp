// Copyright 2014 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Common/Network.h"

#include <algorithm>
#include <string_view>
#include <vector>

#ifndef _WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#else
#include <WinSock2.h>
#endif

#include <fmt/format.h>

#include "Common/Random.h"
#include "Common/StringUtil.h"
#include "Common/BitUtils.h"

namespace Common
{
MACAddress GenerateMacAddress(const MACConsumer type)
{
  constexpr std::array<u8, 3> oui_bba{{0x00, 0x09, 0xbf}};
  constexpr std::array<u8, 3> oui_ios{{0x00, 0x17, 0xab}};

  MACAddress mac{};

  switch (type)
  {
  case MACConsumer::BBA:
    std::copy(oui_bba.begin(), oui_bba.end(), mac.begin());
    break;
  case MACConsumer::IOS:
    std::copy(oui_ios.begin(), oui_ios.end(), mac.begin());
    break;
  }

  // Generate the 24-bit NIC-specific portion of the MAC address.
  Random::Generate(&mac[3], 3);
  return mac;
}

std::string MacAddressToString(const MACAddress& mac)
{
  return fmt::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3],
                     mac[4], mac[5]);
}

std::optional<MACAddress> StringToMacAddress(std::string_view mac_string)
{
  if (mac_string.empty())
    return std::nullopt;

  int x = 0;
  MACAddress mac{};

  for (size_t i = 0; i < mac_string.size() && x < (MAC_ADDRESS_SIZE * 2); ++i)
  {
    char c = Common::ToLower(mac_string.at(i));
    if (c >= '0' && c <= '9')
    {
      mac[x / 2] |= (c - '0') << ((x & 1) ? 0 : 4);
      ++x;
    }
    else if (c >= 'a' && c <= 'f')
    {
      mac[x / 2] |= (c - 'a' + 10) << ((x & 1) ? 0 : 4);
      ++x;
    }
  }

  // A valid 48-bit MAC address consists of 6 octets, where each
  // nibble is a character in the MAC address, making 12 characters
  // in total.
  if (x / 2 != MAC_ADDRESS_SIZE)
    return std::nullopt;

  return std::make_optional(mac);
}

EthernetHeader::EthernetHeader() = default;

EthernetHeader::EthernetHeader(u16 ether_type)
{
  ethertype = htons(ether_type);
}

u16 EthernetHeader::Size() const
{
  return static_cast<u16>(SIZE);
}

IPv4Header::IPv4Header() = default;

IPv4Header::IPv4Header(u16 data_size, u8 ip_proto, const sockaddr_in& from, const sockaddr_in& to)
{
  version_ihl = 0x45;
  total_len = htons(Size() + data_size);
  flags_fragment_offset = htons(0x4000);
  ttl = 0x40;
  protocol = ip_proto;
  std::memcpy(source_addr.data(), &from.sin_addr, IPV4_ADDR_LEN);
  std::memcpy(destination_addr.data(), &to.sin_addr, IPV4_ADDR_LEN);

  header_checksum = htons(ComputeNetworkChecksum(this, Size()));
}

u16 IPv4Header::Size() const
{
  return 4 * (version_ihl & 0xf);
}

u16 IPv4Header::TotalLen() const
{
  return ntohs(total_len);
}

TCPHeader::TCPHeader() = default;

TCPHeader::TCPHeader(const sockaddr_in& from, const sockaddr_in& to, u32 seq, const u8* data,
                     u16 length)
{
  std::memcpy(&source_port, &from.sin_port, 2);
  std::memcpy(&destination_port, &to.sin_port, 2);
  sequence_number = htonl(seq);

  // TODO: Write flags
  // Write data offset
  std::memset(&properties, 0x50, 1);

  window_size = 0xFFFF;

  // Compute the TCP checksum with its pseudo header
  const u32 source_addr = ntohl(from.sin_addr.s_addr);
  const u32 destination_addr = ntohl(to.sin_addr.s_addr);
  const u32 initial_value = (source_addr >> 16) + (source_addr & 0xFFFF) +
                            (destination_addr >> 16) + (destination_addr & 0xFFFF) + IPProto() +
                            Size() + length;
  u32 tcp_checksum = ComputeNetworkChecksum(this, Size(), initial_value);
  tcp_checksum += ComputeNetworkChecksum(data, length);
  while (tcp_checksum > 0xFFFF)
    tcp_checksum = (tcp_checksum >> 16) + (tcp_checksum & 0xFFFF);
  checksum = htons(static_cast<u16>(tcp_checksum));
}

TCPHeader::TCPHeader(const sockaddr_in& from, const sockaddr_in& to, u32 seq, u32 ack, u16 flags)
{
  source_port = from.sin_port;
  destination_port = to.sin_port;
  sequence_number = htonl(seq);
  acknowledgement_number = htonl(ack);
  properties = 0x50 | flags;

  window_size = 0x7c;
  checksum = 0;
}

u16 TCPHeader::Size() const
{
  return 4 * (ntohs(properties) >> 12);
}

u8 TCPHeader::IPProto() const
{
  return static_cast<u8>(IPPROTO_TCP);
}

UDPHeader::UDPHeader() = default;

UDPHeader::UDPHeader(const sockaddr_in& from, const sockaddr_in& to, u16 data_length)
{
  std::memcpy(&source_port, &from.sin_port, 2);
  std::memcpy(&destination_port, &to.sin_port, 2);
  length = htons(Size() + data_length);
}

u16 UDPHeader::Size() const
{
  return static_cast<u16>(SIZE);
}

u8 UDPHeader::IPProto() const
{
  return static_cast<u8>(IPPROTO_UDP);
}

ARPHeader::ARPHeader() = default;

ARPHeader::ARPHeader(u32 from_ip, MACAddress from_mac, u32 to_ip, MACAddress to_mac)
{
  hardware_type = htons(BBA_HARDWARE_TYPE);
  protocol_type = IPV4_HEADER_TYPE;
  hardware_size = MAC_ADDRESS_SIZE;
  protocol_size = IPV4_ADDR_LEN;
  opcode = 0x200;
  sender_ip = from_ip;
  target_ip = to_ip;
  targer_address = to_mac;
  sender_address = from_mac;
}

u16 ARPHeader::Size() const
{
  return static_cast<u16>(SIZE);
}

DHCPBody::DHCPBody() = default;

DHCPBody::DHCPBody(u32 transaction, MACAddress client_address, u32 new_ip, u32 serv_ip)
{
  transaction_id = transaction;
  message_type = DHCPConst::MESSAGE_REPLY;
  hardware_type = BBA_HARDWARE_TYPE;
  hardware_addr = MAC_ADDRESS_SIZE;
  client_mac = client_address;
  your_ip = new_ip;
  server_ip = serv_ip;
}

// Add an option to the DHCP Body
bool DHCPBody::AddDHCPOption(u8 size, u8 fnc, const std::vector<u8>& params)
{
  int i = 0;
  while (options[i] != 0)
  {
    i += options[i + 1] + 2;
    if (i >= std::size(options))
    {
      return false;
    }
  }

  options[i++] = fnc;
  options[i++] = size;
  for (auto val : params)
    options[i++] = val;
  return true;
}

// Compute the network checksum with a 32-bit accumulator using the
// "Normal" order, see RFC 1071 for more details.
u16 ComputeNetworkChecksum(const void* data, u16 length, u32 initial_value)
{
  u32 checksum = initial_value;
  std::size_t index = 0;
  const std::string_view data_view{reinterpret_cast<const char*>(data), length};
  for (u8 b : data_view)
  {
    const bool is_hi = index++ % 2 == 0;
    checksum += is_hi ? b << 8 : b;
  }
  while (checksum > 0xFFFF)
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
  return ~static_cast<u16>(checksum);
}

// Compute the TCP network checksum with a fake header
u16 ComputeTCPNetworkChecksum(const sockaddr_in& from, const sockaddr_in& to, const void* data,
                              u16 length, u8 protocol)
{
  // Compute the TCP checksum with its pseudo header
  const u32 source_addr = ntohl(from.sin_addr.s_addr);
  const u32 destination_addr = ntohl(to.sin_addr.s_addr);
  const u32 initial_value = (source_addr >> 16) + (source_addr & 0xFFFF) +
                            (destination_addr >> 16) + (destination_addr & 0xFFFF) + protocol +
                            length;
  const u32 tcp_checksum = ComputeNetworkChecksum(data, length, initial_value);
  return htons(static_cast<u16>(tcp_checksum));
}

ARPPacket::ARPPacket() = default;

u16 ARPPacket::Size() const
{
  return static_cast<u16>(SIZE);
}

TCPPacket::TCPPacket() = default;

UDPPacket::UDPPacket() = default;

PacketView::PacketView(const u8* ptr, std::size_t size) : m_ptr(ptr), m_size(size)
{
}

std::optional<u16> PacketView::GetEtherType() const
{
  if (m_size < EthernetHeader::SIZE)
    return std::nullopt;
  const std::size_t offset = offsetof(EthernetHeader, ethertype);
  return ntohs(Common::BitCastPtr<u16>(m_ptr + offset));
}

std::optional<ARPPacket> PacketView::GetARPPacket() const
{
  if (m_size < ARPPacket::SIZE)
    return std::nullopt;
  return Common::BitCastPtr<ARPPacket>(m_ptr);
}

std::optional<u8> PacketView::GetIPProto() const
{
  if (m_size < EthernetHeader::SIZE + IPv4Header::MIN_SIZE)
    return std::nullopt;
  return m_ptr[EthernetHeader::SIZE + offsetof(IPv4Header, protocol)];
}

std::optional<TCPPacket> PacketView::GetTCPPacket() const
{
  if (m_size < TCPPacket::MIN_SIZE)
    return std::nullopt;

  TCPPacket packet;
  auto& [eth_header, ip_header, ip_options, tcp_header, tcp_options, data] = packet;
  eth_header = Common::BitCastPtr<EthernetHeader>(m_ptr);
  ip_header = Common::BitCastPtr<IPv4Header>(m_ptr + eth_header.Size());
  ip_options = ParseIPOptions(ip_header);

  const std::size_t tcp_offset = eth_header.Size() + ip_header.Size();
  if (m_size < tcp_offset + sizeof(TCPHeader))
    return std::nullopt;

  tcp_header = Common::BitCastPtr<TCPHeader>(m_ptr + tcp_offset);
  tcp_options = ParseTCPOptions(ip_header, tcp_header);

  const std::size_t data_begin = tcp_offset + tcp_header.Size();
  const std::size_t data_end = eth_header.Size() + ip_header.TotalLen();
  if (m_size < data_end || data_begin > data_end)
    return std::nullopt;
  data = {m_ptr + data_begin, m_ptr + data_end};

  return packet;
}

std::optional<UDPPacket> PacketView::GetUDPPacket() const
{
  if (m_size < UDPPacket::MIN_SIZE)
    return std::nullopt;

  UDPPacket packet;
  auto& [eth_header, ip_header, ip_options, udp_header, data] = packet;
  eth_header = Common::BitCastPtr<EthernetHeader>(m_ptr);
  ip_header = Common::BitCastPtr<IPv4Header>(m_ptr + eth_header.Size());
  ip_options = ParseIPOptions(ip_header);

  const std::size_t udp_offset = eth_header.Size() + ip_header.Size();
  if (m_size < udp_offset + sizeof(UDPHeader))
    return std::nullopt;

  udp_header = Common::BitCastPtr<UDPHeader>(m_ptr + udp_offset);
  const u32 length = ntohs(udp_header.length);

  const std::size_t data_begin = udp_offset + udp_header.Size();
  const std::size_t data_end = udp_offset + length;
  if (m_size < data_end || data_begin > data_end)
    return std::nullopt;
  data = {m_ptr + data_begin, m_ptr + data_end};

  return packet;
}

std::vector<u8> PacketView::ParseIPOptions(const IPv4Header& ip) const
{
  const u32 begin = EthernetHeader::SIZE + ip.MIN_SIZE;
  const u32 end = EthernetHeader::SIZE + ip.Size();
  if (m_size < end)
    return {};
  return {m_ptr + begin, m_ptr + end};
}

std::vector<u8> PacketView::ParseTCPOptions(const IPv4Header& ip, const TCPHeader& tcp) const
{
  const u32 begin = EthernetHeader::SIZE + ip.Size() + tcp.MIN_SIZE;
  const u32 end = EthernetHeader::SIZE + ip.Size() + tcp.Size();
  if (m_size < end)
    return {};
  return {m_ptr + begin, m_ptr + end};
}
}  // namespace Common
