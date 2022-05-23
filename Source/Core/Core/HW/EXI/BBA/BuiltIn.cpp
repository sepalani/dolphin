// Copyright 2022 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <SFML/Network.hpp>

#include "Common/BitUtils.h"
#include "Common/Logging/Log.h"
#include "Common/MsgHandler.h"
#include "Core/HW/EXI/BBA/BuiltIn.h"
#include "Core/HW/EXI/EXI_Device.h"
#include "Core/HW/EXI/EXI_DeviceEthernet.h"

namespace ExpansionInterface
{
u64 GetTickCountStd()
{
  using namespace std::chrono;
  return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void SetHardwareInfo(u8* data, Common::MACAddress dest, Common::MACAddress src)
{
  Common::EthernetHeader* hwpart = (Common::EthernetHeader*)data;
  *hwpart = Common::EthernetHeader(IP_PROTOCOL);
  hwpart->destination = dest;
  hwpart->source = src;
}

std::tuple<Common::EthernetHeader*, Common::IPv4Header*, Common::TCPHeader*>
GetTCPHeaders(u8* data, Common::MACAddress dest, Common::MACAddress src)
{
  SetHardwareInfo(data, dest, src);
  return std::tuple<Common::EthernetHeader*, Common::IPv4Header*, Common::TCPHeader*>(
      (Common::EthernetHeader*)data, (Common::IPv4Header*)&data[14],
      (Common::TCPHeader*)&data[0x22]);
}

std::tuple<Common::EthernetHeader*, Common::IPv4Header*, Common::UDPHeader*>
GetUDPHeaders(u8* data, Common::MACAddress dest, Common::MACAddress src)
{
  SetHardwareInfo(data, dest, src);
  return std::tuple<Common::EthernetHeader*, Common::IPv4Header*, Common::UDPHeader*>(
      (Common::EthernetHeader*)data, (Common::IPv4Header*)&data[14],
      (Common::UDPHeader*)&data[0x22]);
}

bool CEXIETHERNET::BuiltInBBAInterface::Activate()
{
  if (IsActivated())
    return true;

  m_active = true;
  for (auto& buf : m_queue_data)
    buf.reserve(2048);
  m_fake_mac = Common::GenerateMacAddress(Common::MACConsumer::BBA);
  const u32 ip = m_local_ip.empty() ? sf::IpAddress::getLocalAddress().toInteger() :
                                      sf::IpAddress(m_local_ip).toInteger();
  m_current_ip = htonl(ip);
  m_router_ip = (m_current_ip & 0xFFFFFF) | 0x01000000;
  // clear all ref
  for (auto& ref : network_ref)
  {
    ref.ip = 0;
  }

  return RecvInit();
}

void CEXIETHERNET::BuiltInBBAInterface::Deactivate()
{
  // Is the BBA Active? If not skip shutdown
  if (!IsActivated())
    return;
  // Signal read thread to exit.
  m_read_enabled.Clear();
  m_read_thread_shutdown.Set();
  m_active = false;

  // kill all active socket
  for (auto& ref : network_ref)
  {
    if (ref.ip != 0)
    {
      ref.type == IPPROTO_TCP ? ref.tcp_socket.disconnect() : ref.udp_socket.unbind();
    }
    ref.ip = 0;
  }

  // Wait for read thread to exit.
  if (m_read_thread.joinable())
    m_read_thread.join();
}

bool CEXIETHERNET::BuiltInBBAInterface::IsActivated()
{
  return m_active;
}

void CEXIETHERNET::BuiltInBBAInterface::WriteToQueue(const u8* data, std::size_t length)
{
  m_queue_data[m_queue_write].resize(length);
  std::memcpy(m_queue_data[m_queue_write].data(), data, length);
  if (((m_queue_write + 1) & 15) == m_queue_read)
  {
    return;
  }
  m_queue_write = (m_queue_write + 1) & 15;
}

void CEXIETHERNET::BuiltInBBAInterface::HandleARP(const Common::ARPPacket& packet)
{
  const auto& [hwdata, arpdata] = packet;
  std::vector<u8> in_frame;
  in_frame.resize(0x2a);
  Common::EthernetHeader* hwpart = (Common::EthernetHeader*)in_frame.data();
  *hwpart = Common::EthernetHeader(ARP_PROTOCOL);
  hwpart->destination = *(Common::MACAddress*)&m_eth_ref->mBbaMem[BBA_NAFR_PAR0];
  hwpart->source = m_fake_mac;

  Common::ARPHeader* arppart = (Common::ARPHeader*)&in_frame.at(14);
  Common::MACAddress bba_mac = *(Common::MACAddress*)&m_eth_ref->mBbaMem[BBA_NAFR_PAR0];
  if (arpdata.target_ip == m_current_ip)
  {
    // game asked for himself, reply with his mac address
    *arppart = Common::ARPHeader(arpdata.target_ip, bba_mac, m_current_ip, bba_mac);
  }
  else
  {
    *arppart = Common::ARPHeader(arpdata.target_ip, m_fake_mac, m_current_ip, bba_mac);
  }

  WriteToQueue(in_frame.data(), in_frame.size());
}

void CEXIETHERNET::BuiltInBBAInterface::HandleDHCP(const Common::UDPPacket& packet,
                                                   const Common::DHCPBody& request)
{
  const auto& [hwdata, ip, udpdata] = packet;
  std::vector<u8> in_frame;
  in_frame.reserve(Common::DHCPBody::SIZE + 0x2a);
  in_frame.resize(0x156);
  Common::DHCPBody* reply = (Common::DHCPBody*)&in_frame.at(0x2a);
  sockaddr_in from;
  sockaddr_in to;
  std::memset(in_frame.data(), 0, in_frame.size());

  // build layer
  auto [hwpart, ippart, udppart] = GetUDPHeaders(
      in_frame.data(), *(Common::MACAddress*)&m_eth_ref->mBbaMem[BBA_NAFR_PAR0], m_fake_mac);

  from.sin_addr.s_addr = m_router_ip;
  from.sin_family = IPPROTO_UDP;
  from.sin_port = htons(67);
  to.sin_addr.s_addr = m_current_ip;
  to.sin_family = IPPROTO_UDP;
  to.sin_port = udpdata.source_port;
  const std::vector<u8> ip_part = {((u8*)&m_router_ip)[0], ((u8*)&m_router_ip)[1],
                                   ((u8*)&m_router_ip)[2], ((u8*)&m_router_ip)[3]};

  *ippart = Common::IPv4Header(308, IPPROTO_UDP, from, to);

  *udppart = Common::UDPHeader(from, to, 300);

  *reply = Common::DHCPBody(request.transaction_id,
                            *(Common::MACAddress*)&m_eth_ref->mBbaMem[BBA_NAFR_PAR0], m_current_ip,
                            m_router_ip);

  // options
  request.options[2] == 1 ? reply->AddDHCPOption(1, 53, std::vector<u8>{2}) :
                             reply->AddDHCPOption(1, 53, std::vector<u8>{5});
  reply->AddDHCPOption(4, 54, ip_part);                            // dhcp server ip
  reply->AddDHCPOption(4, 51, std::vector<u8>{0, 1, 0x51, 0x80});  // lease time 24h
  reply->AddDHCPOption(4, 58, std::vector<u8>{0, 1, 0x51, 0x80});  // renewal
  reply->AddDHCPOption(4, 59, std::vector<u8>{0, 1, 0x51, 0x80});  // rebind
  reply->AddDHCPOption(4, 1, std::vector<u8>{255, 255, 255, 0});   // submask
  reply->AddDHCPOption(4, 28,
                       std::vector<u8>{ip_part[0], ip_part[1], ip_part[2], 255});  // broadcast ip
  reply->AddDHCPOption(4, 6, ip_part);                                             // dns server
  reply->AddDHCPOption(3, 15, std::vector<u8>{0x6c, 0x61, 0x6e});  // domaine name "lan"
  reply->AddDHCPOption(4, 3, ip_part);                             // router ip
  reply->AddDHCPOption(0, 255, {});                                // end

  udppart->checksum = Common::ComputeTCPNetworkChecksum(from, to, udppart, 308, IPPROTO_UDP);

  WriteToQueue(in_frame.data(), in_frame.size());
}

StackRef* CEXIETHERNET::BuiltInBBAInterface::GetAvailableSlot(u16 port)
{
  if (port > 0)  // existing connection?
  {
    for (auto& ref : network_ref)
    {
      if (ref.ip != 0 && ref.local == port)
        return &ref;
    }
  }
  for (auto& ref : network_ref)
  {
    if (ref.ip == 0)
      return &ref;
  }
  return nullptr;
}

StackRef* CEXIETHERNET::BuiltInBBAInterface::GetTCPSlot(u16 src_port, u16 dst_port, u32 ip)
{
  for (auto& ref : network_ref)
  {
    if (ref.ip == ip && ref.remote == dst_port && ref.local == src_port)
    {
      return &ref;
    }
  }
  return nullptr;
}

std::vector<u8> BuildFINFrame(StackRef* ref)
{
  std::vector<u8> buf;
  buf.resize(0x36);
  std::memset(buf.data(), 0, buf.size());
  auto [hwpart, ippart, tcppart] = GetTCPHeaders(buf.data(), ref->bba_mac, ref->my_mac);

  *ippart = Common::IPv4Header(20, IPPROTO_TCP, ref->from, ref->to);

  *tcppart = Common::TCPHeader(ref->from, ref->to, ref->seq_num, ref->ack_num,
                               TCP_FLAG_FIN | TCP_FLAG_ACK | TCP_FLAG_RST);
  tcppart->checksum =
      Common::ComputeTCPNetworkChecksum(ref->from, ref->to, tcppart, 20, IPPROTO_TCP);

  for (auto& tcp_buf : ref->tcp_buffers)
    tcp_buf.used = false;
  return buf;
}

std::vector<u8> BuildAckFrame(StackRef* ref)
{
  std::vector<u8> buf;
  buf.resize(0x36);
  std::memset(buf.data(), 0, buf.size());
  auto [hwpart, ippart, tcppart] = GetTCPHeaders(buf.data(), ref->bba_mac, ref->my_mac);

  *ippart = Common::IPv4Header(20, IPPROTO_TCP, ref->from, ref->to);

  *tcppart = Common::TCPHeader(ref->from, ref->to, ref->seq_num, ref->ack_num, TCP_FLAG_ACK);
  tcppart->checksum =
      Common::ComputeTCPNetworkChecksum(ref->from, ref->to, tcppart, 20, IPPROTO_TCP);

  return buf;
}

void CEXIETHERNET::BuiltInBBAInterface::HandleTCPFrame(const Common::TCPPacket& packet, const std::vector<u8>& data)
{
  const auto& [hwdata, ipdata, tcpdata] = packet;
  sf::IpAddress target;
  StackRef* ref = GetTCPSlot(tcpdata.source_port, tcpdata.destination_port,
                             Common::BitCast<u32>(ipdata.destination_addr));
  if (tcpdata.properties & (TCP_FLAG_FIN | TCP_FLAG_RST))  // TODO: Fix endianness issues
  {
    if (ref == nullptr)
      return;  // not found

    ref->ack_num++;
    const std::vector<u8> buf = BuildFINFrame(ref);
    WriteToQueue(buf.data(), buf.size());
    ref->ip = 0;
    ref->tcp_socket.disconnect();
  }
  else if (tcpdata.properties & TCP_FLAG_SIN)
  {
    // new connection
    if (ref != nullptr)
      return;
    ref = GetAvailableSlot(0);

    ref->delay = GetTickCountStd();
    ref->local = tcpdata.source_port;
    ref->remote = tcpdata.destination_port;
    ref->ack_num = htonl(tcpdata.sequence_number) + 1;
    ref->ack_base = ref->ack_num;
    ref->seq_num = 0x1000000;
    ref->window_size = htons(tcpdata.window_size);
    ref->type = IPPROTO_TCP;
    for (auto& tcp_buf : ref->tcp_buffers)
      tcp_buf.used = false;
    ref->from.sin_addr.s_addr = Common::BitCast<u32>(ipdata.destination_addr);
    ref->from.sin_port = tcpdata.destination_port;
    ref->to.sin_addr.s_addr = Common::BitCast<u32>(ipdata.source_addr);
    ref->to.sin_port = tcpdata.source_port;
    ref->bba_mac = *(Common::MACAddress*)&m_eth_ref->mBbaMem[BBA_NAFR_PAR0];
    ref->my_mac = m_fake_mac;
    ref->tcp_socket.setBlocking(false);

    // reply with a sin_ack
    std::vector<u8> in_frame;
    in_frame.resize(0x3e);
    std::memset(in_frame.data(), 0, in_frame.size());
    auto [hwpart, ippart, tcppart] = GetTCPHeaders(in_frame.data(), ref->bba_mac, ref->my_mac);

    *ippart = Common::IPv4Header(28, IPPROTO_TCP, ref->from, ref->to);

    *tcppart = Common::TCPHeader(ref->from, ref->to, ref->seq_num, ref->ack_num,
                                 0x70 | TCP_FLAG_SIN | TCP_FLAG_ACK);
    const u8 options[] = {0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x01, 0x01};
    std::memcpy(&in_frame.at(0x36), options, std::size(options));

    // do checksum
    tcppart->checksum =
        Common::ComputeTCPNetworkChecksum(ref->from, ref->to, tcppart, 28, IPPROTO_TCP);

    ref->seq_num++;
    target = sf::IpAddress(htonl(Common::BitCast<u32>(ipdata.destination_addr)));
    ref->tcp_socket.connect(target, ntohs(tcpdata.destination_port));
    ref->ready = false;
    ref->ip = Common::BitCast<u32>(ipdata.destination_addr);

    std::memcpy(&ref->tcp_buffers[0].data, in_frame.data(), in_frame.size());
    ref->tcp_buffers[0].data_size = (u16)in_frame.size();
    ref->tcp_buffers[0].seq_id = ref->seq_num - 1;
    ref->tcp_buffers[0].tick = GetTickCountStd() - 900;  // delay
    ref->tcp_buffers[0].used = true;
  }
  else
  {
    // data packet
    if (ref == nullptr)
      return;  // not found

    const int c = (tcpdata.properties & 0xf0) >> 2;  // header size
    const int size = ntohs(ipdata.total_len) - 20 - c;
    const u32 this_seq = ntohl(tcpdata.sequence_number);

    if (size > 0)
    {
      // only if data
      if ((int)(this_seq - ref->ack_num) >= 0 && data.size() >= size)
      {
        ref->tcp_socket.send(data.data(), size);
        ref->ack_num += size;
      }

      // send ack
      const std::vector<u8> buf = BuildAckFrame(ref);
      WriteToQueue(buf.data(), buf.size());
    }
    // update windows size
    ref->window_size = ntohs(tcpdata.window_size);

    // clear any ack data
    if (tcpdata.properties & TCP_FLAG_ACK)
    {
      const u32 ack_num = ntohl(tcpdata.acknowledgement_number);
      for (auto& tcp_buf : ref->tcp_buffers)
      {
        if (!tcp_buf.used || tcp_buf.seq_id >= ack_num)
          continue;
        Common::TCPHeader* tcppart = (Common::TCPHeader*)&tcp_buf.data[0x22];
        const u32 seq_end =
            tcp_buf.seq_id + tcp_buf.data_size - ((tcppart->properties & 0xf0) >> 2) - 34;
        if (seq_end <= ack_num)
        {
          tcp_buf.used = false;  // confirmed data received
          if (!ref->ready && !ref->tcp_buffers[0].used)
            ref->ready = true;
          continue;
        }
        // partial data, adjust the packet for next ack
        const u16 ack_size = ack_num - tcp_buf.seq_id;
        const u16 new_data_size = tcp_buf.data_size - 0x36 - ack_size;
        std::memmove(&tcp_buf.data[0x36], &tcp_buf.data[0x36 + ack_size], new_data_size);
        tcp_buf.data_size -= ack_size;
        tcp_buf.seq_id += ack_size;
        tcppart->sequence_number = htonl(tcp_buf.seq_id);
        Common::IPv4Header* ippart = (Common::IPv4Header*)&tcp_buf.data[14];
        ippart->total_len = htons(tcp_buf.data_size - 14);
        tcppart->checksum = 0;
        tcppart->checksum = Common::ComputeTCPNetworkChecksum(ref->from, ref->to, tcppart,
                                                              new_data_size + 20, IPPROTO_TCP);
      }
    }
  }
}

/// <summary>
/// This is a litle hack, Mario Kart open some UDP port
/// and listen to it. We open it on our side manualy.
/// </summary>
void CEXIETHERNET::BuiltInBBAInterface::InitUDPPort(u16 port)
{
  StackRef* ref = GetAvailableSlot(htons(port));
  if (ref == nullptr || ref->ip != 0)
    return;
  ref->ip = m_router_ip;  // change for ip
  ref->local = htons(port);
  ref->remote = htons(port);
  ref->type = IPPROTO_UDP;
  ref->bba_mac = *(Common::MACAddress*)&m_eth_ref->mBbaMem[BBA_NAFR_PAR0];
  ref->my_mac = m_fake_mac;
  ref->from.sin_addr.s_addr = 0;
  ref->from.sin_port = htons(port);
  ref->to.sin_addr.s_addr = m_current_ip;
  ref->to.sin_port = htons(port);
  ref->udp_socket.setBlocking(false);
  if (ref->udp_socket.bind(port) != sf::Socket::Done)
  {
    ERROR_LOG_FMT(SP1, "Couldn't open UDP socket");
    PanicAlertFmt("Could't open port {:x}, this game might not work proprely in LAN mode.", port);
    return;
  }
}

void CEXIETHERNET::BuiltInBBAInterface::HandleUDPFrame(const Common::UDPPacket& packet, const std::vector<u8>& data)
{
  const auto& [hwdata, ipdata, udpdata] = packet;
  sf::IpAddress target;
  const u32 destination_addr = ipdata.destination_addr == Common::IP_ADDR_ANY ?
                                   m_router_ip :  // dns request
                                   Common::BitCast<u32>(ipdata.destination_addr);

  StackRef* ref = GetAvailableSlot(udpdata.source_port);
  if (ref->ip == 0)
  {
    ref->ip = destination_addr;  // change for ip
    ref->local = udpdata.source_port;
    ref->remote = udpdata.destination_port;
    ref->type = IPPROTO_UDP;
    ref->bba_mac = *(Common::MACAddress*)&m_eth_ref->mBbaMem[BBA_NAFR_PAR0];
    ref->my_mac = m_fake_mac;
    ref->from.sin_addr.s_addr = destination_addr;
    ref->from.sin_port = udpdata.destination_port;
    ref->to.sin_addr.s_addr = Common::BitCast<u32>(ipdata.source_addr);
    ref->to.sin_port = udpdata.source_port;
    ref->udp_socket.setBlocking(false);
    if (ref->udp_socket.bind(htons(udpdata.source_port)) != sf::Socket::Done)
    {
      PanicAlertFmt(
          "Port {:x} is already in use, this game might not work as intented in LAN Mode.",
          htons(udpdata.source_port));
      if (ref->udp_socket.bind(sf::Socket::AnyPort) != sf::Socket::Done)
      {
        ERROR_LOG_FMT(SP1, "Couldn't open UDP socket");
        return;
      }
    }
    if (ntohs(udpdata.destination_port) == 1900)
    {
      InitUDPPort(26512);                                                // MK DD and 1080
      InitUDPPort(26502);                                                // Air Ride
      if (udpdata.length > 150)
      {
        // Quick hack to unlock the connection, throw it back at him
        std::vector<u8> in_frame;
        in_frame.resize(ntohs(ipdata.total_len) + 14);
        Common::EthernetHeader* hwpart = (Common::EthernetHeader*)in_frame.data();
        Common::IPv4Header* ippart = (Common::IPv4Header*)&in_frame[14];
        std::memcpy(in_frame.data(), &hwdata, in_frame.size());
        hwpart->destination = hwdata.source;
        hwpart->source = hwdata.destination;
        ippart->destination_addr = ipdata.source_addr;
        if (ipdata.destination_addr == Common::IP_ADDR_SSDP)
          ippart->source_addr = Common::IP_ADDR_BROADCAST;
        else
          ippart->source_addr = Common::BitCast<Common::IPAddress>(destination_addr);
        WriteToQueue(in_frame.data(), in_frame.size());
      }
    }
  }
  if (ntohs(udpdata.destination_port) == 53)
  {
    target = sf::IpAddress(m_dns_ip.c_str());  // dns server ip
  }
  else
  {
    target = sf::IpAddress(ntohl(Common::BitCast<u32>(ipdata.destination_addr)));
  }
  ref->udp_socket.send(data.data(), data.size(), target, ntohs(udpdata.destination_port));
}

bool CEXIETHERNET::BuiltInBBAInterface::SendFrame(const u8* frame, u32 size)
{
  std::lock_guard<std::mutex> lock(m_mtx);
  const Common::PacketView view(frame, size);

  const std::optional<u16> ethertype = view.GetEtherType();
  if (!ethertype.has_value())
  {
    ERROR_LOG_FMT(SP1, "Unable to send frame with invalid ethernet header");
    return false;
  }

  switch (*ethertype)
  {
  case Common::IPV4_ETHERTYPE:
  {
    const std::optional<u8> ip_proto = view.GetIPProto();
    if (!ip_proto.has_value())
    {
      ERROR_LOG_FMT(SP1, "Unable to send frame with invalid IP header");
      return false;
    }

    switch (*ip_proto)
    {
    case IPPROTO_UDP:
    {
      const auto udp_packet = view.GetUDPPacket();
      if (!udp_packet.has_value())
      {
        ERROR_LOG_FMT(SP1, "Unable to send frame with invalid UDP header");
        return false;
      }

      const std::vector<u8> udp_data = view.GetUDPData();
      if (ntohs(udp_packet->udp_header.destination_port) == 67)
      {
        Common::DHCPBody request;
        std::memcpy(&request, udp_data.data(), udp_data.size());
        HandleDHCP(*udp_packet, request);
      }
      else
      {
        HandleUDPFrame(*udp_packet, udp_data);
      }
      break;
    }

    case IPPROTO_TCP:
    {
      const auto tcp_packet = view.GetTCPPacket();
      if (!tcp_packet.has_value())
      {
        ERROR_LOG_FMT(SP1, "Unable to send frame with invalid TCP header");
        return false;
      }

      const std::vector<u8> tcp_data = view.GetTCPData();
      HandleTCPFrame(*tcp_packet, tcp_data);
      break;
    }
    }
    break;
  }

  case Common::ARP_ETHERTYPE:
  {
    const auto arp_packet = view.GetARPPacket();
    if (!arp_packet.has_value())
    {
      ERROR_LOG_FMT(SP1, "Unable to send frame with invalid ARP header");
      return false;
    }

    HandleARP(*arp_packet);
    break;
  }

  default:
    ERROR_LOG_FMT(SP1, "Unsupported EtherType {#06x}", *ethertype);
    return false;
  }

  m_eth_ref->SendComplete();
  return true;
}

size_t TryGetDataFromSocket(StackRef* ref, u8* buffer)
{
  size_t datasize = 0;  // this will be filled by the socket read later
  unsigned short remote_port;

  switch (ref->type)
  {
  case IPPROTO_UDP:
    ref->udp_socket.receive(&buffer[0x2a], MAX_UDP_LENGTH, datasize, ref->target, remote_port);
    if (datasize > 0)
    {
      std::memset(buffer, 0, 0x2a);
      auto [hwpart, ipdata, udpdata] = GetUDPHeaders(buffer, ref->bba_mac, ref->my_mac);

      ref->from.sin_port = htons(remote_port);
      ref->from.sin_addr.s_addr = htonl(ref->target.toInteger());
      *ipdata = Common::IPv4Header((u16)(datasize + 8), IPPROTO_UDP, ref->from, ref->to);

      *udpdata = Common::UDPHeader(ref->from, ref->to, (u16)datasize);
      udpdata->checksum = Common::ComputeTCPNetworkChecksum(ref->from, ref->to, udpdata,
                                                            (u16)(datasize + 8), IPPROTO_UDP);
      datasize += 0x2a;
    }
    break;

  case IPPROTO_TCP:
    sf::Socket::Status st = sf::Socket::Status::Done;
    TcpBuffer* tcp_buffer = nullptr;
    for (auto& tcp_buf : ref->tcp_buffers)
    {
      if (tcp_buf.used)
        continue;
      tcp_buffer = &tcp_buf;
      break;
    }

    // set default size to 0 to avoid issue
    datasize = 0;
    const bool can_go = (GetTickCountStd() - ref->poke_time > 100 || ref->window_size > 2000);
    if (tcp_buffer != nullptr && ref->ready && can_go)
      st = ref->tcp_socket.receive(&buffer[0x36], MAX_TCP_LENGTH, datasize);

    if (datasize > 0)
    {
      std::memset(buffer, 0, 0x36);
      auto [hwpart, ipdata, tcpdata] = GetTCPHeaders(buffer, ref->bba_mac, ref->my_mac);

      *ipdata = Common::IPv4Header((u16)(datasize + 20), IPPROTO_TCP, ref->from, ref->to);

      *tcpdata = Common::TCPHeader(ref->from, ref->to, ref->seq_num, ref->ack_num, TCP_FLAG_ACK);
      tcpdata->checksum = Common::ComputeTCPNetworkChecksum(ref->from, ref->to, tcpdata,
                                                            (u16)(datasize + 20), IPPROTO_TCP);

      // build buffer
      tcp_buffer->seq_id = ref->seq_num;
      tcp_buffer->data_size = (u16)datasize + 0x36;
      tcp_buffer->tick = GetTickCountStd();
      std::memcpy(&tcp_buffer->data[0], buffer, datasize + 0x36);
      tcp_buffer->seq_id = ref->seq_num;
      tcp_buffer->used = true;
      ref->seq_num += (u32)datasize;
      ref->poke_time = GetTickCountStd();
      datasize += 0x36;
    }
    if (GetTickCountStd() - ref->delay > 3000)
    {
      if (st == sf::Socket::Disconnected || st == sf::Socket::Error)
      {
        ref->ip = 0;
        ref->tcp_socket.disconnect();
        const std::vector<u8> buf = BuildFINFrame(ref);
        datasize = buf.size();
        std::memcpy(buffer, buf.data(), datasize);
      }
    }
    break;
  }

  return datasize;
}

void CEXIETHERNET::BuiltInBBAInterface::ReadThreadHandler(CEXIETHERNET::BuiltInBBAInterface* self)
{
  while (!self->m_read_thread_shutdown.IsSet())
  {
    // make thread less cpu hungry
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    if (!self->m_read_enabled.IsSet())
      continue;
    size_t datasize = 0;

    u8 wp = self->m_eth_ref->page_ptr(BBA_RWP);
    const u8 rp = self->m_eth_ref->page_ptr(BBA_RRP);
    if (rp > wp)
      wp += 16;

    if ((wp - rp) >= 8)
      continue;

    std::lock_guard<std::mutex> lock(self->m_mtx);
    // process queue file first
    if (self->m_queue_read != self->m_queue_write)
    {
      datasize = self->m_queue_data[self->m_queue_read].size();
      if (datasize > BBA_RECV_SIZE)
      {
        ERROR_LOG_FMT(
            SP1, "Frame size is exceiding BBA capacity, frame stack might be corrupted"
                 "Killing Dolphin...");
        std::exit(0);
      }
      std::memcpy(self->m_eth_ref->mRecvBuffer.get(), self->m_queue_data[self->m_queue_read].data(),
                  datasize);
      self->m_queue_read++;
      self->m_queue_read &= 15;
    }
    else
    {
      // test connections data
      for (auto& net_ref : self->network_ref)
      {
        if (net_ref.ip == 0)
          continue;
        datasize = TryGetDataFromSocket(&net_ref, self->m_eth_ref->mRecvBuffer.get());
        if (datasize > 0)
          break;
      }
    }

    // test and add any sleeping tcp data
    for (auto& net_ref : self->network_ref)
    {
      if (net_ref.ip == 0 || net_ref.type != IPPROTO_TCP)
        continue;
      for (auto& tcp_buf : net_ref.tcp_buffers)
      {
        if (!tcp_buf.used || (GetTickCountStd() - tcp_buf.tick) <= 1000)
          continue;

        tcp_buf.tick = GetTickCountStd();
        // late data, resend
        if (((self->m_queue_write + 1) & 15) != self->m_queue_read)
        {
          self->WriteToQueue(&tcp_buf.data[0], tcp_buf.data_size);
        }
      }
    }

    if (datasize > 0)
    {
      u8* b = &self->m_eth_ref->mRecvBuffer[0];
      Common::EthernetHeader* hwdata = (Common::EthernetHeader*)b;
      if (hwdata->ethertype == 0x8)  // IP_PROTOCOL
      {
        Common::IPv4Header* ipdata = (Common::IPv4Header*)&b[14];
        ipdata->identification = ntohs(++self->m_ip_frame_id);
        ipdata->header_checksum = 0;
        ipdata->header_checksum = htons(Common::ComputeNetworkChecksum(ipdata, 20));
      }
      self->m_eth_ref->mRecvBufferLength = datasize > 64 ? (u32)datasize : 64;
      self->m_eth_ref->RecvHandlePacket();
    }
  }
}

bool CEXIETHERNET::BuiltInBBAInterface::RecvInit()
{
  m_read_thread = std::thread(ReadThreadHandler, this);
  return true;
}

void CEXIETHERNET::BuiltInBBAInterface::RecvStart()
{
  m_read_enabled.Set();
}

void CEXIETHERNET::BuiltInBBAInterface::RecvStop()
{
  m_read_enabled.Clear();
  for (auto& net_ref : network_ref)
  {
    if (net_ref.ip != 0)
    {
      net_ref.type == IPPROTO_TCP ? net_ref.tcp_socket.disconnect() : net_ref.udp_socket.unbind();
    }
    net_ref.ip = 0;
  }
  m_queue_read = 0;
  m_queue_write = 0;
}
}  // namespace ExpansionInterface
