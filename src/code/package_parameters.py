from math import sqrt

# Класс, содержащий информацию о каком-либо пакете
class PacketInf:

  def __init__(self, lst):
      self.numPacket = int(lst[0])
      self.timePacket = float(lst[1])
      self.packetSize = int(lst[2])
      self.mac_src, self.mac_dest, self.protoType = lst[3], lst[4], lst[5]
      self.ip_src, self.ip_dest = lst[6], lst[7]
      self.port_src, self.port_dest, self.len_data = int(lst[8]), int(lst[9]), int(lst[10])

      if self.protoType == 'TCP':
          self.seq, self.ack = lst[11], lst[12]
          self.fl_ack, self.fl_psh = lst[13], lst[14]
          self.fl_rst, self.fl_syn = lst[15], lst[16]
          self.fl_fin, self.win_size = lst[17], 0
          if len(lst) > 18:
              self.win_size = int(lst[18])

# Класс, содержащий информацию относительно какого-либо IP-адреса
class ExploreObject:

  def __init__(self, ip):
    self.ip = ip
    self.strt_time, self.fin_time = None, None
    self.amnt_packet, self.avg_packet_num = None, None
    self.avg_packet_size = None

    self.commonPorts = None
    self.in_out_rel_data, self.ack_flags_diff_data = None, None
    self.avg_time_intervals, self.dev_time_intervals = None, None
    self.psh_flags_freq_data, self.ack_flags_freq_data = None, None
    self.pkt_amnt_src_data, self.pkt_amnt_dst_data = None, None
    self.adjcIPList, self.adjcPacketList, self.avg_winsize_dest = None, None, None