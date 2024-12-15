from math import sqrt

# Класс, содержащий информацию о каком-либо пакете
class PacketInf:

  def __init__(self, lst):
      self.numPacket = int(lst[0])
      self.timePacket = float(lst[1])
      self.packetSize = int(lst[2])
      self.mac_src = lst[3]
      self.mac_dest = lst[4]
      self.protoType = lst[5]
      self.ip_src = lst[6]
      self.ip_dest = lst[7]
      self.port_src = int(lst[8])
      self.port_dest = int(lst[9])
      self.len_data = int(lst[10])
      if self.protoType == 'TCP':
          self.seq = lst[11]
          self.ack = lst[12]
          self.fl_ack = lst[13]
          self.fl_psh = lst[14]
          self.fl_rst = lst[15]
          self.fl_syn = lst[16]
          self.fl_fin = lst[17]
          self.win_size = 0
          if len(lst) > 18:
              self.win_size = int(lst[18])



# Класс, содержащий информацию относительно какого-либо IP-адреса
class ExploreObject:

  def __init__(self, ip):
    self.ip = ip
    self.strt_time = None
    self.fin_time = None
    self.amnt_packet = None
    self.avg_packet_num = None
    self.avg_packet_size = None

    self.commonPorts = None
    self.in_out_rel_data = None
    self.ack_flags_diff_data = None
    self.udp_tcp_rel_data = None
    self.avg_time_intervals = None
    self.dev_time_intervals = None
    self.syn_flags_freq_data = None
    self.fin_flags_freq_data = None
    self.psh_flags_freq_data = None
    self.psh_flags_freq_data_src = None
    self.ack_flags_freq_data = None
    self.ack_flags_freq_data_src = None
    self.pkt_amnt_src_data = None
    self.pkt_amnt_dst_data = None
    self.pkt_size_data_src = None
    self.pkt_size_data_dst = None
    self.adjcIPList = None
    self.adjcPacketList = None
    self.avg_winsize_dest = None