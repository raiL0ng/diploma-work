from math import sqrt

# Класс, содержащий информацию о каком-либо пакете
class PacketInf:

  def __init__( self, numPacket, timePacket, packetSize, mac_src, mac_dest, protoType
              , ip_src, ip_dest, port_src, port_dest, len_data, seq=None, ack=None
              , fl_ack=None, fl_psh=None, fl_rst=None, fl_syn=None, fl_fin=None):
    self.numPacket = int(numPacket)
    self.timePacket = float(timePacket)
    self.packetSize = int(packetSize)
    self.mac_src = mac_src
    self.mac_dest = mac_dest
    self.protoType = protoType
    self.ip_src = ip_src
    self.ip_dest = ip_dest
    self.port_src = port_src
    self.port_dest = port_dest
    self.len_data = int(len_data)
    self.seq = seq
    self.ack = ack
    self.fl_ack = fl_ack
    self.fl_psh = fl_psh
    self.fl_rst = fl_rst
    self.fl_syn = fl_syn
    self.fl_fin = fl_fin


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
    self.syn_flags_freq_data = None
    self.psh_flags_freq_data = None
    self.pkt_amnt_src_data = None
    self.pkt_amnt_dst_data = None
    self.pkt_size_data_src = None
    self.pkt_size_data_dst = None
    self.adjcIPList = None
    self.adjcPacketList = None


# Класс, содержащий информацию о каждой активной сессии
class Session:

  def __init__(self, strtTime, init, target, port):
    self.fl_syn = True
    self.fl_fin = False  
    self.fl_rst = False
    self.strtTime = strtTime
    self.curTime = strtTime + 5
    self.curSec = strtTime + 1
    self.finTime = None
    self.totalTime = None
    self.initiator = init
    self.target = target
    self.port = port
    self.seq_num = None
    self.ack_num = None
    self.is_rdp = False
    self.is_rdpArr = []
    self.cntTr = 0
    self.prob = 0
    self.is_rdpDev = False
    self.pktSize = []
    self.is_rdpPSH = False
    self.cntpsh = 0
    self.cntPktTCP = 0
    self.pshfreq = []  
    self.is_rdpInOut = False
    self.trafficInit = []
    self.trafficTarg = []
    self.cntInitIn = 0
    self.cntTargIn = 0
    self.cntInitOut = 0
    self.cntTargOut = 0
    self.is_rdpIntvl = False
    self.intervals = []
    self.prevPktTime = None


# Обновление значения порядкового номера
  def upd_seq_num(self, seq):
    self.seq_num = int(seq)


# Обновление значения номера подтверждения
  def upd_ack_num(self, ack):
    self.ack_num = ack


# Обновление значения флага FIN
  def upd_fl_fin(self, fin):
    self.fl_fin = True
    self.finTime = fin
    self.totalTime = round(self.finTime - self.strtTime, 2)


# Обновление значения флага RST
  def upd_fl_rst(self, fin):
    self.fl_rst = True
    self.finTime = fin
    self.totalTime = round(self.finTime - self.strtTime, 2)


# Вычисление распределений для выявления признаков RDP 
  def get_rdp_features(self, pkt, isfin=False):
    n = len(self.pktSize)
    if n != 0 and (pkt.timePacket > self.curTime or isfin):
      # Вычисление распределения размеров пакетов
      sum = 0
      for el in self.pktSize:
        sum += el
      avg = sum / n
      sum = 0
      for el in self.pktSize:
        sum += (el - avg) * (el - avg)
      dev = sqrt(sum / n)
      cnt = 0
      for el in self.pktSize:
        if abs(avg - dev * 4) > el or el > (avg + dev * 4):
          cnt += 1
      if cnt * 1.6 > n:
        self.is_rdpDev = True
      else:
        self.is_rdpDev = False
      self.pktSize.clear()
      # Вычисление частоты PSH флагов
      if self.cntPktTCP != 0:
        self.pshfreq.append(self.cntpsh / self.cntPktTCP)
      else:
        self.pshfreq.append(0.0)
      avg = self.get_average_val()
      if self.pshfreq[-1] > 0.0 and abs(avg - self.pshfreq[-1]) < 0.3:
        self.is_rdpPSH = True
      else:
        self.is_rdpPSH = False
      self.cntPktTCP = 0
      self.cntpsh = 0
      # Вычисление отношения входящего трафика на исходящий
      in_len = len(self.trafficInit)
      out_len = len(self.trafficTarg)
      if in_len != 0:
        avg = 0
        for el in self.trafficInit:
          avg += el
        avg = avg / in_len
        avg1 = 0
        for el in self.trafficTarg:
          avg1 += el
        avg1 = avg1 / out_len
        if (in_len > 3 and out_len > 3) and \
           ((1 < avg and avg <= 2.0 and 0.5 <= avg1 and avg1 < 1) or \
            (0.5 <= avg and avg < 1 and 1 < avg1 and avg1 <= 2.0)) and \
           (abs(avg - avg1) > 0.2 and abs(avg - avg1) < 1.8):
          self.is_rdpInOut = True
        else:
          self.is_rdpInOut = False
        self.cntInitIn = 0
        self.cntInitOut = 0
        self.cntTargIn = 0
        self.cntTargOut = 0
        self.trafficInit.clear()
        self.trafficTarg.clear()
      else:
        self.is_rdpInOut = False
      # Вычисление распределения интервалов
      l = len(self.intervals)
      if l != 0:
        sum = 0
        for el in self.intervals:
          sum += el
        avg = sum / l
        sum = 0
        for el in self.intervals:
          sum += (el - avg) * (el - avg)
        dev = sqrt(sum / l)
        cnt = 0
        if l > 40:
          for el in self.intervals:
            if el > abs(avg + dev / 1.8) or el < abs(avg - dev / 1.8):
              cnt += 1
        if cnt * 2 > l:
          self.is_rdpIntvl = True
        else:
          self.is_rdpIntvl = False
        self.intervals.clear()
        self.prevPktTime = None
      else:
        self.is_rdpIntvl = False
      self.curTime += 5
      self.rdp_check()
      if len(self.is_rdpArr) == 0:
        self.is_rdp = False
      else:
        self.is_rdp = self.is_rdpArr[-1]
    self.pktSize.append(pkt.packetSize)
    if pkt.protoType == 'TCP' and pkt.ip_src == self.initiator:
      self.cntPktTCP += 1
      if pkt.fl_psh == '1':
        self.cntpsh += 1
    if self.prevPktTime != None:
      self.intervals.append(pkt.timePacket - self.prevPktTime)
      self.prevPktTime = pkt.timePacket
    else:
      self.prevPktTime = pkt.timePacket


# Вычисление входящего и исходящего трафика за единицу времени
  def get_in_out_traffic(self, pkt):
    if pkt.timePacket > self.curSec:
      if self.cntInitOut != 0:
        self.trafficInit.append(self.cntInitIn / self.cntInitOut)
      else:
        self.trafficInit.append(0.0)
      if self.cntTargOut != 0:
        self.trafficTarg.append(self.cntTargIn / self.cntTargOut)
      else:
        self.trafficTarg.append(0.0)
      self.cntInitIn = 0
      self.cntTargIn = 0
      self.cntInitOut = 0
      self.cntTargOut = 0
      self.curSec += 1
    if pkt.ip_src == self.initiator:
      self.cntInitOut += 1
    if pkt.ip_dest == self.initiator:
      self.cntInitIn += 1
    if pkt.ip_src == self.target:
      self.cntTargOut += 1
    if pkt.ip_dest == self.target:
      self.cntTargIn += 1


# Анализ значений списка rdpArr
  def rdpArr_check(self):
    l = len(self.is_rdpArr)
    if l > 2:
      return self.cntTr > l - self.cntTr
    else:
      return False
    

# Нахождение среднего значения частот PSH-флагов
  def get_average_val(self):
    n = len(self.pshfreq)
    if n >= 4:
      return (self.pshfreq[n - 4] + self.pshfreq[n - 3] + \
              self.pshfreq[n - 2] ) / 3
    return -10


# Осуществление проверки текущего интервала
# времени на наличие RDP-трафика
  def rdp_check(self):
    if self.port == '3389':
      self.is_rdpArr.append(True)
      self.cntTr += 1
      self.prob = 100
    elif self.prob > 70:
      self.is_rdpArr.append(True)
      self.cntTr += 1
      self.prob = round((self.cntTr / len(self.is_rdpArr)) * 100)
    else:
      if (self.is_rdpInOut and self.is_rdpIntvl) or \
         (self.is_rdpInOut and self.is_rdpPSH and self.is_rdpDev):
        self.is_rdpArr.append(True)
        self.cntTr += 1
      else:
        if (self.is_rdpInOut or self.is_rdpIntvl):
          if (self.is_rdpDev and self.rdpArr_check()) or \
             (not self.is_rdpDev and self.rdpArr_check()):
            self.is_rdpArr.append(True)
            self.cntTr += 1
          else:
            self.is_rdpArr.append(False)
        else:
          self.is_rdpArr.append(False)
      if len(self.is_rdpArr) > 4:
        self.prob = round((self.cntTr / len(self.is_rdpArr)) * 100)


# Подсчет значений списка rdpArr для анализа трафика
  def fin_rdp_check(self):
    cnt = 0
    for el in self.is_rdpArr:
      if el:
        cnt += 1
    self.is_rdp = cnt > len(self.is_rdpArr) - cnt
