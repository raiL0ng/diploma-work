import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import time, socket, os, struct, math, keyboard
from colorama import init, Back, Fore

init(autoreset=True)


# Глобальные переменные
FileName = ''
Packet_list = []
Object_list = []
Labels_list = []
Session_list = []
x_axisLabels = []
Phrases_signs = [ 'Нет', 'Установка соединиения (SYN)'
                , 'Подтверждение установки соединения (SYN-ACK)'
                , 'Установлена сессия', 'Ведется сессия', 'Подозрение на RDP-сессию!'
                , 'Сессия закончена', 'Сессия прервана'
                , 'Передача клавиатурных и мышинных событий']
findRDP = False
line = '-------------------------'


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
      dev = math.sqrt(sum / n)
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
        dev = math.sqrt(sum / l)
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


# Получение ethernet-кадра
def get_ethernet_frame(data):
  dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
  return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto)


# Получение MAC-адреса
def get_mac_addr(mac_bytes):
  mac_str = ''
  for el in mac_bytes:
    mac_str += format(el, '02x').upper() + ':'
  return mac_str[:len(mac_str) - 1]


# Получение IPv4-заголовка
def get_ipv4_data(data):
  version_header_length = data[0]
  header_length = (version_header_length & 15) * 4
  ttl, proto, src, dest = struct.unpack('!8xBB2x4s4s', data[:20])
  return ttl, proto, ipv4_dec(src), ipv4_dec(dest), data[header_length:]


# Получение IP-адреса формата X.X.X.X
def ipv4_dec(ip_bytes):
  ip_str = ''
  for el in ip_bytes:
    ip_str += str(el) + '.'
  return ip_str[:-1]


# Получение UDP-сегмента данных
def get_udp_segment(data):
  src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
  return str(src_port), str(dest_port), size, data[8:]


# Получение TCP-cегмента данных
def get_tcp_segment(data):
  src_port, dest_port, sequence, ack, some_block = struct.unpack('!HHLLH', data[:14])
  return str(src_port), str(dest_port), str(sequence), str(ack), \
         some_block, data[(some_block >> 12) * 4:]


# Форматирование данных для корректного представления
def format_data(data):
  if isinstance(data, bytes):
    data = ''.join(r'\x{:02x}'.format(el) for el in data)
  return data


# Перехват трафика и вывод информации в консоль
def start_to_listen(s_listen):
  global Packet_list
  NumPacket = 1
  curcnt = 1000
  while True:
    # Получение пакетов в виде набора hex-чисел
    raw_data, _ = s_listen.recvfrom(65565)
    pinf = [''] * 18
    pinf[0], pinf[1] = NumPacket, time.time()
    pinf[2] = len(raw_data)
    # Если это интернет-протокол четвертой версии    
    pinf[4], pinf[3], protocol = get_ethernet_frame(raw_data)
    if protocol == 8:
      _, proto, pinf[6], pinf[7], data_ipv4 = get_ipv4_data(raw_data[14:])
      if NumPacket > curcnt:
        curcnt += 1000
        clear_end_sessions() 
      # Если это UDP-протокол  
      if proto == 17:
        NumPacket += 1
        pinf[5] = 'UDP'
        pinf[8], pinf[9], _, data_udp = get_udp_segment(data_ipv4)
        pinf[10] = len(data_udp)
        Packet_list.append(PacketInf( pinf[0], pinf[1], pinf[2]
                                    , pinf[3], pinf[4], pinf[5]
                                    , pinf[6], pinf[7], pinf[8]
                                    , pinf[9], pinf[10]))
        mes_prob = find_session_location(Packet_list[-1])
        print_packet_inf(Packet_list[-1], mes_prob)
      # Если это TCP-протокол  
      if proto == 6:
        NumPacket += 1
        pinf[5] = 'TCP'
        pinf[8], pinf[9], pinf[11], \
        pinf[12], flags, data_tcp = get_tcp_segment(data_ipv4)
        pinf[10] = len(data_tcp)
        pinf[13] = str((flags & 16) >> 4)
        pinf[14] = str((flags & 8) >> 3)
        pinf[15] = str((flags & 4) >> 2)
        pinf[16] = str((flags & 2) >> 1)
        pinf[17] = str(flags & 1)
        Packet_list.append(PacketInf( pinf[0], pinf[1], pinf[2], pinf[3]
                                    , pinf[4], pinf[5], pinf[6], pinf[7]
                                    , pinf[8], pinf[9], pinf[10], pinf[11]
                                    , pinf[12], pinf[13], pinf[14], pinf[15]
                                    , pinf[16], pinf[17] ))
        mes_prob = find_session_location(Packet_list[-1])
        print_packet_inf(Packet_list[-1], mes_prob)
    if keyboard.is_pressed('space'):
      s_listen.close()
      print('\nЗавершение программы...\n')
      break


# Обработка значений списка Session_list
def clear_end_sessions():
  global Session_list
  n = len(Session_list)
  ids = []
  for i in range(n):
    if Session_list[i].fl_fin or Session_list[i].fl_rst:
      if Session_list[i].totalTime < 10:
        ids.append(i)
  tmp = Session_list.copy()
  Session_list.clear()
  for i in range(n):
    if i in ids:
      continue  
    Session_list.append(tmp[i])
  for s in Session_list:
    s.get_rdp_features(Packet_list[-1], True)


# Нахождение активных сессий
def find_session_location(pkt):
  global Session_list
  if pkt.protoType == 'UDP':
    for s in Session_list:
      if (not s.fl_fin and not s.fl_rst):
        if ( (pkt.ip_src == s.initiator and pkt.ip_dest == s.target) or \
             (pkt.ip_src == s.target and pkt.ip_dest == s.initiator) ) and \
           (pkt.port_src == s.port or pkt.port_dest == s.port):
          s.get_in_out_traffic(pkt)
          s.get_rdp_features(pkt)
          if s.is_rdp:
            if s.is_rdpPSH:
              return ([4, 5, 8], s.prob)
            return ([4, 5], s.prob)
    return ([0], 0)  
  if pkt.fl_syn == '1' and pkt.fl_ack == '0':
    Session_list.append(Session( pkt.timePacket, pkt.ip_src
                               , pkt.ip_dest, pkt.port_dest ))
    Session_list[-1].upd_seq_num(pkt.seq)
    Session_list[-1].get_in_out_traffic(pkt)
    Session_list[-1].get_rdp_features(pkt)
    return ([1], Session_list[-1].prob)
  for s in Session_list:
    if (not s.fl_fin and not s.fl_rst):
      if pkt.fl_fin == '1' and pkt.fl_ack == '1' and \
        ( (pkt.ip_src == s.initiator and pkt.ip_dest == s.target) or \
          (pkt.ip_src == s.target and pkt.ip_dest == s.initiator) ) and \
        (pkt.port_src == s.port or pkt.port_dest == s.port):
        s.upd_fl_fin(pkt.timePacket)
        s.get_in_out_traffic(pkt)
        s.get_rdp_features(pkt)
        if s.is_rdp:
          if s.is_rdpPSH:
            return ([5, 6, 8], s.prob)
          return ([5, 6], s.prob)
        return ([6], s.prob)
      if pkt.fl_rst == '1' and pkt.fl_ack == '1' and \
         ( (pkt.ip_src == s.initiator and pkt.ip_dest == s.target) or \
           (pkt.ip_src == s.target and pkt.ip_dest == s.initiator) ) and \
         (pkt.port_src == s.port or pkt.port_dest == s.port):
        s.upd_fl_rst(pkt.timePacket)
        s.get_in_out_traffic(pkt)
        s.get_rdp_features(pkt)
        if s.is_rdp:
          if s.is_rdpPSH:
            return ([5, 7, 8], s.prob)
          return ([5, 7], s.prob)
        return ([7], s.prob)
      if pkt.fl_syn == '1' and pkt.fl_ack == '1' and s.ack_num == None and \
         pkt.ack == str(s.seq_num + 1) and pkt.ip_src == s.target and \
         pkt.ip_dest == s.initiator and pkt.port_src == s.port:
        s.upd_ack_num(pkt.ack)
        s.upd_seq_num(pkt.seq)
        s.get_in_out_traffic(pkt)
        s.get_rdp_features(pkt)
        if s.is_rdp:
          if s.is_rdpPSH:
            return ([2, 5, 8], s.prob)
          return ([2, 5], s.prob)
        return ([2], s.prob)
      elif pkt.fl_syn == '0' and pkt.fl_ack == '1' and pkt.ack == str(s.seq_num + 1) and \
           pkt.seq == s.ack_num and \
           pkt.port_dest == s.port and pkt.ip_src == s.initiator and \
           pkt.ip_dest == s.target:
        s.get_in_out_traffic(pkt)
        s.get_rdp_features(pkt)
        if s.is_rdp:
          if s.is_rdpPSH:
            return ([3, 5, 8], s.prob)
          return ([3, 5], s.prob)
        return ([3], s.prob)
      if pkt.fl_ack == '1' and \
         ( (pkt.ip_src == s.initiator and pkt.ip_dest == s.target) or \
           (pkt.ip_src == s.target and pkt.ip_dest == s.initiator) ) and \
         (pkt.port_src == s.port or pkt.port_dest == s.port):
        s.get_in_out_traffic(pkt)
        s.get_rdp_features(pkt)
        if s.is_rdp:
          if s.is_rdpPSH:
            return ([4, 5, 8], s.prob)
          return ([4, 5], s.prob)
        return ([4], s.prob)
  return ([0], 0)


# Вывод информации о сессиях
def print_inf_about_sessions():
  cnt = 1
  print(f'\nБыло перехвачено {len(Session_list)} сессии(-й)')
  for s in Session_list:
    print(f'\nИнформация о сессии #{cnt}:')
    print(f'Инициатор подключения: {s.initiator}')
    print(f'Целевое устройство: {s.target}')
    print(f'Порт подключения: {s.port}')
    print( f'Время установки соединения:'
         , time.strftime('%d.%m.%Y г. %H:%M:%S', time.localtime(s.strtTime)) )
    if s.finTime == None:
      print(f'Время завершения соединения: нет данных')
    else:
      print( f'Время завершения соединения:'
           , time.strftime('%d.%m.%Y г. %H:%M:%S', time.localtime(s.finTime)))
      print(f'Общее время соединения: {s.totalTime} сек')
    if s.is_rdp and s.prob > 50:
      print(Back.GREEN + Fore.BLACK + f'Найдена RDP-сессия с вероятностью {s.prob}%!!!')
    cnt += 1
  print(f'{line}{line}\n')


# Запись информации о пакетах в файл
def write_to_file(f):
  if Packet_list == []:
    return False
  try:
    for obj in Packet_list:
      if obj.protoType == 'UDP':
        f.write( f'No:{obj.numPacket};Time:{obj.timePacket};Pac-size:{obj.packetSize};' +
                 f'MAC-src:{obj.mac_src};MAC-dest:{obj.mac_dest};Type:{obj.protoType};' + 
                 f'IP-src:{obj.ip_src};IP-dest:{obj.ip_dest};Port-src:{obj.port_src};' + 
                 f'Port-dest:{obj.port_dest};Len-data:{obj.len_data};!\n' )
      else:
        f.write( f'No:{obj.numPacket};Time:{obj.timePacket};Pac-size:{obj.packetSize};' +
                 f'MAC-src:{obj.mac_src};MAC-dest:{obj.mac_dest};Type:{obj.protoType};' + 
                 f'IP-src:{obj.ip_src};IP-dest:{obj.ip_dest};Port-src:{obj.port_src};' + 
                 f'Port-dest:{obj.port_dest};Len-data:{obj.len_data};Seq:{obj.seq};' +
                 f'Ack:{obj.ack};Fl-ack:{obj.fl_ack};Fl-psh:{obj.fl_psh};' +
                 f'Fl-rst:{obj.fl_rst};Fl-syn:{obj.fl_syn};Fl-fin:{obj.fl_fin};!\n' )
  except:
      return False
  return True


# Считывание с файла и заполнение массива
# Packet_list объектами класса PacketInf
def read_from_file(inf):
  global Packet_list
  a = []
  while True:
    beg = inf.find(':')
    end = inf.find(';')
    if beg == -1 and end == -1:
      break
    else:
      a.append(inf[beg + 1: end])
    inf = inf[end + 1:]
  try:
    if a[5] == 'TCP':
      Packet_list.append(PacketInf( a[0], a[1], a[2], a[3], a[4], a[5]
                                  , a[6], a[7], a[8], a[9], a[10], a[11]
                                  , a[12], a[13], a[14], a[15], a[16], a[17] ))
      _ = find_session_location(Packet_list[-1])
    elif a[5] == 'UDP':
      Packet_list.append(PacketInf( a[0], a[1], a[2], a[3], a[4], a[5]
                                  , a[6], a[7], a[8], a[9], a[10] ))
      _ = find_session_location(Packet_list[-1])
  except:
    print('Ошибка при считывании файла...')
    exit(0)


# Вывод информации о перехваченных пакетах
def print_packet_inf(obj, mes_prob):
  if findRDP:
    if 5 not in mes_prob[0] or mes_prob[1] <= 50:
      return
  print( f'{line}Пакет No{obj.numPacket}{line}\n'
       , 'Время перехвата: '
       , time.strftime( '%m:%d:%Y %H:%M:%S'
                      , time.localtime(obj.timePacket) ) + '\n'
       , f'Протокол: {obj.protoType}\n'
       , f'MAC-адрес отправителя: {obj.mac_src}\n'
       , f'MAC-адрес получателя: {obj.mac_dest}\n'
       , f'Отправитель: {obj.ip_src}:{obj.port_src}\n'
       , f'Получатель: {obj.ip_dest}:{obj.port_dest}')
  if obj.protoType == 'TCP':
    print( f' Порядковый номер: {obj.seq}; Номер подтверждения: {obj.ack}\n' +
           f' SYN:{obj.fl_syn}; ACK:{obj.fl_ack}; PSH:{obj.fl_psh}; ' +
           f'RST:{obj.fl_rst}; FIN:{obj.fl_fin}\n')
  print('Признаки: ', end='')
  for i in mes_prob[0]:
    print(Phrases_signs[i], end='; ')
  print(f'\nВероятность RDP-сессии {mes_prob[1]}%')


# Получение общей информации о текущей
# попытке перехвата трафика
def get_common_data():
  global Labels_list
  Labels_list.clear()
  IPList = set()
  numPacketsPerSec = []
  curTime = Packet_list[0].timePacket + 1
  fin = Packet_list[-1].timePacket + 1
  Labels_list.append(time.strftime('%H:%M:%S', time.localtime(Packet_list[0].timePacket)))
  cntPacket = 0
  i = 0
  while curTime < fin:
    for k in range(i, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        numPacketsPerSec.append(cntPacket)
        Labels_list.append(time.strftime('%H:%M:%S', time.localtime(curTime)))
        cntPacket = 0
        i = k
        break
      cntPacket += 1
    curTime += 1
  numPacketsPerSec.append(cntPacket)
  for p in Packet_list:
    IPList.add(p.ip_src)
    IPList.add(p.ip_dest)
  return list(IPList), numPacketsPerSec


# Получение общих портов относительно текущего IP-адреса
def get_common_ports(curIP):
  ports = set()
  for pkt in Packet_list:
    if pkt.ip_src == curIP or pkt.ip_dest == curIP:
      ports.add(pkt.port_src)
      ports.add(pkt.port_dest)
  return list(ports)

 
# Вывод пар (число, IP-адрес/порт) для
# предоставления выбора IP-адреса/порта
# пользователю
def print_list_of_pairs(IPList, fl=False):
  num = 0
  cnt = 1
  if fl:
    print ('[' + str(num), '---', 'None', end='] ')
    cnt += 1
    num += 1
  for el in IPList:
    if cnt > 3:
      cnt = 0
      print ('[' + str(num), '---', el, end=']\n')
    else:
      print ('[' + str(num), '---', el, end='] ')
    cnt += 1
    num += 1
  print('')


# Вывод пакетов, связанных с выбранным IP-адресом 
def print_adjacent_packets(adjcPacketLIst):
  cnt = 0
  for p in adjcPacketLIst:
    t = time.strftime('%H:%M:%S', time.localtime(p.timePacket))
    if cnt % 2 == 1:
      print( f'Номер пакета: {p.numPacket};', f' Время: {t};'
           , f' Размер: {p.packetSize};', f' MAC-адрес отправителя: {p.mac_src};'
           , f' MAC-адрес получателя: {p.mac_dest};', f' Протокол: {p.protoType};'
           , f' Отправитель: {p.ip_src}:{p.port_src};'
           , f' Получатель: {p.ip_dest}:{p.port_dest};'
           , f' Размер поля данных: {p.len_data};', end='' )
      if p.protoType == 'TCP':
          print( f' Порядковый номер: {p.seq}; Номер подтверждения: {p.ack};' +
                 f' SYN:{p.fl_syn}; ACK:{p.fl_ack}; PSH:{p.fl_psh}; ' +
                 f'RST:{p.fl_rst}; FIN:{p.fl_fin};')
      else:
        print('')
    else:
      print( Back.CYAN + Fore.BLACK + f'Номер пакета: {p.numPacket};' + f' Время: {t};' +
             f' Размер: {p.packetSize};' + f' MAC-адрес отправителя: {p.mac_src};' +
             f' MAC-адрес получателя: {p.mac_dest};' + 
             f' Отправитель: {p.ip_src}:{p.port_src};' +
             f' Получатель: {p.ip_dest}:{p.port_dest};' +
             f' Протокол: {p.protoType};' +
             f' Размер поля данных: {p.len_data};', end='' )
      if p.protoType == 'TCP':
        print( Back.CYAN + Fore.BLACK + f' Порядковый номер: {p.seq};' +
               f' Номер подтверждения: {p.ack};' +
               f' SYN:{p.fl_syn}; ACK:{p.fl_ack}; PSH:{p.fl_psh};' +
               f' RST:{p.fl_rst}; FIN:{p.fl_fin};')
      else:
        print('')
    cnt += 1


# Получение данных об отношении входящего
# трафика к исходящему в единицу времени
def get_in_out_rel(exploreIP, strt, fin, port):
  cntInput = 0
  cntOutput = 0
  rel_list = []
  curTime = strt + 1
  fin += 1
  pos = 0
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        if cntOutput != 0:
          rel_list.append(cntInput / cntOutput)
        else:
          rel_list.append(0.0)
        cntInput = 0
        cntOutput = 0
        pos = k
        break
      if port == None:
        if Packet_list[k].ip_src == exploreIP:
          cntOutput += 1
        if Packet_list[k].ip_dest == exploreIP:
          cntInput += 1
      else:
        if Packet_list[k].port_src == port or Packet_list[k].port_dest == port:
          if Packet_list[k].ip_src == exploreIP:
            cntOutput += 1
          if Packet_list[k].ip_dest == exploreIP:
            cntInput += 1
    curTime += 1
  if cntOutput != 0:
    rel_list.append(cntInput / cntOutput)
  else:
    rel_list.append(0.0)
  return rel_list


# Получение данных об отношении количества
# входящего UDP-трафика на количество
# исходящего TCP-трафика в единицу времени
def get_udp_tcp_rel(exploreIP, strt, fin, port):
  cntUDP = 0
  cntTCP = 0
  curTime = strt + 1
  fin += 1
  pos = 0
  rel_list = []
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        if cntTCP != 0:
          rel_list.append(cntUDP / cntTCP)
        else:
          rel_list.append(0.0)
        cntTCP = 0
        cntUDP = 0
        pos = k
        break
      if port == None:
        if Packet_list[k].ip_dest == exploreIP:
          if Packet_list[k].protoType == 'TCP':
            cntTCP += 1
          if Packet_list[k].protoType == 'UDP':
            cntUDP += 1
      else:
        if Packet_list[k].port_src == port or Packet_list[k].port_dest == port:
          if Packet_list[k].ip_dest == exploreIP:
            if Packet_list[k].protoType == 'TCP':
              cntTCP += 1
            if Packet_list[k].protoType == 'UDP':
              cntUDP += 1
    curTime += 1
  if cntTCP != 0:
    rel_list.append(cntUDP / cntTCP)
  else:
    rel_list.append(0.0)
  return rel_list


# Получение данных о разности количества
# исходящих ACK-флагов и количества входящих
# ACK-флагов
def get_ack_flags_diff(exploreIP, strt, fin, port):
  cntInput = 0
  cntOutput = 0
  diff_list = []
  curTime = strt + 1
  fin += 1
  pos = 0
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
          diff_list.append(cntOutput - cntInput)
          cntInput = 0
          cntOutput = 0
          pos = k
          break
      if port == None:
        if Packet_list[k].protoType == 'TCP' and Packet_list[k].fl_ack == '1':
          if Packet_list[k].ip_src == exploreIP:
            cntOutput += 1
          if Packet_list[k].ip_dest == exploreIP:
            cntInput += 1
      else:
        if Packet_list[k].port_src == port or Packet_list[k].port_dest == port:
          if Packet_list[k].protoType == 'TCP' and Packet_list[k].fl_ack == '1':
            if Packet_list[k].ip_src == exploreIP:
              cntOutput += 1
            if Packet_list[k].ip_dest == exploreIP:
              cntInput += 1
    curTime += 1
  diff_list.append(cntOutput - cntInput)
  return diff_list


# Получение данных о частоте SYN-флагов
def get_syn_flags_freq(exploreIP, strt, fin, port):
  cntSynTCP = 0
  cntTCP = 0
  rel_list = []
  curTime = strt + 1
  fin += 1
  pos = 0
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        if cntTCP != 0:
          rel_list.append(cntSynTCP / cntTCP)
        else:
          rel_list.append(0.0)
        cntSynTCP = 0
        cntTCP = 0
        pos = k
        break
      if port == None:
        if Packet_list[k].ip_dest == exploreIP and Packet_list[k].protoType == 'TCP':
          cntTCP += 1
          if Packet_list[k].fl_syn == '1':
            cntSynTCP += 1
      else:
        if Packet_list[k].port_src == port or Packet_list[k].port_dest == port:
          if Packet_list[k].ip_dest == exploreIP and Packet_list[k].protoType == 'TCP':
            cntTCP += 1
            if Packet_list[k].fl_syn == '1':
              cntSynTCP += 1
    curTime += 1
  if cntTCP != 0:
    rel_list.append(cntSynTCP / cntTCP)
  else:
    rel_list.append(0.0)
  return rel_list


# Получение данных о частоте PSH-флагов
def get_psh_flags_freq(exploreIP, strt, fin, port):
  cntPshTCP = 0
  cntTCP = 0
  rel_list = []
  curTime = strt + 1
  fin += 1
  pos = 0
  while curTime < fin:
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        if cntTCP != 0:
          rel_list.append(cntPshTCP / cntTCP)
        else:
          rel_list.append(0.0)
        cntPshTCP = 0
        cntTCP = 0
        pos = k
        break
      if port == None:
        if Packet_list[k].ip_dest == exploreIP and Packet_list[k].protoType == 'TCP':
          cntTCP += 1
          if Packet_list[k].fl_psh == '1':
            cntPshTCP += 1
      else:
        if Packet_list[k].port_src == port or Packet_list[k].port_dest == port:
          if Packet_list[k].ip_dest == exploreIP and Packet_list[k].protoType == 'TCP':
            cntTCP += 1
            if Packet_list[k].fl_psh == '1':
              cntPshTCP += 1
    curTime += 1
  if cntTCP != 0:
    rel_list.append(cntPshTCP / cntTCP)
  else:
    rel_list.append(0.0)
  return rel_list


# Получение данных о количестве пакетов и
# о максимумах пакетов в единицу времени
def get_pktamnt_and_size_persec(exploreIP, strt, fin, port):
  pktAmntSrcList = []
  pktAmntDstList = []
  pktSizeSrcList = []
  pktSizeDstList = []
  curTime = strt + 1
  fin += 1
  pos = 0
  while curTime < fin:
    cntpktsrc = 0
    cntpktdest = 0
    maxpktsizesrc = 0
    maxpktsizedst = 0
    for k in range(pos, len(Packet_list)):
      if Packet_list[k].timePacket > curTime:
        pktAmntSrcList.append(cntpktsrc)
        pktAmntDstList.append(cntpktdest)
        pktSizeSrcList.append(maxpktsizesrc)
        pktSizeDstList.append(maxpktsizedst)
        pos = k
        break
      if port == None:
        if Packet_list[k].ip_src == exploreIP:
          cntpktsrc += 1
          if maxpktsizesrc < Packet_list[k].packetSize:
            maxpktsizesrc = Packet_list[k].packetSize
        if Packet_list[k].ip_dest == exploreIP:
          cntpktdest += 1
          if maxpktsizedst < Packet_list[k].packetSize:
            maxpktsizedst = Packet_list[k].packetSize
      else:
        if Packet_list[k].port_src == port or Packet_list[k].port_dest == port:
          if Packet_list[k].ip_src == exploreIP:
            cntpktsrc += 1
            if maxpktsizesrc < Packet_list[k].packetSize:
              maxpktsizesrc = Packet_list[k].packetSize
          if Packet_list[k].ip_dest == exploreIP:
            cntpktdest += 1
            if maxpktsizedst < Packet_list[k].packetSize:
              maxpktsizedst = Packet_list[k].packetSize
    curTime += 1
  pktAmntSrcList.append(cntpktsrc)
  pktAmntDstList.append(cntpktdest)
  pktSizeSrcList.append(maxpktsizesrc)
  pktSizeDstList.append(maxpktsizedst)
  return pktAmntSrcList, pktAmntDstList, pktSizeSrcList, pktSizeDstList


# Получение общей информации о трафике,
# связанном с выбранным IP-адресом
def get_inf_about_IP(exploreIP, port):
  adjcPacketList = []
  adjcIPList = set()
  if port != None:
    for p in Packet_list:
      if p.port_src == port or p.port_dest == port:
        if p.ip_src == exploreIP:
          adjcPacketList.append(p)
          adjcIPList.add(p.ip_dest)
        if p.ip_dest == exploreIP:
          adjcPacketList.append(p)
          adjcIPList.add(p.ip_src)
  else:
    for p in Packet_list:
      if p.ip_src == exploreIP:
        adjcPacketList.append(p)
        adjcIPList.add(p.ip_dest)
      if p.ip_dest == exploreIP:
        adjcPacketList.append(p)
        adjcIPList.add(p.ip_src)
  return adjcPacketList, list(adjcIPList)


# Получение номера по IP-адресу
def get_pos_by_IP(curIP):
  for i in range(len(Object_list)):
    if Object_list[i].ip == curIP:
      return i
  return -1


# Получение меток и "шага" для оси абсцисс
def get_x_labels(total_time):
  global x_axisLabels
  step = 1
  if total_time > 600:
    step = 30
  elif total_time > 300:
    step = 10
  elif total_time > 50:
    step = 5
  x_axisLabels.clear()
  for i in range(0, len(Labels_list), step):
    x_axisLabels.append(Labels_list[i])
  return step


# Получение второго IP-адреса
def get_2nd_IP_for_plot(k):
  print('\nИзобразить на графике еще один объект. Выберите ' + \
            'IP-адрес для добавления (введите цифру)')
  print_list_of_pairs(Object_list[k].adjcIPList, True)
  scndIP = 'None'
  try:
    pos = int(input())
  except:
    print('Некорректный ввод!')
    return -1
  else:
    if pos < 0 or pos > len(Object_list[k].adjcIPList):
      print('Некорректный ввод!')
      return -1
    if pos != 0:
      scndIP = Object_list[k].adjcIPList[pos - 1]
  return scndIP


# Выбор опций для выбранного IP-адреса
def choose_options(k, strt, fin, step, port):
  curIP = Object_list[k].ip
  Object_list[k].adjcPacketList, Object_list[k].adjcIPList = get_inf_about_IP(curIP, port)
  Object_list[k].strt_time = time.localtime(Object_list[k].adjcPacketList[0].timePacket)
  Object_list[k].fin_time = time.localtime(Object_list[k].adjcPacketList[-1].timePacket)
  Object_list[k].amnt_packet = len(Object_list[k].adjcPacketList)
  totalTime = round( Object_list[k].adjcPacketList[-1].timePacket - \
                     Object_list[k].adjcPacketList[0].timePacket )
  if totalTime == 0:
    totalTime = 1
  Object_list[k].avg_packet_num = round(Object_list[k].amnt_packet / totalTime, 3)
  avgSize = 0
  for p in Object_list[k].adjcPacketList:
    avgSize += p.len_data
  Object_list[k].avg_packet_size = round(avgSize / Object_list[k].amnt_packet, 3)
  while True:
    print(f'Общая информация о трафике, связанном с {curIP}')
    print( 'Время первого перехваченного пакета: '
         , time.strftime('%d.%m.%Y г. %H:%M:%S', Object_list[k].strt_time) )
    print( 'Время последнего перехваченного пакета: '
         , time.strftime('%d.%m.%Y г. %H:%M:%S', Object_list[k].fin_time) )
    print('Общее время:', totalTime, 'сек.')
    print('Количество пакетов: ', Object_list[k].amnt_packet)
    print('Среднее количество пакетов в секунду: ', Object_list[k].avg_packet_num)
    print('Средний размер пакетов: ', Object_list[k].avg_packet_size)  
    print(f"""Выберите опцию:
    1. Вывести весь трафик, связанный с {curIP}
    2. Построить график отношения входящего и исходящего трафиков
    3. Построить график отношения объема входящего UDP-трафика и объёма входящего TCP-трафика
    4. Построить график разности числа исходящих и числа входящих ACK-флагов в единицу времени
    5. Построить график частоты SYN и PSH флагов во входящих пакетах
    6. Построить график отображения количества пакетов в единицу времени
    7. Построить график отображения максимумов среди пакетов в единицу времени
    8. Вернуться к выбору IP-адреса """)
    bl = input()
    if bl == '1':
      print_adjacent_packets(Object_list[k].adjcPacketList)

    elif bl == '2':
      Object_list[k].in_out_rel_data = get_in_out_rel(curIP, strt, fin, port)
      x = [i for i in range(0, len(Object_list[k].in_out_rel_data))]
      x_labels = [i for i in range(0, len(x), step)]
      scndIP = get_2nd_IP_for_plot(k)
      if scndIP == -1:
        continue
      if scndIP != 'None':
        pos = get_pos_by_IP(scndIP)
        Object_list[pos].in_out_rel_data = get_in_out_rel(scndIP, strt, fin, port)
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      f = fig.add_subplot()
      f.grid()
      f.set_title('Отношение объема входящего к объему исходящего трафиков' + \
                  r' ($r_{in/out} = \frac{V_{in}}{V_{out}}$)', fontsize=15 )
      f.set_xlabel('Общее время перехвата трафика', fontsize=15)
      f.set_ylabel(r'$r_{in/out} = \frac{V_{in}}{V_{out}}$', fontsize=15)
      plt.plot(x, Object_list[k].in_out_rel_data, label=curIP)
      if scndIP != 'None':
        plt.plot(x, Object_list[pos].in_out_rel_data, label=scndIP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=10)
      f.legend()
      plt.show()
    elif bl == '3':
      Object_list[k].udp_tcp_rel_data = get_udp_tcp_rel(curIP, strt, fin, port)
      x = [i for i in range(0, len(Object_list[k].udp_tcp_rel_data))]
      x_labels = [i for i in range(0, len(x), step)]
      scndIP = get_2nd_IP_for_plot(k)
      if scndIP == -1:
        continue
      if scndIP != 'None':
        pos = get_pos_by_IP(scndIP)
        Object_list[pos].udp_tcp_rel_data = get_udp_tcp_rel(scndIP, strt, fin, port)
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      f = fig.add_subplot()
      f.grid()
      f.set_title( 'Отношение объема входящего UDP-трафика к объему ' +  
                   'входящего TCP-трафика' + r' ($r_{in} = \frac{V_{udp}}{V_{tcp}}$)'
                 , fontsize=15 )
      f.set_xlabel('Общее время перехвата трафика', fontsize=15)
      f.set_ylabel(r'$r_{in} = \frac{V_{udp}}{V_{tcp}}$', fontsize=15)
      plt.plot(x, Object_list[k].udp_tcp_rel_data, label=curIP)
      if scndIP != 'None':
        plt.plot(x, Object_list[pos].udp_tcp_rel_data, label=scndIP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=10)
      f.legend()
      plt.show()
    elif bl == '4':
      Object_list[k].ack_flags_diff_data = get_ack_flags_diff(curIP, strt, fin, port)
      x = [i for i in range(0, len(Object_list[k].ack_flags_diff_data))]
      x_labels = [i for i in range(0, len(x), step)]
      scndIP = get_2nd_IP_for_plot(k)
      if scndIP == -1:
        continue
      if scndIP != 'None':
        pos = get_pos_by_IP(scndIP)
        Object_list[pos].ack_flags_diff_data = get_ack_flags_diff(scndIP, strt, fin, port)
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      f = fig.add_subplot()
      f.grid()
      f.set_title('Разность числа исходящих и числа входящих ACK-флагов' + \
                  r' ($r_{ack} = V_{A_{out}} - V_{A_{in}}$)', fontsize=15)
      f.set_xlabel('Общее время перехвата трафика', fontsize=15)
      f.set_ylabel(r'$r_{ack} = V_{A_{out}} - V_{A_{in}}$', fontsize=15)
      plt.plot(x, Object_list[k].ack_flags_diff_data, label=curIP)
      if scndIP != 'None':
        plt.plot(x, Object_list[pos].ack_flags_diff_data, label=scndIP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=10)
      f.legend()
      plt.show()
    elif bl == '5':
      data = get_syn_flags_freq(curIP, strt, fin, port)
      Object_list[k].syn_flags_freq_data = data
      data = get_psh_flags_freq(curIP, strt, fin, port)
      Object_list[k].psh_flags_freq_data = data
      x = [i for i in range(0, len(Object_list[k].syn_flags_freq_data))]
      x_labels = [i for i in range(0, len(x), step)]
      scndIP = get_2nd_IP_for_plot(k)
      if scndIP == -1:
        continue
      if scndIP != 'None':
        pos = get_pos_by_IP(scndIP)
        data = get_syn_flags_freq(scndIP, strt, fin, port)
        Object_list[pos].syn_flags_freq_data = data
        data = get_psh_flags_freq(scndIP, strt, fin, port)
        Object_list[pos].psh_flags_freq_data = data
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      gs = gridspec.GridSpec(ncols=1, nrows=2, figure=fig)
      fig_1 = fig.add_subplot(gs[0, 0])
      fig_1.grid()
      fig_1.set_title('Частота флагов SYN' + \
                       r' ($r_{syn} = \frac{V_{S_{in}}}{V_{tcp}}$)', fontsize=15)
      fig_1.set_xlabel('Общее время перехвата трафика', fontsize=15)
      fig_1.set_ylabel(r'$r_{syn} = \frac{V_{S_{in}}}{V_{tcp}}$', fontsize=15)
      plt.plot(x, Object_list[k].syn_flags_freq_data, 'b', label=curIP)
      if scndIP != 'None':
        plt.plot(x, Object_list[pos].syn_flags_freq_data, 'r', label=scndIP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_1.legend()
      fig_2 = fig.add_subplot(gs[1, 0])
      fig_2.grid()
      plt.plot(x, Object_list[k].psh_flags_freq_data, 'orange', label=curIP)
      fig_2.set_title('Частота флагов PSH' + \
                      r' ($r_{psh} = \frac{V_{P_{in}}}{V_{tcp}}$)', fontsize=15)
      fig_2.set_xlabel('Общее время перехвата трафика', fontsize=15)
      fig_2.set_ylabel(r'$r_{psh} = \frac{V_{P_{in}}}{V_{tcp}}$', fontsize=15)
      if scndIP != 'None':
        plt.plot(x, Object_list[pos].psh_flags_freq_data, 'g', label=scndIP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_2.legend()
      plt.show()
    elif bl == '6':
      d1, d2, d3, d4 = get_pktamnt_and_size_persec(curIP, strt, fin, port)
      Object_list[k].pkt_amnt_src_data = d1
      Object_list[k].pkt_amnt_dst_data = d2
      Object_list[k].pkt_size_data_src = d3
      Object_list[k].pkt_size_data_dst = d4
      x = [i for i in range(0, len(Object_list[k].pkt_amnt_src_data))]
      x_labels = [i for i in range(0, len(x), step)]
      scndIP = get_2nd_IP_for_plot(k)
      if scndIP == -1:
        continue
      if scndIP != 'None':
        pos = get_pos_by_IP(scndIP)
        d1, d2, d3, d4 = get_pktamnt_and_size_persec(scndIP, strt, fin, port)
        Object_list[pos].pkt_amnt_src_data = d1
        Object_list[pos].pkt_amnt_dst_data = d2
        Object_list[pos].pkt_size_data_src = d3
        Object_list[pos].pkt_size_data_dst = d4
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      gs = gridspec.GridSpec(ncols=1, nrows=2, figure=fig)
      fig_1 = fig.add_subplot(gs[0, 0])
      fig_1.grid()
      fig_1.set_title('Количество входящих пакетов, полученных за ' + \
                      'единицу времени', fontsize=15)
      fig_1.set_xlabel('Общее время перехвата трафика', fontsize=15)
      plt.plot(x, Object_list[k].pkt_amnt_dst_data, 'b', label=curIP)
      if scndIP != 'None':
        plt.plot(x, Object_list[pos].pkt_amnt_dst_data, 'r', label=scndIP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_1.legend()
      fig_2 = fig.add_subplot(gs[1, 0])
      fig_2.grid()
      plt.plot(x, Object_list[k].pkt_amnt_src_data, 'orange', label=curIP)
      fig_2.set_title('Количество исходящих пакетов, полученных за ' + \
                      'единицу времени', fontsize=15)
      fig_2.set_xlabel('Общее время перехвата трафика', fontsize=15)
      if scndIP != 'None':
        plt.plot(x, Object_list[pos].pkt_amnt_src_data, 'g', label=scndIP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_2.legend()
      plt.show()
    elif bl == '7':
      d1, d2, d3, d4 = get_pktamnt_and_size_persec(curIP, strt, fin, port)
      Object_list[k].pkt_amnt_src_data = d1
      Object_list[k].pkt_amnt_dst_data = d2
      Object_list[k].pkt_size_data_src = d3
      Object_list[k].pkt_size_data_dst = d4
      x = [i for i in range(0, len(Object_list[k].pkt_size_data_src))]
      x_labels = [i for i in range(0, len(x), step)]
      scndIP = get_2nd_IP_for_plot(k)
      if scndIP == -1:
        continue
      if scndIP != 'None':
        pos = get_pos_by_IP(scndIP)
        d1, d2, d3, d4 = get_pktamnt_and_size_persec(scndIP, strt, fin, port)
        Object_list[pos].pkt_amnt_src_data = d1
        Object_list[pos].pkt_amnt_dst_data = d2
        Object_list[pos].pkt_size_data_src = d3
        Object_list[pos].pkt_size_data_dst = d4
      fig = plt.figure(figsize=(16, 6), constrained_layout=True)
      gs = gridspec.GridSpec(ncols=1, nrows=2, figure=fig)
      fig_1 = fig.add_subplot(gs[0, 0])
      fig_1.grid()
      fig_1.set_title('Максимальный размер входящих пакетов, полученных за ' + \
                      'единицу времени', fontsize=15)
      fig_1.set_xlabel('Общее время перехвата трафика', fontsize=15)
      plt.plot(x, Object_list[k].pkt_size_data_dst, 'b', label=curIP)
      if scndIP != 'None':
        plt.plot(x, Object_list[pos].pkt_size_data_dst, 'r', label=scndIP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_1.legend()
      fig_2 = fig.add_subplot(gs[1, 0])
      fig_2.grid()
      plt.plot(x, Object_list[k].pkt_size_data_src, 'orange', label=curIP)
      fig_2.set_title('Максимальный размер исходящих пакетов, полученных за ' + \
                      'единицу времени', fontsize=15)
      fig_2.set_xlabel('Общее время перехвата трафика', fontsize=15)
      if scndIP != 'None':
        plt.plot(x, Object_list[pos].pkt_size_data_src, 'g', label=scndIP)
      plt.xticks(x_labels, x_axisLabels, rotation=30, fontsize=8)
      fig_2.legend()
      plt.show()
    elif bl == '8':
      break


# Выбор опции (меню)
def choose_mode():
  global Packet_list, Object_list, Labels_list, Session_list, findRDP
  while True:
    print('1. Перехват трафика')
    print('2. Запись данных в файл')
    print('3. Считывание с файла данных для анализа трафика')
    print('4. Анализ трафика')
    print('5. Выход')
    bl = input()
    if bl == '1':
      Packet_list.clear()
      Object_list.clear()
      Labels_list.clear()
      Session_list.clear()
      findRDP = False
      print('Поставить фильтр RDP? (Если да, то введите 1)')
      fl = input('Ответ: ')
      if fl == '1':
        findRDP = True
      try:
        print('\nВыберите сетевой интерфейс, нажав соответствующую цифру:')
        print(socket.if_nameindex())
        interface = int(input())
        if 0 > interface or interface > len(socket.if_nameindex()):
          print('\nОшибка ввода!!!\n')
          return
        os.system(f'ip link set {socket.if_indextoname(interface)} promisc on')
        s_listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
      except PermissionError:
        print('\nНедостаточно прав!')
        print('Запустите программу от имени администратора!')
        return
      else:
        print('\nНачался процесс захвата трафика...\n')
        start_to_listen(s_listen)
      print(f'\nДанные собраны. Перехвачено: {len(Packet_list)} пакетов(-а)\n')

      print('\nХотите записать перехваченный трафик в файл? (да - нажмите 1)')
      bl1 = input('Ответ: ')
      if '1' in bl1:
        print('Введите название файла (например: data.log)')
        FileName = input()
        try:
          f = open(FileName, 'w')
        except:
          print('\nНекорректное название файла!\n')
          continue
        if write_to_file(f):
          print(f'\nВ файл {FileName} была успешна записана информация.\n')
          f.close()
        else:
          print(f'\nОшибка записи в файл {FileName}! Возможно нет данных для записи\n')
          f.close()
      print('')
    elif bl == '2':
      if Packet_list == []:
        print('\nНет данных! Сначала необходимо получить данные!\n')
        continue
      print('Введите название файла (например: data.log)')
      FileName = input()
      try:
        f = open(FileName, 'w')
      except:
        print('\nНекорректное название файла!\n')
        continue
      if write_to_file(f):
        print(f'\nВ файл {FileName} была успешна записана информация.\n')
        f.close()
      else:
        print(f'\nОшибка записи в файл {FileName}! Возможно нет данных для записи...\n')
        f.close()
        continue
    elif bl == '3':
      Packet_list.clear()
      Object_list.clear()
      Labels_list.clear()
      Session_list.clear()
      print('Введите название файла (например: data.log)')
      FileName = input()
      if not Packet_list:
        try:
          f = open(FileName, 'r')
        except:
          print('\nНекорректное название файла!\n')
          continue
        while True:
          inf = f.readline()
          if not inf:
            break
          read_from_file(inf)
        f.close()
      print(f'\nДанные собраны. Перехвачено: {len(Packet_list)} пакетов(-а)\n')
    elif bl == '4':
      if Packet_list == []:
        print('\nНет данных! Сначала необходимо получить данные!\n')
        continue
      IPList, numPacketsPerSec = get_common_data()
      clear_end_sessions()
      for s in Session_list:
        s.fin_rdp_check()
      print_inf_about_sessions()
      strt = Packet_list[0].timePacket
      fin = Packet_list[-1].timePacket
      strt_time = time.localtime(strt)
      fin_time = time.localtime(fin)
      avgNumPacket = 0
      for el in numPacketsPerSec:
        avgNumPacket += el
      avgNumPacket /= len(numPacketsPerSec)
      avgSizePacket = 0
      for p in Packet_list:
        avgSizePacket += p.packetSize
      avgSizePacket /= len(Packet_list)

      step = get_x_labels(int(fin - strt))
      print('Общая информация:')
      print( 'Время первого перехваченного пакета: '
           , time.strftime('%d.%m.%Y г. %H:%M:%S', strt_time) )
      print( 'Время последнего перехваченного пакета: '
           , time.strftime('%d.%m.%Y г. %H:%M:%S', fin_time) )
      print('Количество пакетов: ', len(Packet_list))
      print('Общее время перехвата: ', round(fin - strt, 3), 'сек')
      print('Среднее количество пакетов в секунду: ', round(avgNumPacket, 3))
      print('Средний размер пакетов: ', round(avgSizePacket, 3))
      print('Завершить просмотр (нажмите \"q\" для выхода)')
      for k in range(len(IPList)):
        Object_list.append(ExploreObject(IPList[k]))
        Object_list[-1].commonPorts = get_common_ports(IPList[k])
      print_list_of_pairs(IPList)
      print(f'\nВыберите цифру (0 - {len(IPList) - 1}) для просмотра IP-адреса:')
      k = input()
      if k == 'q':
        break
      try:
        k = int(k)
      except:
        print('\nНекорректный ввод!\n')
        continue
      else:
        if 0 <= k and k < len(IPList):
          port = None
          print('Список портов которые учавствовали в соединении с данным IP-адресом')
          print_list_of_pairs(Object_list[k].commonPorts, True)
          t = len(Object_list[k].commonPorts)
          print(f'\nВыберите цифру (0 - {t}) для выбора порта:')
          k1 = input()
          if k1 == 'q':
            break
          try:
            k1 = int(k1)
          except:
            print('Некорректный ввод!\n')
            continue
          else:
            if 0 <= k1 and k1 <= t:
              if k1 != 0:
                port = Object_list[k].commonPorts[k1 - 1]
              choose_options(k, strt, fin, step, port)
            else:
              print(f'Введите число в пределах 0 - {t - 1}')
        else:
          print(f'Введите число в пределах 0 - {len(IPList) - 1}')
    elif bl == '5':
      return


if __name__ == '__main__':
  print('\nЗапуск программы....\n')
  choose_mode()