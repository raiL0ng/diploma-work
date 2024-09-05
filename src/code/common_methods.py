import time
from variable_definition import Packet_list, Session_list, findRDP, line


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