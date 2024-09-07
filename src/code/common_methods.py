import time
from colorama import init, Back, Fore
from variable_definition import Packet_list, Session_list, Labels_list, line
from package_parameters import PacketInf


init(autoreset=True)


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
def write_to_file():
    print('Введите название файла (например: data.log)')
    FileName = input()
    try:
        f = open(FileName, 'w')
    except:
        print('\nНекорректное название файла!\n')
    else:
        if Packet_list == []:
            return
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
            print(f'\nВ файл {FileName} была успешна записана информация.\n')
            f.close()
        except:
            print(f'\nОшибка записи в файл {FileName}! Возможно нет данных для записи\n')
            f.close()


# Обработка строки с данными
def row_processing(inf):
    data = []
    while True:
        beg = inf.find(':')
        end = inf.find(';')
        if beg == -1 and end == -1:
            break
        else:
            data.append(inf[beg + 1: end])
        inf = inf[end + 1:]
    return PacketInf().set_data_from_list(data)


# Считывание с файла и заполнение массива
# Packet_list объектами класса PacketInf
def read_from_file():
    global Packet_list
    print('Введите название файла (например: data.log)')
    FileName = input()
    if Packet_list:
        return
    try:
        with open(FileName, 'r') as f:
            while True:
                inf = f.readline()
                if not inf:
                    break
                Packet_list.append(row_processing(inf))
                _ = find_session_location(Packet_list[-1])
    except:
        print(f'\nОшибка считывания файла {FileName}!\n')


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
