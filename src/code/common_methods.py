from session_creation import SessionInitialization, SessionInitialization2
from variable_definition import Packet_list
from package_parameters import PacketInf


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
                             f'Fl-rst:{obj.fl_rst};Fl-syn:{obj.fl_syn};Fl-fin:{obj.fl_fin};Win-size:{obj.win_size}!\n' )
            print(f'\nВ файл {FileName} была успешна записана информация.\n')
            f.close()
        except:
            print(f'\nОшибка записи в файл {FileName}! Возможно нет данных для записи\n')
            f.close()


# Обработка строки с данными
def row_processing(inf):
    global Packet_list
    data = []
    while True:
        beg = inf.find(':')
        end = inf.find(';')
        if beg == -1 and end == -1:
            break
        else:
            data.append(inf[beg + 1: end])
        inf = inf[end + 1:]
    Packet_list.append(PacketInf(data))


def get_new_session(pkt, iplist):
    if len(iplist) == 0:
        return True
    for el in iplist:
        if el == (pkt.ip_src, pkt.ip_dest) or (pkt.ip_dest, pkt.ip_src) == el:
            return False
    return True

# Считывание с файла и заполнение массива
# Packet_list объектами класса PacketInf
def read_from_file():
    # global Packet_list
    print('Введите название файла (например: data.log)')
    FileName = input()
    if Packet_list:
        return
    try:
        # si = SessionInitialization()
        si = SessionInitialization2()
        iplist = set()
        with open(FileName, 'r') as f:
            while True:
                inf = f.readline()
                if not inf:
                    break
                row_processing(inf)
                if get_new_session(Packet_list[-1], iplist):
                    iplist.add((Packet_list[-1].ip_src, Packet_list[-1].ip_dest))
                if si.curTime is None:
                    si.add_start_time(Packet_list[-1].timePacket) 
                si.find_session_location(Packet_list[-1])

        print(f"IPS = {iplist} len = {len(iplist)}")
    except:
        print(f'\nОшибка считывания файла {FileName}!\n')