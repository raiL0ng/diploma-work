from session_creation import SessionInitialization
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
        si = SessionInitialization()
        with open(FileName, 'r') as f:
            while True:
                inf = f.readline()
                if not inf:
                    break
                Packet_list.append(row_processing(inf))
                _ = si.find_session_location(Packet_list[-1])
    except:
        print(f'\nОшибка считывания файла {FileName}!\n')