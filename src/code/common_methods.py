from session_creation import SessionInitialization
from package_parameters import PacketInf

# Список перехваченных пакетов
Packet_list = []

# Запись информации о пакетах в файл
def write_to_file():
    if not Packet_list:
        print('Нет данных для записи в файл!')
        return
    
    try:
        FileName = input('Введите название файла (например: data.log): ')
        with open(FileName, 'w') as f:
            for obj in Packet_list:
                base_info = (
                    f"No:{obj.numPacket};Time:{obj.timePacket};Pac-size:{obj.packetSize};"
                    f"MAC-src:{obj.mac_src};MAC-dest:{obj.mac_dest};Type:{obj.protoType};"
                    f"IP-src:{obj.ip_src};IP-dest:{obj.ip_dest};Port-src:{obj.port_src};"
                    f"Port-dest:{obj.port_dest};Len-data:{obj.len_data};"
                )
                if obj.protoType == 'TCP':
                    tcp_info = (
                        f"Seq:{obj.seq};Ack:{obj.ack};Fl-ack:{obj.fl_ack};"
                        f"Fl-psh:{obj.fl_psh};Fl-rst:{obj.fl_rst};Fl-syn:{obj.fl_syn};"
                        f"Fl-fin:{obj.fl_fin};Win-size:{obj.win_size};"
                    )
                    f.write(base_info + tcp_info + "!\n")
                else:
                    f.write(base_info + "!\n")
            print(f'\nИнформация успешно записана в файл {FileName}.\n')
    except Exception as e:
        print(f'\nОшибка записи в файл {FileName}: {e}\n')

# Обработка строки с данными
def row_processing(inf):
    global Packet_list
    data = [field.split(':', 1)[1] for field in inf.split(';') if ':' in field]
    if data:
        Packet_list.append(PacketInf(data))

# Проверка, является ли сессия новой
def is_new_session(pkt, iplist):
    return (pkt.ip_src, pkt.ip_dest) not in iplist and (pkt.ip_dest, pkt.ip_src) not in iplist

# Считывание с файла и заполнение массива Packet_list
def read_from_file():
    try:
        FileName = input('Введите название файла (например: data.log): ')
        if Packet_list:
            print('Список Packet_list уже содержит данные.')
            return
        si = SessionInitialization(False, False)
        si.load_LSTM_model()
        iplist = set()
        
        with open(FileName, 'r') as f:
            for inf in f:
                if not inf.strip():
                    continue
                row_processing(inf)
                packet = Packet_list[-1]
                
                if is_new_session(packet, iplist):
                    iplist.add((packet.ip_src, packet.ip_dest))
                
                if si.curTime is None:
                    si.add_start_time(packet.timePacket)
                
                si.find_session_location(packet)
        
        si.packet_preparation()
        print(f'\nДанные успешно считаны из файла {FileName}.\n')
    except Exception as e:
        print(f'\nОшибка обработки файла {FileName} или загрузки модели: {e}\n')
