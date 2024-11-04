import socket, struct, keyboard, os
import threading
import queue
from time import time
from variable_definition import Packet_list, line, Phrases_signs
from common_methods import write_to_file
from package_parameters import PacketInf
from session_creation import SessionInitialization


class Sniffer:

    def __init__(self) -> None:
        self.connection = None
        self.findRDP = False
        self.packet_queue = queue.Queue()
        self.error_load_model = False

    # Получение ethernet-кадра
    def get_ethernet_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto)


    # Получение MAC-адреса
    def get_mac_addr(self, mac_bytes):
        mac_str = ''
        for el in mac_bytes:
            mac_str += format(el, '02x').upper() + ':'
        return mac_str[:len(mac_str) - 1]


    # Получение IPv4-заголовка
    def get_ipv4_data(self, data):
        version_header_length = data[0]
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, dest = struct.unpack('!8xBB2x4s4s', data[:20])
        return ttl, proto, self.ipv4_dec(src), self.ipv4_dec(dest), data[header_length:]


    # Получение IP-адреса формата X.X.X.X
    def ipv4_dec(self, ip_bytes):
        ip_str = ''
        for el in ip_bytes:
            ip_str += str(el) + '.'
        return ip_str[:-1]


    # Получение UDP-сегмента данных
    def get_udp_segment(self, data):
        src_port, dest_port, size = struct.unpack('!HH2xH', data[:8])
        return str(src_port), str(dest_port), size, data[8:]


    # Получение TCP-cегмента данных
    def get_tcp_segment(self, data):
        src_port, dest_port, sequence, ack, \
            offset_flags, win_size = struct.unpack('!HHLLHH', data[:16])
        offset = (offset_flags >> 12) * 4
        return str(src_port), str(dest_port), str(sequence), \
               str(ack), offset_flags, win_size, data[offset:]


    # Форматирование данных для корректного представления
    def format_data(self, data):
        if isinstance(data, bytes):
            data = ''.join(r'\x{:02x}'.format(el) for el in data)
        return data


    # Перехват трафика и вывод информации в консоль
    def start_to_listen(self):
        
        def packet_processing():
            while True:
                pkt = self.packet_queue.get()
                if pkt is None:
                    break  # Завершаем обработку
                fl = si.find_session_location(pkt)
                si.print_packet_information(pkt, fl)
                self.packet_queue.task_done()

        global Packet_list
        NumPacket = 1
        curcnt = 1000
        pinf = [''] * 19
        si = SessionInitialization(self.findRDP, False)
        if self.findRDP:
            if not si.load_LSTM_model():
                self.error_load_model = True
                return

        # Запускаем поток для обработки пакетов
        processing_thread = threading.Thread(target=packet_processing)
        processing_thread.start()

        while True:
            raw_data, _ = self.connection.recvfrom(65565)
            pinf[0], pinf[1] = NumPacket, time()
            pinf[2] = len(raw_data)
            if si.curTime is None:
                si.add_start_time(pinf[1])

            pinf[4], pinf[3], protocol = self.get_ethernet_frame(raw_data)
            if protocol == 8:
                _, proto, pinf[6], pinf[7], data_ipv4 = self.get_ipv4_data(raw_data[14:])
                # if NumPacket > curcnt:
                #     curcnt += 1000
                #     si.clear_unwanted_sessions()

                if proto == 17:  # UDP
                    NumPacket += 1
                    pinf[5] = 'UDP'
                    pinf[8], pinf[9], _, data_udp = self.get_udp_segment(data_ipv4)
                    pinf[10] = len(data_udp)
                    Packet_list.append(PacketInf(pinf))
                    self.packet_queue.put(Packet_list[-1])

                if proto == 6:  # TCP
                    NumPacket += 1
                    pinf[5] = 'TCP'
                    pinf[8], pinf[9], pinf[11], \
                    pinf[12], flags, pinf[18], data_tcp = self.get_tcp_segment(data_ipv4)
                    pinf[10] = len(data_tcp)
                    pinf[13] = str((flags & 16) >> 4)
                    pinf[14] = str((flags & 8) >> 3)
                    pinf[15] = str((flags & 4) >> 2)
                    pinf[16] = str((flags & 2) >> 1)
                    pinf[17] = str(flags & 1)
                    Packet_list.append(PacketInf(pinf))
                    self.packet_queue.put(Packet_list[-1])

            if keyboard.is_pressed('space'):
                self.connection.close()
                self.packet_queue.put(None)
                processing_thread.join()
                si.packet_preparation()
                print('\nЗавершение программы...\n')
                break

    # Определение параметров перехвата трафика
    def traffic_interception(self):
        try:
            print('Поставить фильтр RDP? (Если да, то введите 1)')
            fl = input('Ответ: ')
            if fl == '1':
                self.findRDP = True
            print('\nВыберите сетевой интерфейс, нажав соответствующую цифру:')
            print(socket.if_nameindex())
            interface = int(input())
            if 0 > interface or interface > len(socket.if_nameindex()):
                print('\nОшибка ввода!!!\n')
                return
            os.system(f'ip link set {socket.if_indextoname(interface)} promisc on')
            self.connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except PermissionError:
            print('\nНедостаточно прав!')
            print('Запустите программу от имени администратора!')
            return
        else:
            print('\nНачался процесс захвата трафика...\n')
            self.start_to_listen()
        if not self.error_load_model:
            print(f'\nДанные собраны. Перехвачено: {len(Packet_list)} пакетов(-а)\n')
            write_to_file()