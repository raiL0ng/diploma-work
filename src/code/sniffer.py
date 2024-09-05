import socket, struct, keyboard
from time import time
from variable_definition import Packet_list
from common_methods import find_session_location, clear_end_sessions, print_packet_inf
from package_parameters import PacketInf


class SnifferRDP:

    def __init__(self) -> None:
        # для UNIX систем
        self.connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

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
        src_port, dest_port, sequence, ack, some_block = struct.unpack('!HHLLH', data[:14])
        return str(src_port), str(dest_port), str(sequence), str(ack), \
                some_block, data[(some_block >> 12) * 4:]


    # Форматирование данных для корректного представления
    def format_data(self, data):
        if isinstance(data, bytes):
            data = ''.join(r'\x{:02x}'.format(el) for el in data)
        return data


    # Перехват трафика и вывод информации в консоль
    def start_to_listen(self):
        global Packet_list
        NumPacket = 1
        curcnt = 1000
        while True:
            # Получение пакетов в виде набора hex-чисел
            raw_data, _ = self.connection.recvfrom(65565)
            pinf = [''] * 18
            pinf[0], pinf[1] = NumPacket, time()
            pinf[2] = len(raw_data)
            # Если это интернет-протокол четвертой версии    
            pinf[4], pinf[3], protocol = self.get_ethernet_frame(raw_data)
            if protocol == 8:
                _, proto, pinf[6], pinf[7], data_ipv4 = self.get_ipv4_data(raw_data[14:])
                if NumPacket > curcnt:
                    curcnt += 1000
                    clear_end_sessions() 
                # Если это UDP-протокол  
                if proto == 17:
                    NumPacket += 1
                    pinf[5] = 'UDP'
                    pinf[8], pinf[9], _, data_udp = self.get_udp_segment(data_ipv4)
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
                    pinf[12], flags, data_tcp = self.get_tcp_segment(data_ipv4)
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
                self.connection.close()
                print('\nЗавершение программы...\n')
                break