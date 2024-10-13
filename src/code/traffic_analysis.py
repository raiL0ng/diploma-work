import time
from variable_definition import Packet_list, Object_list, Labels_list, Session_list
from session_creation import SessionInitialization, Session, SessionInitialization2, Session2
from package_parameters import ExploreObject
from chart_creation import ChartCreation

class TrafficAnalysis:

    def __init__(self) -> None:
        self.IPList = None
        self.numPacketsPerSec = None
        # self.strt_time = None
        # self.fin_time = None
        # self.avgNumPacket = None
        # self.avgSizePacket = None


    # Получение общей информации о текущей
    # попытке перехвата трафика
    def get_common_data(self):
        global Labels_list
        Labels_list.clear()
        self.IPList = set()
        self.numPacketsPerSec = []
        curTime = Packet_list[0].timePacket + 1
        fin = Packet_list[-1].timePacket + 1
        Labels_list.append(time.strftime('%H:%M:%S', time.localtime(Packet_list[0].timePacket)))
        cntPacket = 0
        i = 0
        while curTime < fin:
            for k in range(i, len(Packet_list)):
                if Packet_list[k].timePacket > curTime:
                    self.numPacketsPerSec.append(cntPacket)
                    Labels_list.append(time.strftime('%H:%M:%S', time.localtime(curTime)))
                    cntPacket = 0
                    i = k
                    break
                cntPacket += 1
            curTime += 1
        self.numPacketsPerSec.append(cntPacket)
        for p in Packet_list:
            self.IPList.add(p.ip_src)
            self.IPList.add(p.ip_dest)
        self.IPList = sorted(list(self.IPList), key=lambda ip: list(map(int, ip.split('.'))))
    

    # Получение общих портов относительно текущего IP-адреса
    def get_common_ports(self, curIP):
        ports = set()
        for pkt in Packet_list:
            if pkt.ip_src == curIP or pkt.ip_dest == curIP:
                ports.add(pkt.port_src)
                ports.add(pkt.port_dest)
        return sorted(list(ports))


    # Вывод пар (число, IP-адрес/порт) для
    # предоставления выбора IP-адреса/порта
    # пользователю
    def print_list_of_pairs(self, IPList, fl=False):
        num = 0
        cnt = 1
        if fl:
            print('[' + str(num), '---', 'None', end='] ')
            cnt += 1
            num += 1
        for el in IPList:
            if cnt > 3:
                cnt = 0
                print('[' + str(num), '---', el, end=']\n')
            else:
                print('[' + str(num), '---', el, end='] ')
            cnt += 1
            num += 1
        print('')


    def start_to_analyse(self):
        if Packet_list == []:
            print('\nНет данных! Сначала необходимо получить данные!\n')
            return
        self.get_common_data()
        # si = SessionInitialization()
        # print(f'Sessions len = {len(Session_list)}:')
        # for el in Session_list:
        #     print(f"({el.initiator}, {el.target})", end=' ')
        # si.clear_unwanted_sessions()
        # print(f'after clean Sessions len = {len(Session_list)}:')
        # for el in Session_list:
        #     print(f"({el.initiator}, {el.target})", end=' ')
        # for s in Session_list:
        #     s.fin_rdp_check()
        # si.print_inf_about_sessions()
        si = SessionInitialization2()
        print(f'Sessions len = {len(Session_list)}:')
        si.clear_unwanted_sessions()
        print(f'After Sessions len = {len(Session_list)}:')
        si.print_inf_about_sessions()
        strt = Packet_list[0].timePacket
        fin = Packet_list[-1].timePacket
        strt_time = time.localtime(strt)
        fin_time = time.localtime(fin)
        avgNumPacket = 0
        for el in self.numPacketsPerSec:
            avgNumPacket += el
        avgNumPacket /= len(self.numPacketsPerSec)
        avgSizePacket = 0
        for p in Packet_list:
            avgSizePacket += p.packetSize
        avgSizePacket /= len(Packet_list)
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
        for k in range(len(self.IPList)):
            Object_list.append(ExploreObject(self.IPList[k]))
            Object_list[-1].commonPorts = self.get_common_ports(self.IPList[k])
        self.print_list_of_pairs(self.IPList)
        print(f'\nВыберите цифру (0 - {len(self.IPList) - 1}) для просмотра IP-адреса:')
        k = input()
        if k == 'q':
            return
        try:
            k = int(k)
        except:
            print('\nНекорректный ввод!\n')
            return
        else:
            if 0 <= k and k < len(self.IPList):
                port = None
                print('Список портов которые учавствовали в соединении с данным IP-адресом')
                self.print_list_of_pairs(Object_list[k].commonPorts, True)
                t = len(Object_list[k].commonPorts)
                print(f'\nВыберите цифру (0 - {t}) для выбора порта:')
                k1 = input()
                if k1 == 'q':
                    return
                try:
                    k1 = int(k1)
                except:
                    print('Некорректный ввод!\n')
                    return
                else:
                    if 0 <= k1 and k1 <= t:
                        if k1 != 0:
                            port = Object_list[k].commonPorts[k1 - 1]
                        ChartCreation(k, strt, fin, port).start_to_plot()
                    else:
                        print(f'Введите число в пределах 0 - {t - 1}')
            else:
                print(f'Введите число в пределах 0 - {len(self.IPList) - 1}')