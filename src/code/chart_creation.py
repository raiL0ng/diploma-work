import time
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from colorama import Back, Fore
from variable_definition import Packet_list, Object_list, Labels_list


class ChartCreation():

    def __init__(self, k, strt, fin, port) -> None:
        self.k = k
        self.strt_time = strt
        self.fin_time = fin
        self.curPort = port
        self.step = None
        self.curIP = None
        self.x_axisLabels = []

    # Получение меток и "шага" для оси абсцисс
    def get_x_labels(self):
        total_time = int(self.fin_time - self.strt_time)
        self.step = 1
        if total_time > 600:
            self.step = 30
        elif total_time > 300:
            self.step = 10
        elif total_time > 50:
            self.step = 5
        self.x_axisLabels.clear()
        for i in range(0, len(Labels_list), self.step):
            self.x_axisLabels.append(Labels_list[i])


    # Получение общей информации о трафике,
    # связанном с выбранным IP-адресом
    def get_inf_about_IP(self):
        adjcPacketList = []
        adjcIPList = set()
        if self.curPort != None:
            for p in Packet_list:
                if p.port_src == self.curPort or p.port_dest == self.curPort:
                    if p.ip_src == self.curIP:
                        adjcPacketList.append(p)
                        adjcIPList.add(p.ip_dest)
                    if p.ip_dest == self.curIP:
                        adjcPacketList.append(p)
                        adjcIPList.add(p.ip_src)
        else:
            for p in Packet_list:
                if p.ip_src == self.curIP:
                    adjcPacketList.append(p)
                    adjcIPList.add(p.ip_dest)
                if p.ip_dest == self.curIP:
                    adjcPacketList.append(p)
                    adjcIPList.add(p.ip_src)
        return adjcPacketList, list(adjcIPList)


    # Вывод пакетов, связанных с выбранным IP-адресом 
    def print_adjacent_packets(self):
        adjcPacketLIst = Object_list[self.k].adjcPacketList
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


    # Вывод пар (число, IP-адрес/порт) для
    # предоставления выбора IP-адреса/порта
    # пользователю
    def print_list_of_pairs(self, IPList, fl=False):
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


    # Получение второго IP-адреса
    def get_2nd_IP_for_plot(self):
        print('\nИзобразить на графике еще один объект. Выберите ' + \
                    'IP-адрес для добавления (введите цифру)')
        self.print_list_of_pairs(Object_list[self.k].adjcIPList, True)
        scndIP = 'None'
        try:
            pos = int(input())
        except:
            print('Некорректный ввод!')
            return -1
        else:
            if pos < 0 or pos > len(Object_list[self.k].adjcIPList):
                print('Некорректный ввод!')
                return -1
            if pos != 0:
                scndIP = Object_list[self.k].adjcIPList[pos - 1]
        return scndIP


    # Получение номера по IP-адресу
    def get_pos_by_IP(self, exploreIP):
        for i in range(len(Object_list)):
            if Object_list[i].ip == exploreIP:
                return i
        return -1


    # Получение данных об отношении входящего
    # трафика к исходящему в единицу времени
    def get_in_out_rel(self, exploreIP):
        cntInput = 0
        cntOutput = 0
        rel_list = []
        curTime = self.strt_time + 1
        finTime = self.fin_time + 1
        pos = 0
        while curTime < finTime:
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
                if self.curPort == None:
                    if Packet_list[k].ip_src == exploreIP:
                        cntOutput += 1
                    if Packet_list[k].ip_dest == exploreIP:
                        cntInput += 1
                else:
                    if Packet_list[k].port_src == self.curPort or Packet_list[k].port_dest == self.curPort:
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
    def get_udp_tcp_rel(self, exploreIP):
        cntUDP = 0
        cntTCP = 0
        curTime = self.strt + 1
        finTime = self.fin_time + 1
        pos = 0
        rel_list = []
        while curTime < finTime:
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
                if self.curPort == None:
                    if Packet_list[k].ip_dest == exploreIP:
                        if Packet_list[k].protoType == 'TCP':
                            cntTCP += 1
                        if Packet_list[k].protoType == 'UDP':
                            cntUDP += 1
                else:
                    if Packet_list[k].port_src == self.curPort or Packet_list[k].port_dest == self.curPort:
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
    def get_ack_flags_diff(self, exploreIP):
        cntInput = 0
        cntOutput = 0
        diff_list = []
        curTime = self.strt_time + 1
        finTime = self.fin_time + 1
        pos = 0
        while curTime < finTime:
            for k in range(pos, len(Packet_list)):
                if Packet_list[k].timePacket > curTime:
                    diff_list.append(cntOutput - cntInput)
                    cntInput = 0
                    cntOutput = 0
                    pos = k
                    break
                if self.port == None:
                    if Packet_list[k].protoType == 'TCP' and Packet_list[k].fl_ack == '1':
                        if Packet_list[k].ip_src == exploreIP:
                            cntOutput += 1
                        if Packet_list[k].ip_dest == exploreIP:
                            cntInput += 1
                else:
                    if Packet_list[k].port_src == self.curPort or Packet_list[k].port_dest == self.curPort:
                        if Packet_list[k].protoType == 'TCP' and Packet_list[k].fl_ack == '1':
                            if Packet_list[k].ip_src == exploreIP:
                                cntOutput += 1
                            if Packet_list[k].ip_dest == exploreIP:
                                cntInput += 1
            curTime += 1
        diff_list.append(cntOutput - cntInput)
        return diff_list


    # Получение данных о частоте SYN-флагов
    def get_syn_flags_freq(self, exploreIP):
        cntSynTCP = 0
        cntTCP = 0
        rel_list = []
        curTime = self.strt_time + 1
        finTime = self.fin_time + 1
        pos = 0
        while curTime < finTime:
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
                if self.curPort == None:
                    if Packet_list[k].ip_dest == exploreIP and Packet_list[k].protoType == 'TCP':
                        cntTCP += 1
                        if Packet_list[k].fl_syn == '1':
                            cntSynTCP += 1
                else:
                    if Packet_list[k].port_src == self.curPort or Packet_list[k].port_dest == self.curPort:
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
    def get_psh_flags_freq(self, exploreIP):
        cntPshTCP = 0
        cntTCP = 0
        rel_list = []
        curTime = self.strt_time + 1
        finTime = self.fin_time + 1
        pos = 0
        while curTime < finTime:
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
                if self.curPort == None:
                    if Packet_list[k].ip_dest == exploreIP and Packet_list[k].protoType == 'TCP':
                        cntTCP += 1
                        if Packet_list[k].fl_psh == '1':
                            cntPshTCP += 1
                else:
                    if Packet_list[k].port_src == self.curPort or Packet_list[k].port_dest == self.curPort:
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
    def get_pktamnt_and_size_persec(self, exploreIP):
        pktAmntSrcList = []
        pktAmntDstList = []
        pktSizeSrcList = []
        pktSizeDstList = []
        curTime = self.strt_time + 1
        finTime = self.fin_time + 1
        pos = 0
        while curTime < finTime:
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
                if self.curPort == None:
                    if Packet_list[k].ip_src == exploreIP:
                        cntpktsrc += 1
                        if maxpktsizesrc < Packet_list[k].packetSize:
                            maxpktsizesrc = Packet_list[k].packetSize
                    if Packet_list[k].ip_dest == exploreIP:
                        cntpktdest += 1
                        if maxpktsizedst < Packet_list[k].packetSize:
                            maxpktsizedst = Packet_list[k].packetSize
            else:
                if Packet_list[k].port_src == self.curPort or Packet_list[k].port_dest == self.curPort:
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


    # Выбор опций для выбранного IP-адреса
    def start_to_plot(self):
        self.get_x_labels()
        self.curIP = Object_list[self.k].ip
        Object_list[self.k].adjcPacketList, Object_list[self.k].adjcIPList = self.get_inf_about_IP()
        Object_list[self.k].strt_time = time.localtime(Object_list[self.k].adjcPacketList[0].timePacket)
        Object_list[self.k].fin_time = time.localtime(Object_list[self.k].adjcPacketList[-1].timePacket)
        Object_list[self.k].amnt_packet = len(Object_list[self.k].adjcPacketList)
        totalTime = round( Object_list[self.k].adjcPacketList[-1].timePacket - \
                            Object_list[self.k].adjcPacketList[0].timePacket )
        if totalTime == 0:
            totalTime = 1
        Object_list[self.k].avg_packet_num = round(Object_list[self.k].amnt_packet / totalTime, 3)
        avgSize = 0
        for p in Object_list[self.k].adjcPacketList:
            avgSize += p.len_data
        Object_list[self.k].avg_packet_size = round(avgSize / Object_list[self.k].amnt_packet, 3)
        while True:
            print(f'Общая информация о трафике, связанном с {self.curIP}')
            print( 'Время первого перехваченного пакета: '
                , time.strftime('%d.%m.%Y г. %H:%M:%S', Object_list[self.k].strt_time) )
            print( 'Время последнего перехваченного пакета: '
                , time.strftime('%d.%m.%Y г. %H:%M:%S', Object_list[self.k].fin_time) )
            print('Общее время:', totalTime, 'сек.')
            print('Количество пакетов: ', Object_list[self.k].amnt_packet)
            print('Среднее количество пакетов в секунду: ', Object_list[self.k].avg_packet_num)
            print('Средний размер пакетов: ', Object_list[self.k].avg_packet_size)  
            print(f"""Выберите опцию:
            1. Вывести весь трафик, связанный с {self.curIP}
            2. Построить график отношения входящего и исходящего трафиков
            3. Построить график отношения объема входящего UDP-трафика и объёма входящего TCP-трафика
            4. Построить график разности числа исходящих и числа входящих ACK-флагов в единицу времени
            5. Построить график частоты SYN и PSH флагов во входящих пакетах
            6. Построить график отображения количества пакетов в единицу времени
            7. Построить график отображения максимумов среди пакетов в единицу времени
            8. Вернуться к выбору IP-адреса """)
            bl = input()
            if bl == '1':
                self.print_adjacent_packets()
            elif bl == '2':
                Object_list[self.k].in_out_rel_data = self.get_in_out_rel(self.curIP)
                x = [i for i in range(0, len(Object_list[self.k].in_out_rel_data))]
                x_labels = [i for i in range(0, len(x), self.step)]
                scndIP = self.get_2nd_IP_for_plot()
                if scndIP == -1:
                    continue
                if scndIP != 'None':
                    pos = self.get_pos_by_IP(scndIP)
                    Object_list[pos].in_out_rel_data = self.get_in_out_rel(scndIP)
                fig = plt.figure(figsize=(16, 6), constrained_layout=True)
                f = fig.add_subplot()
                f.grid()
                f.set_title('Отношение объема входящего к объему исходящего трафиков' + \
                            r' ($r_{in/out} = \frac{V_{in}}{V_{out}}$)', fontsize=15 )
                f.set_xlabel('Общее время перехвата трафика', fontsize=15)
                f.set_ylabel(r'$r_{in/out} = \frac{V_{in}}{V_{out}}$', fontsize=15)
                plt.plot(x, Object_list[self.k].in_out_rel_data, label=self.curIP)
                if scndIP != 'None':
                    plt.plot(x, Object_list[pos].in_out_rel_data, label=scndIP)
                plt.xticks(x_labels, self.x_axisLabels, rotation=30, fontsize=10)
                f.legend()
                plt.show()
            elif bl == '3':
                Object_list[self.k].udp_tcp_rel_data = self.get_udp_tcp_rel(self.curIP)
                x = [i for i in range(0, len(Object_list[self.k].udp_tcp_rel_data))]
                x_labels = [i for i in range(0, len(x), self.step)]
                scndIP = self.get_2nd_IP_for_plot()
                if scndIP == -1:
                    continue
                if scndIP != 'None':
                    pos = self.get_pos_by_IP(scndIP)
                    Object_list[pos].udp_tcp_rel_data = self.get_udp_tcp_rel(scndIP)
                fig = plt.figure(figsize=(16, 6), constrained_layout=True)
                f = fig.add_subplot()
                f.grid()
                f.set_title( 'Отношение объема входящего UDP-трафика к объему ' +  
                             'входящего TCP-трафика' + r' ($r_{in} = \frac{V_{udp}}{V_{tcp}}$)'
                           , fontsize=15 )
                f.set_xlabel('Общее время перехвата трафика', fontsize=15)
                f.set_ylabel(r'$r_{in} = \frac{V_{udp}}{V_{tcp}}$', fontsize=15)
                plt.plot(x, Object_list[self.k].udp_tcp_rel_data, label=self.curIP)
                if scndIP != 'None':
                    plt.plot(x, Object_list[pos].udp_tcp_rel_data, label=scndIP)
                plt.xticks(x_labels, self.x_axisLabels, rotation=30, fontsize=10)
                f.legend()
                plt.show()
            elif bl == '4':
                Object_list[self.k].ack_flags_diff_data = self.get_ack_flags_diff(self.curIP)
                x = [i for i in range(0, len(Object_list[self.k].ack_flags_diff_data))]
                x_labels = [i for i in range(0, len(x), self.step)]
                scndIP = self.get_2nd_IP_for_plot()
                if scndIP == -1:
                    continue
                if scndIP != 'None':
                    pos = self.get_pos_by_IP(scndIP)
                    Object_list[pos].ack_flags_diff_data = self.get_ack_flags_diff(scndIP)
                fig = plt.figure(figsize=(16, 6), constrained_layout=True)
                f = fig.add_subplot()
                f.grid()
                f.set_title('Разность числа исходящих и числа входящих ACK-флагов' + \
                            r' ($r_{ack} = V_{A_{out}} - V_{A_{in}}$)', fontsize=15)
                f.set_xlabel('Общее время перехвата трафика', fontsize=15)
                f.set_ylabel(r'$r_{ack} = V_{A_{out}} - V_{A_{in}}$', fontsize=15)
                plt.plot(x, Object_list[self.k].ack_flags_diff_data, label=self.curIP)
                if scndIP != 'None':
                    plt.plot(x, Object_list[pos].ack_flags_diff_data, label=scndIP)
                plt.xticks(x_labels, self.x_axisLabels, rotation=30, fontsize=10)
                f.legend()
                plt.show()
            elif bl == '5':
                data = self.get_syn_flags_freq(self.curIP)
                Object_list[self.k].syn_flags_freq_data = data
                data = self.get_psh_flags_freq(self.curIP)
                Object_list[self.k].psh_flags_freq_data = data
                x = [i for i in range(0, len(Object_list[self.k].syn_flags_freq_data))]
                x_labels = [i for i in range(0, len(x), self.step)]
                scndIP = self.get_2nd_IP_for_plot()
                if scndIP == -1:
                    continue
                if scndIP != 'None':
                    pos = self.get_pos_by_IP(scndIP)
                    data = self.get_syn_flags_freq(scndIP)
                    Object_list[pos].syn_flags_freq_data = data
                    data = self.get_psh_flags_freq(scndIP)
                    Object_list[pos].psh_flags_freq_data = data
                fig = plt.figure(figsize=(16, 6), constrained_layout=True)
                gs = gridspec.GridSpec(ncols=1, nrows=2, figure=fig)
                fig_1 = fig.add_subplot(gs[0, 0])
                fig_1.grid()
                fig_1.set_title('Частота флагов SYN' + \
                                r' ($r_{syn} = \frac{V_{S_{in}}}{V_{tcp}}$)', fontsize=15)
                fig_1.set_xlabel('Общее время перехвата трафика', fontsize=15)
                fig_1.set_ylabel(r'$r_{syn} = \frac{V_{S_{in}}}{V_{tcp}}$', fontsize=15)
                plt.plot(x, Object_list[self.k].syn_flags_freq_data, 'b', label=self.curIP)
                if scndIP != 'None':
                    plt.plot(x, Object_list[pos].syn_flags_freq_data, 'r', label=scndIP)
                plt.xticks(x_labels, self.x_axisLabels, rotation=30, fontsize=8)
                fig_1.legend()
                fig_2 = fig.add_subplot(gs[1, 0])
                fig_2.grid()
                plt.plot(x, Object_list[self.k].psh_flags_freq_data, 'orange', label=self.curIP)
                fig_2.set_title('Частота флагов PSH' + \
                                r' ($r_{psh} = \frac{V_{P_{in}}}{V_{tcp}}$)', fontsize=15)
                fig_2.set_xlabel('Общее время перехвата трафика', fontsize=15)
                fig_2.set_ylabel(r'$r_{psh} = \frac{V_{P_{in}}}{V_{tcp}}$', fontsize=15)
                if scndIP != 'None':
                    plt.plot(x, Object_list[pos].psh_flags_freq_data, 'g', label=scndIP)
                plt.xticks(x_labels, self.x_axisLabels, rotation=30, fontsize=8)
                fig_2.legend()
                plt.show()
            elif bl == '6':
                d1, d2, d3, d4 = self.get_pktamnt_and_size_persec(self.curIP)
                Object_list[self.k].pkt_amnt_src_data = d1
                Object_list[self.k].pkt_amnt_dst_data = d2
                Object_list[self.k].pkt_size_data_src = d3
                Object_list[self.k].pkt_size_data_dst = d4
                x = [i for i in range(0, len(Object_list[self.k].pkt_amnt_src_data))]
                x_labels = [i for i in range(0, len(x), self.step)]
                scndIP = self.get_2nd_IP_for_plot()
                if scndIP == -1:
                    continue
                if scndIP != 'None':
                    pos = self.get_pos_by_IP(scndIP)
                    d1, d2, d3, d4 = self.get_pktamnt_and_size_persec(scndIP)
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
                plt.plot(x, Object_list[self.k].pkt_amnt_dst_data, 'b', label=self.curIP)
                if scndIP != 'None':
                    plt.plot(x, Object_list[pos].pkt_amnt_dst_data, 'r', label=scndIP)
                plt.xticks(x_labels, self.x_axisLabels, rotation=30, fontsize=8)
                fig_1.legend()
                fig_2 = fig.add_subplot(gs[1, 0])
                fig_2.grid()
                plt.plot(x, Object_list[self.k].pkt_amnt_src_data, 'orange', label=self.curIP)
                fig_2.set_title('Количество исходящих пакетов, полученных за ' + \
                                'единицу времени', fontsize=15)
                fig_2.set_xlabel('Общее время перехвата трафика', fontsize=15)
                if scndIP != 'None':
                    plt.plot(x, Object_list[pos].pkt_amnt_src_data, 'g', label=scndIP)
                plt.xticks(x_labels, self.x_axisLabels, rotation=30, fontsize=8)
                fig_2.legend()
                plt.show()
            elif bl == '7':
                d1, d2, d3, d4 = self.get_pktamnt_and_size_persec(self.curIP)
                Object_list[self.k].pkt_amnt_src_data = d1
                Object_list[self.k].pkt_amnt_dst_data = d2
                Object_list[self.k].pkt_size_data_src = d3
                Object_list[self.k].pkt_size_data_dst = d4
                x = [i for i in range(0, len(Object_list[self.k].pkt_size_data_src))]
                x_labels = [i for i in range(0, len(x), self.step)]
                scndIP = self.get_2nd_IP_for_plot()
                if scndIP == -1:
                    continue
                if scndIP != 'None':
                    pos = self.get_pos_by_IP(scndIP)
                    d1, d2, d3, d4 = self.get_pktamnt_and_size_persec(scndIP)
                    Object_list[pos].pkt_amnt_src_data = d1
                    Object_list[pos].pkt_amnt_dst_data = d2
                    Object_list[pos].pkt_size_data_src = d3
                    Object_list[pos].pkt_size_data_dst = d4
                fig = plt.figure(figsize=(16, 6), constrained_layout=True)
                gs = gridspec.GridSpec(ncols=1, nrows=2, figure=fig)
                fig_1 = fig.add_subplot(gs[0, 0])
                fig_1.grid()
            elif bl == '8':
                break