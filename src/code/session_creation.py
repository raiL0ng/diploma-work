import time
import numpy as np
from variable_definition import Packet_list, Session_list, line
from colorama import init, Back, Fore
from math import sqrt
from keras.models import load_model
from keras.models import Sequential
from keras.layers import LSTM, Dense


init(autoreset=True)


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

        self.pktTimeIntervals = []
        self.prevPktTime__ = None
        self.curTime__ = strtTime + 10

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
            dev = sqrt(sum / n)
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
                dev = sqrt(sum / l)
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


    def set_time_intervals(self, pkt):
        if self.curTime__ > self.curTime__:
            self.curTime__ += 10
            return 
        if self.prevPktTime__ is None:
            self.prevPktTime__ = pkt.timePacket
        else:
            self.pktTimeIntervals.append(pkt.timePacket - self.prevPktTime__)
            self.prevPktTime__ = pkt.timePacket
        return None

class SessionInitialization:

    def __init__(self) -> None:
        pass

    # Обработка значений списка Session_list
    def clear_unwanted_sessions(self):
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
    def find_session_location(self, pkt):
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
    def print_inf_about_sessions(self):
        cnt = 1
        print(f'\nБыло перехвачено {len(Session_list)} сессии(-й)')
        for s in Session_list:
            print( f'\nИнформация о сессии #{cnt}:\n' +
                   f'Инициатор подключения: {s.initiator}'
                   f'Целевое устройство: {s.target}'
                   f'Порт подключения: {s.port}')
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


class Session2:

    def __init__(self, strt_time, ips, ports) -> None:
        self.strt_time = strt_time
        self.ips = ips
        self.stateActive = True
        self.forceFin = False
        self.ports = ports
        self.prevTimePkt = None
        self.lastTimePkt = None
        self.totalTime = None
        self.intervalsList = []

        self.cntPktSrcIP1 = 0
        self.cntPktDestIP1 = 0
        self.pktSizeDestIP1 = []
        self.pktSizeDestIP2 = []
        
        # Для подсчета флагов PSH        
        self.cntPSHDestIP1 = 0
        self.cntPSHDestIP2 = 0
        # Для подсчета флагов ACK
        self.cntACKDestIP1 = 0
        self.cntACKDestIP2 = 0
        self.cntACKSrcIP1 = 0
        # Для подсчета всего TCP-трафика
        self.cntPktTCPDestIP1 = 0
        self.cntPktTCPDestIP2 = 0

        self.winSizeList = []

        self.cntPktUDP = 0
        self.cntPkt = 0
        self.CNT = 0


    def update_data(self, pkt):
        # Вычисление временных интервалов
        if self.prevTimePkt is None:
            self.prevTimePkt = pkt.timePacket
        else:
            self.intervalsList.append(pkt.timePacket - self.prevTimePkt)
            self.prevTimePkt = pkt.timePacket
        # Подсчет параметров входящего и исходящего трафиков для IP1
        # и размера входящих пакетов для IP1 и IP2
        if pkt.ip_src == self.ips[0]:
            self.cntPktSrcIP1 += 1
            self.pktSizeDestIP2.append(pkt.packetSize)
        else:
            self.cntPktDestIP1 += 1
            self.pktSizeDestIP1.append(pkt.packetSize)
        # Подсчет флагов PSH и ACK
        if pkt.protoType == 'TCP':
            if pkt.ip_dest == self.ips[0]:
                if pkt.fl_psh == '1':
                    self.cntPSHDestIP1 += 1
                if pkt.fl_ack == '1':
                    self.cntACKDestIP1 += 1
                self.cntPktTCPDestIP1 += 1
            if pkt.ip_dest == self.ips[1]:
                if pkt.fl_psh == '1':
                    self.cntPSHDestIP2 += 1
                if pkt.fl_ack == '1':
                    self.cntACKDestIP2 += 1
                    self.cntACKSrcIP1 += 1
                self.cntPktTCPDestIP2 += 1
            if pkt.fl_fin == '1' or pkt.fl_rst == '1':
                self.forceFin = True
            # Подсчет размеров окна
            self.winSizeList.append(pkt.win_size)
        else:
            self.cntPktUDP += 1
        self.lastTimePkt = pkt.timePacket
        self.cntPkt += 1
        self.CNT += 1

    def clean_all_parameters(self):
        self.prevTimePkt = None
        self.intervalsList.clear()
        self.cntPktSrcIP1 = 0
        self.cntPktDestIP1 = 0
        self.pktSizeDestIP1.clear()
        self.pktSizeDestIP2.clear()
        self.cntPSHDestIP1 = 0
        self.cntPSHDestIP2 = 0
        self.cntACKDestIP1 = 0
        self.cntACKDestIP2 = 0
        self.cntACKSrcIP1 = 0
        self.cntPktTCPDestIP1 = 0
        self.cntPktTCPDestIP2 = 0
        
        self.winSizeList.clear()
        self.cntPktUDP = 0
        self.cntPkt = 0


    def ratio_calc(self, num, denom):
        if denom == 0:
            return 0
        return num / denom


    def get_result(self):
        result = []
        if not self.stateActive:
            return None
        l = len(self.intervalsList)
        self.totalTime = round(self.lastTimePkt - self.strt_time, 2)
        # print(f"intervals = {l} pktSizeDstIP1 = {len(self.pktSizeDestIP1)} pktSizeDstIP2 = {len(self.pktSizeDestIP2)} winsize = {len(self.winSizeList)} cntPkt = {self.cntPkt} CNT = {self.CNT}")
        if self.stateActive and self.cntPkt < 2:
            self.stateActive = False
            # print( f'Время last:'
            #      , time.strftime('%d.%m.%Y г. %H:%M:%S', time.localtime(self.lastTimePkt)) )
            # print( f'Время strt:'
            #      , time.strftime('%d.%m.%Y г. %H:%M:%S', time.localtime(self.strt_time)) )
            # print( f'Время total: {self.totalTime}' )
            return None
        # Вычисление средней задержки
        sum = 0
        for el in self.intervalsList:
            sum += el
        result.append(sum / l)
        # Вычисление стандартного отклонения
        sum = 0
        for el in self.intervalsList:
            sum += (el - result[0]) * (el - result[0])
        result.append(sqrt(sum / l))
        # Вычисление среднего отклонения (джиттера)
        sum = 0
        if l < 2:
            result.append(0)
        else:
            for i in range(1, l):
                sum += abs(self.intervalsList[i] - self.intervalsList[i - 1])
            result.append(sum / (l - 1))
        # Вычисление медианы временных интервалов
        tmp = sorted(self.intervalsList)
        if l % 2 == 0:
            result.append((tmp[(l // 2) - 1] + tmp[l // 2]) / 2)
        else:
            result.append(tmp[l // 2])
        # Вычисление отношения объема входящего на исходящий трафик для IP1 и IP2
        result.append(self.ratio_calc(self.cntPktDestIP1, self.cntPktSrcIP1))
        result.append(self.ratio_calc(self.cntPktSrcIP1, self.cntPktDestIP1))
        # Вычисление отношения объема UDP-трафика и TCP-трафика
        result.append(self.ratio_calc(self.cntPktUDP, self.cntPkt - self.cntPktUDP))
        # Вычисление среднего значения объема пакетов получаемого IP1
        l = len(self.pktSizeDestIP1)
        sum = 0
        for el in self.pktSizeDestIP1:
            sum += el
        if l != 0:
            result.append(sum / l)
        else:
            result.append(0)
        # Вычисление среднего значения объема пакетов получаемого IP2
        l = len(self.pktSizeDestIP2)
        sum = 0
        for el in self.pktSizeDestIP2:
            sum += el
        if l != 0:
            result.append(sum / l)
        else:
            result.append(0)
        # Вычисление частоты флагов PSH для IP1 и IP2
        result.append(self.ratio_calc(self.cntPSHDestIP1, self.cntPktTCPDestIP1))
        result.append(self.ratio_calc(self.cntPSHDestIP2, self.cntPktTCPDestIP2))
        # Вычисление частоты флагов ACK для IP1 и IP2
        result.append(self.ratio_calc(self.cntACKDestIP1, self.cntPktTCPDestIP1))
        result.append(self.ratio_calc(self.cntACKDestIP2, self.cntPktTCPDestIP2))
        # Вычисление отношения ACK/PSH для IP1 и IP2
        result.append(self.ratio_calc(self.cntPSHDestIP1, self.cntACKDestIP1))
        result.append(self.ratio_calc(self.cntPSHDestIP2, self.cntACKDestIP2))
        # Вычисление разности числа исходящих и входящих ACK-флагов IP1
        result.append(abs(self.cntACKDestIP1 - self.cntACKSrcIP1))
        # Вычисление среднего размера экрана
        l = len(self.winSizeList)
        if l != 0:
            sum = 0
            for el in self.winSizeList:
                sum += el
            result.append(sum / l)
            # Вычисление частоты обновления окна
            cntRatio = 1
            prev = self.winSizeList[0]
            for winSize in self.winSizeList[1:]:
                if prev != winSize:
                    prev = winSize
                    cntRatio += 1
            result.append(cntRatio / 15)
        else:
            result.extend([0, 0])
        self.clean_all_parameters()
        return result


class SessionInitialization2:


    def __init__(self) -> None:
        # self.strtTime = strt
        self.known_ports = {21, 22, 23, 25, 53, 80, 88, 161, 443, 873}
        self.curTime = None
        self.model = None
        self.train_mode = True
        self.x_input = []
        self.cntPeriods = 0

    def add_start_time(self, strt):
        self.curTime = strt + 15


    # Запись входных векторов в файл
    def write_data_to_file(self, filename='x_input.log'):
        with open(filename, 'a+') as f:
            f.write(f"{self.cntPeriods}-th interval\n")
            for ports, row in self.x_input:
                f.write(f'{ports}:')
                for el in row:
                    f.write(f'{el},')
                f.write('!\n')


    # Загрузка модели для дальнейшей работы с ней
    def load_LSTM_model(self, path='../model_directory/model.keras'):
        self.model = load_model(path)


    def find_session_location(self, pkt) -> None:
        global Session_list
        isNewSession = True
        if pkt.timePacket > self.curTime:
            self.x_input.clear()
            self.cntPeriods += 1
            for s in Session_list:
                vec = s.get_result()
                if vec is not None:
                    self.x_input.append((s.ports, vec))
                # print(f"ips = {s.ips} ports = {s.ports} vector = {vec}")
            if self.train_mode:
                self.write_data_to_file()
            else:
                #TODO здесь должно быть предсказание
                pass
            self.curTime += 15
        for s in Session_list:
            if s.stateActive and pkt.ip_src in s.ips and pkt.ip_dest in s.ips:
                if (s.ports[1] is None and (pkt.port_src == s.ports[0] or pkt.port_dest == s.ports[0])) or \
                   (pkt.port_src in s.ports and pkt.port_dest in s.ports):
                    isNewSession = False
                    s.update_data(pkt)
        if isNewSession:
            if pkt.port_src in self.known_ports:
                Session_list.append(Session2(pkt.timePacket, (pkt.ip_src, pkt.ip_dest), (pkt.port_src, None)))
            elif pkt.port_dest in self.known_ports:
                Session_list.append(Session2(pkt.timePacket, (pkt.ip_src, pkt.ip_dest), (pkt.port_dest, None)))
            else:
                Session_list.append(Session2(pkt.timePacket, (pkt.ip_src, pkt.ip_dest), (pkt.port_src, pkt.port_dest)))
            Session_list[-1].update_data(pkt)

    # TODO добавить сюда тоже вызов нейронки
    def rest_data_process(self):
        global Session_list
        for s in Session_list:
            vec = s.get_result()


    # Обработка значений списка Session_list
    def clear_unwanted_sessions(self):
        global Session_list
        n = len(Session_list)
        ids = []
        for i in range(n):
            if Session_list[i].CNT < 20 or Session_list[i].totalTime < 10:
                ids.append(i)
        tmp = Session_list.copy()
        Session_list.clear()
        for i in range(n):
            if i in ids:
                continue
            Session_list.append(tmp[i])


    # Вывод информации о сессиях
    def print_inf_about_sessions(self):
        cnt = 1
        print(f'\nБыло перехвачено {len(Session_list)} сессии(-й)')
        for s in Session_list:
            print( f'\nИнформация о сессии #{cnt}:\n' +
                   f'IP-адреса: {s.ips}\n' +
                   f'Порт подключения: {s.ports}')
            print( f'Время перехвата первого пакета:'
                 , time.strftime('%d.%m.%Y г. %H:%M:%S', time.localtime(s.strt_time)) )
            print(f'Количество перехваченных пакетов: {s.CNT}')
            print( f'Общее время перехвата: {s.totalTime}')
            
            # if s.finTime == None:
            #     print(f'Время завершения соединения: нет данных')
            # else:
            #     print( f'Время завершения соединения:'
            #          , time.strftime('%d.%m.%Y г. %H:%M:%S', time.localtime(s.finTime)))
            #     print(f'Общее время соединения: {s.totalTime} сек')
            # if s.is_rdp and s.prob > 50:
            #     print(Back.GREEN + Fore.BLACK + f'Найдена RDP-сессия с вероятностью {s.prob}%!!!')
            cnt += 1
        print(f'{line}{line}\n')