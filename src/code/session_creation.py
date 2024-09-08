import time
from variable_definition import Packet_list, Session_list, Labels_list, Object_list, line
from colorama import init, Back, Fore
from math import sqrt


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


class SessionInitialization:

    def __init__(self) -> None:
        pass

    # Обработка значений списка Session_list
    def clear_end_sessions(self):
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