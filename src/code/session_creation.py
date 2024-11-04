import time
import numpy as np
from variable_definition import Session_list, line
from colorama import init, Back, Fore
from math import sqrt
from keras.models import load_model


init(autoreset=True)


# Класс, содержащий информацию о каждой активной сессии
class Session:

    def __init__(self, strt_time, ips, ports) -> None:
        self.strt_time = strt_time
        self.ips = ips
        self.stateActive = True
        self.forceFin = False
        self.isRDP = False
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
        self.rdpProb = []
        self.cntTr = 0
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


    def rdp_prob_check(self, val0, val1):
        if val0 > 0.5 and val1 < 0.5:
            self.rdpProb.append(True)
            self.cntTr += 1
        else:
            self.rdpProb.append(False)
        l = len(self.rdpProb)
        if not self.isRDP and l >= 2:
            self.isRDP = self.cntTr > l - self.cntTr


# Обработка получаемых пакетов
class SessionInitialization:


    def __init__(self, fl_find_rdp=False, fl_train=True) -> None:
        # self.strtTime = strt
        self.known_ports = {21, 22, 23, 25, 53, 80, 88, 161, 443, 873}
        self.curTime = None
        self.model = None
        self.train_mode = fl_train
        self.findRDP = fl_find_rdp
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


    # Загрузка модели для выявления RDP сессий
    def load_LSTM_model(self, filename='model.keras'):
        try:
            self.model = load_model(f'../model_directory/{filename}')
        except Exception as ex:
            print(ex)
            print('Модель должна лежать в каталоге model.keras')
            return False
        else:
            print('\nМодель успешно загружена!')
            return True

    
    def get_prediction(self, indexes):
        pred = self.model.predict(self.x_input)
        j = 0
        for i in indexes:
            Session_list[i].rdp_prob_check(pred[0, j, 0], pred[0, j, 1])
            j += 1


    def packet_preparation(self):
        self.x_input = []
        self.cntPeriods += 1
        # Если поставлен флаг для выявления RDP-трафика
        # то происходит работа с нейронной сетью
        if self.findRDP:
            ids = []
            for i in range(len(Session_list)):
                vec = Session_list[i].get_result()
                if vec is not None:
                    ids.append(i)
                    self.x_input.append(vec)
            self.x_input = np.array(self.x_input)
            self.x_input = np.expand_dims(self.x_input, axis=0)
            if len(self.x_input.shape) != 3:
                print(self.x_input)
                return
            self.get_prediction(ids)
        # Режим обучения
        elif self.train_mode:
            for s in Session_list:
                vec = s.get_result()
                if vec is not None:
                    self.x_input.append((s.ports, vec))
                # print(f"ips = {s.ips} ports = {s.ports} vector = {vec}")
            self.write_data_to_file()
        else:
            for s in Session_list:
                vec = s.get_result()

    def find_session_location(self, pkt) -> bool:
        global Session_list
        isNewSession = True
        if pkt.timePacket > self.curTime:
            self.packet_preparation()
            self.curTime += 15
        for s in Session_list:
            if s.stateActive and pkt.ip_src in s.ips and pkt.ip_dest in s.ips:
                if (s.ports[1] is None and (pkt.port_src == s.ports[0] or pkt.port_dest == s.ports[0])) or \
                   (pkt.port_src in s.ports and pkt.port_dest in s.ports):
                    isNewSession = False
                    s.update_data(pkt)
                    return s.isRDP
        if isNewSession:
            if pkt.port_src in self.known_ports:
                Session_list.append(Session(pkt.timePacket, (pkt.ip_src, pkt.ip_dest), (pkt.port_src, None)))
            elif pkt.port_dest in self.known_ports:
                Session_list.append(Session(pkt.timePacket, (pkt.ip_src, pkt.ip_dest), (pkt.port_dest, None)))
            else:
                Session_list.append(Session(pkt.timePacket, (pkt.ip_src, pkt.ip_dest), (pkt.port_src, pkt.port_dest)))
            Session_list[-1].update_data(pkt)
        return False


    # Вывод информации о перехваченных пакетах
    def print_packet_information(self, pkt, pred_res):
        if self.findRDP and not pred_res:
            return
        print( f'{line}Пакет No{pkt.numPacket}{line}\n'
             , 'Время перехвата: '
             , time.strftime( '%m:%d:%Y %H:%M:%S'
                            , time.localtime(pkt.timePacket) ) + '\n'
             , f'Протокол: {pkt.protoType}\n'
             , f'MAC-адрес отправителя: {pkt.mac_src}\n'
             , f'MAC-адрес получателя: {pkt.mac_dest}\n'
             , f'Отправитель: {pkt.ip_src}:{pkt.port_src}\n'
             , f'Получатель: {pkt.ip_dest}:{pkt.port_dest}')
        if pkt.protoType == 'TCP':
            print( f' Порядковый номер: {pkt.seq}; Номер подтверждения: {pkt.ack}\n' +
                f' SYN:{pkt.fl_syn}; ACK:{pkt.fl_ack}; PSH:{pkt.fl_psh}; ' +
                f'RST:{pkt.fl_rst}; FIN:{pkt.fl_fin}\n')
        if self.findRDP and pred_res:
            print(f'{line} Обнаружена RDP-сессия! {line}')
        # print(f'\nВероятность RDP-сессии {mes_prob[1]}%')


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
                   f'IP-адреса: {s.ips}')
            if s.ports[1] is None:
                print(f'Порт подключения: {s.ports[0]}')
            else:
                print(f'Порты подключения: {s.ports}')
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