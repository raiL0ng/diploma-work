import time
import numpy as np
from colorama import init, Back, Fore
from math import sqrt
from keras.models import load_model

# Глобальный список сессий
Session_list = []

init(autoreset=True)

# Класс, содержащий информацию о каждой активной сессии
class Session:

    def __init__(self, strt_time, ips, ports) -> None:
            self.strt_time = strt_time
            self.ips = ips
            self.ports = ports
            self.stateActive = True
            self.forceFin = False
            self.isRDP = False

            self.prevTimePkt = None
            self.lastTimePkt = None
            self.totalTime = None
            self.intervalsList = []

            # Для подсчета количества/размера пакетов
            self.cntPktSrcIP1 = self.cntPktDestIP1 = 0
            self.pktSizeDestIP1 = []
            self.pktSizeDestIP2 = []

            # Для подсчета флагов PSH
            self.cntPSHDestIP1 = self.cntPSHDestIP2 = 0

            # Для подсчета флагов ACK
            self.cntACKDestIP1 = self.cntACKDestIP2 = self.cntACKSrcIP1 = 0

            # Для подсчета всего TCP-трафика
            self.cntPktTCPDestIP1 = self.cntPktTCPDestIP2 = 0

            # Для подсчета флагов SYN, FIN, RST
            self.cntSYNSrc = self.cntSYNDest = self.cntFINSrc = 0
            self.cntFINDest = self.cntRSTSrc = self.cntRSTDest = 0

            self.cntTr = self.CNT = self.cntPkt = self.cntPktUDP =  0
            self.winSizeList = []
            self.rdpProb = []

    # Сбор данных о сессии, извлекаемых из пакетов
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
                if pkt.fl_syn == '1':
                    self.cntSYNDest += 1
                if pkt.fl_fin == '1':
                    self.cntFINDest += 1
                if pkt.fl_rst == '1':
                    self.cntRSTDest += 1
                self.cntPktTCPDestIP1 += 1
            if pkt.ip_dest == self.ips[1]:
                if pkt.fl_psh == '1':
                    self.cntPSHDestIP2 += 1
                if pkt.fl_ack == '1':
                    self.cntACKDestIP2 += 1
                    self.cntACKSrcIP1 += 1
                if pkt.fl_syn == '1':
                    self.cntSYNSrc += 1
                if pkt.fl_fin == '1':
                    self.cntFINSrc += 1
                if pkt.fl_rst == '1':
                    self.cntRSTSrc += 1
                self.cntPktTCPDestIP2 += 1
            # TODO надо подумать что делать с этими флагами соединения
            if pkt.fl_fin == '1' or pkt.fl_rst == '1':
                self.forceFin = True
            # Подсчет размеров окна
            self.winSizeList.append(pkt.win_size)
        else:
            self.cntPktUDP += 1
        self.lastTimePkt = pkt.timePacket
        self.cntPkt += 1
        self.CNT += 1

    # Обнуление накопленных данных после предсказания
    def clean_all_parameters(self):
        # Очистка временных данных
        self.prevTimePkt = None
        self.intervalsList.clear()
        
        # Сброс счетчиков и списков
        self.cntPktSrcIP1 = self.cntPktDestIP1 = 0
        self.pktSizeDestIP1.clear()
        self.pktSizeDestIP2.clear()
        self.cntPSHDestIP1 = self.cntPSHDestIP2 = 0
        self.cntACKDestIP1 = self.cntACKDestIP2 = self.cntACKSrcIP1 = 0
        self.cntPktTCPDestIP1 = self.cntPktTCPDestIP2 = 0
        self.cntSYNSrc = self.cntSYNDest = self.cntFINSrc = 0
        self.cntFINDest = self.cntRSTSrc = self.cntRSTDest = 0
        
        self.winSizeList.clear()
        self.cntPktUDP = self.cntPkt = 0

    # Получение входного вектора x_t
    def get_result(self):
        
        def ratio_calc(num, denom):
            if denom == 0:
                return 0
            return num / denom

        result = []
        if not self.stateActive:
            return None
        l = len(self.intervalsList)
        self.totalTime = round(self.lastTimePkt - self.strt_time, 2)
        if self.stateActive and self.cntPkt < 2:
            self.stateActive = False
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
        result.append(ratio_calc(self.cntPktDestIP1, self.cntPktSrcIP1))
        result.append(ratio_calc(self.cntPktSrcIP1, self.cntPktDestIP1))
        # Вычисление отношения объема UDP-трафика и TCP-трафика
        result.append(ratio_calc(self.cntPktUDP, self.cntPkt - self.cntPktUDP))
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
        result.append(ratio_calc(self.cntPSHDestIP1, self.cntPktTCPDestIP1))
        result.append(ratio_calc(self.cntPSHDestIP2, self.cntPktTCPDestIP2))
        # Вычисление частоты флагов ACK для IP1 и IP2
        result.append(ratio_calc(self.cntACKDestIP1, self.cntPktTCPDestIP1))
        result.append(ratio_calc(self.cntACKDestIP2, self.cntPktTCPDestIP2))
        # Вычисление отношения ACK/PSH для IP1 и IP2
        result.append(ratio_calc(self.cntPSHDestIP1, self.cntACKDestIP1))
        result.append(ratio_calc(self.cntPSHDestIP2, self.cntACKDestIP2))
        # Вычисление разности числа исходящих и входящих ACK-флагов IP1
        result.append(abs(self.cntACKDestIP1 - self.cntACKSrcIP1))
        # Вычисление отношения количества флагов SYN, FIN, RST
        result.append(ratio_calc( self.cntSYNSrc + 1
                                , self.cntFINSrc + self.cntRSTSrc + 1 ))
        result.append(ratio_calc( self.cntSYNDest + 1
                                , self.cntFINDest + self.cntRSTDest + 1 ))
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
        result.append(self.cntPkt)
        self.clean_all_parameters()
        return result

    # Оценка результата предсказания
    def rdp_prob_check(self, val0, val1):
        if val0 > 0.5 and val1 < 0.5:
            self.rdpProb.append((True, [val0, val1]))
            self.cntTr += 1
        else:
            self.rdpProb.append((False, [val0, val1]))
        l = len(self.rdpProb)
        if not self.isRDP and l >= 2:
            self.isRDP = self.cntTr > l - self.cntTr


# Обработка получаемых пакетов
class SessionInitialization:

    def __init__(self, fl_find_rdp=False, fl_train=True) -> None:
        self.cur_ports = set()
        self.curTime = None
        self.model = None
        self.train_mode = fl_train
        self.findRDP = fl_find_rdp
        self.x_input = []
        self.cntPeriods = 0
        self.line = '-------------------------'

    # Инициализация времени
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
    
    # Выполнение предсказания по каждой активной сессии
    def get_prediction(self, indexes):
        pred = self.model.predict(self.x_input)
        j = 0
        for i in indexes:
            Session_list[i].rdp_prob_check(pred[0, j, 0], pred[0, j, 1])
            j += 1

    # Обработка режимов работы с моделью
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
            self.get_prediction(ids)
        # Режим обучения
        elif self.train_mode:
            for s in Session_list:
                vec = s.get_result()
                if vec is not None:
                    self.x_input.append(((s.ips, s.ports), vec))
            self.write_data_to_file()
        else:
            for s in Session_list:
                vec = s.get_result()

    # Классификация пакетов по сессиям
    def find_session_location(self, pkt) -> bool:
        global Session_list
        isNewSession = True
        if pkt.timePacket > self.curTime:
            self.packet_preparation()
            self.curTime += 15
        for s in Session_list:
            if s.stateActive and pkt.ip_src in s.ips and pkt.ip_dest in s.ips:
                if (s.ports[1] is None and ( pkt.port_src == s.ports[0] or \
                                             pkt.port_dest == s.ports[0]) ) or \
                   (pkt.port_src in s.ports and pkt.port_dest in s.ports):
                    isNewSession = False
                    s.update_data(pkt)
                    return s.isRDP
                elif s.ports[1] is not None:
                    if (pkt.port_dest in s.ports and pkt.port_src not in s.ports):
                        isNewSession = False
                        s.ports = (s.ports[1], None)
                        self.cur_ports.add(pkt.port_dest)
                        s.update_data(pkt)
                        return s.isRDP
                    elif (pkt.port_src in s.ports and pkt.port_dest not in s.ports):
                        isNewSession = False
                        s.ports = (s.ports[0], None)
                        self.cur_ports.add(pkt.port_src)
                        s.update_data(pkt)
                        return s.isRDP
        if isNewSession:
            if pkt.protoType == 'TCP' and pkt.fl_syn == '1' and pkt.fl_ack == '0':
                self.cur_ports.add(pkt.port_dest)
                Session_list.append(Session( pkt.timePacket
                                           , (pkt.ip_src, pkt.ip_dest)
                                           , (pkt.port_dest, None)))
            else:
                Session_list.append(Session( pkt.timePacket
                                           , (pkt.ip_src, pkt.ip_dest)
                                           , (pkt.port_src, pkt.port_dest)))
            Session_list[-1].update_data(pkt)
        return False

    # Вывод информации о перехваченных пакетах
    def print_packet_information(self, pkt, pred_res):
        if self.findRDP and not pred_res:
            return
        packet_info = [
            f'{self.line}Пакет No{pkt.numPacket}{self.line}',
            f'Время перехвата: {time.strftime("%m:%d:%Y %H:%M:%S", time.localtime(pkt.timePacket))}',
            f'Протокол: {pkt.protoType}',
            f'MAC-адрес отправителя: {pkt.mac_src}',
            f'MAC-адрес получателя: {pkt.mac_dest}',
            f'Отправитель: {pkt.ip_src}:{pkt.port_src}',
            f'Получатель: {pkt.ip_dest}:{pkt.port_dest}'
        ]
        if pkt.protoType == 'TCP':
            tcp_flags = f'SYN:{pkt.fl_syn}; ACK:{pkt.fl_ack}; PSH:{pkt.fl_psh}; RST:{pkt.fl_rst}; FIN:{pkt.fl_fin}'
            packet_info.append(f'Порядковый номер: {pkt.seq}; Номер подтверждения: {pkt.ack}')
            packet_info.append(tcp_flags)
        print("\n".join(packet_info))
        if self.findRDP and pred_res:
            print(f'{self.line} Обнаружена RDP-сессия! {self.line}')

    # Обработка значений списка Session_list
    def clear_unwanted_sessions(self):
        global Session_list
        Session_list = [
            session for session in Session_list
            if session.CNT >= 20 and session.totalTime >= 10
        ]

    # Вывод информации о сессиях
    def print_inf_about_sessions(self):
        print(f'\nБыло перехвачено {len(Session_list)} сессии(-й)')
        for cnt, s in enumerate(Session_list, start=1):
            session_info = [
                f'\nИнформация о сессии #{cnt}:',
                f'IP-адреса: {s.ips}',
                f'Порт подключения: {s.ports[0]}' if s.ports[1] is None else f'Порты подключения: {s.ports}',
                f'Время перехвата первого пакета: {time.strftime("%d.%m.%Y г. %H:%M:%S", time.localtime(s.strt_time))}',
                f'Количество перехваченных пакетов: {s.CNT}',
                f'Общее время перехвата: {s.totalTime}'
            ]
            if s.isRDP:
                session_info.append(Back.GREEN + Fore.BLACK + 'Найдена RDP-сессия!!!')
            print("\n".join(session_info))
        print(f'{self.line}{self.line}\n')