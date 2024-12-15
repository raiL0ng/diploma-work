import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
from session_creation import Session_list
from chart_creation import Object_list
from common_methods import read_from_file, write_to_file, Packet_list
from sniffer import Sniffer
from traffic_analysis import TrafficAnalysis


# Выбор опции (меню)
def choose_mode():
  global Packet_list, Object_list, Session_list
  while True:
    print('1. Перехват трафика')
    print('2. Запись данных в файл')
    print('3. Считывание с файла данных для анализа трафика')
    print('4. Анализ трафика')
    print('5. Выход')
    bl = input()
    if bl == '1':
      Packet_list.clear()
      Object_list.clear()
      Session_list.clear()
      Sniffer().traffic_interception()
    elif bl == '2':
      write_to_file()
    elif bl == '3':
      Packet_list.clear()
      Object_list.clear()
      Session_list.clear()
      read_from_file()
      print(f'\nДанные собраны. Перехвачено: {len(Packet_list)} пакетов(-а)\n')
    elif bl == '4':
      TrafficAnalysis().start_to_analyse()
    elif bl == '5':
      return


if __name__ == '__main__':
  print('\nЗапуск программы....\n')
  choose_mode()