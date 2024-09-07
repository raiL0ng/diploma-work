import socket, os
from variable_definition import Packet_list, Object_list, Labels_list, Session_list, findRDP
from common_methods import read_from_file, write_to_file, clear_end_sessions, print_inf_about_sessions, get_common_data
from package_parameters import ExploreObject
from sniffer import Sniffer

# Выбор опции (меню)
def choose_mode():
  global Packet_list, Object_list, Labels_list, Session_list, findRDP
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
      Labels_list.clear()
      Session_list.clear()
      findRDP = False
      Sniffer().traffic_interception()
    elif bl == '2':
      write_to_file()
    elif bl == '3':
      Packet_list.clear()
      Object_list.clear()
      Labels_list.clear()
      Session_list.clear()
      read_from_file()
      print(f'\nДанные собраны. Перехвачено: {len(Packet_list)} пакетов(-а)\n')
    elif bl == '4':
      if Packet_list == []:
        print('\nНет данных! Сначала необходимо получить данные!\n')
        continue
      IPList, numPacketsPerSec = get_common_data()
      clear_end_sessions()
      for s in Session_list:
        s.fin_rdp_check()
      print_inf_about_sessions()
      strt = Packet_list[0].timePacket
      fin = Packet_list[-1].timePacket
      strt_time = time.localtime(strt)
      fin_time = time.localtime(fin)
      avgNumPacket = 0
      for el in numPacketsPerSec:
        avgNumPacket += el
      avgNumPacket /= len(numPacketsPerSec)
      avgSizePacket = 0
      for p in Packet_list:
        avgSizePacket += p.packetSize
      avgSizePacket /= len(Packet_list)

      step = get_x_labels(int(fin - strt))
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
      for k in range(len(IPList)):
        Object_list.append(ExploreObject(IPList[k]))
        Object_list[-1].commonPorts = get_common_ports(IPList[k])
      print_list_of_pairs(IPList)
      print(f'\nВыберите цифру (0 - {len(IPList) - 1}) для просмотра IP-адреса:')
      k = input()
      if k == 'q':
        break
      try:
        k = int(k)
      except:
        print('\nНекорректный ввод!\n')
        continue
      else:
        if 0 <= k and k < len(IPList):
          port = None
          print('Список портов которые учавствовали в соединении с данным IP-адресом')
          print_list_of_pairs(Object_list[k].commonPorts, True)
          t = len(Object_list[k].commonPorts)
          print(f'\nВыберите цифру (0 - {t}) для выбора порта:')
          k1 = input()
          if k1 == 'q':
            break
          try:
            k1 = int(k1)
          except:
            print('Некорректный ввод!\n')
            continue
          else:
            if 0 <= k1 and k1 <= t:
              if k1 != 0:
                port = Object_list[k].commonPorts[k1 - 1]
              choose_options(k, strt, fin, step, port)
            else:
              print(f'Введите число в пределах 0 - {t - 1}')
        else:
          print(f'Введите число в пределах 0 - {len(IPList) - 1}')
    elif bl == '5':
      return


if __name__ == '__main__':
  print('\nЗапуск программы....\n')
  choose_mode()