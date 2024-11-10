from keras.models import Sequential, load_model
from keras.layers import LSTM, Dense
from keras.preprocessing.sequence import pad_sequences
import numpy as np
import os

class ModelInit:

    def __init__(self) -> None:
        self.model = None
        self.train_mode = True
        self.sizeX = 21
        self.sizeY = 2
        self.x_input = []
        self.y_input = []


    # Определение модели LSTM
    def define_model(self):
        self.model = Sequential()
        # Входной слой LSTM
        self.model.add(LSTM(units=64, return_sequences=True))
        # Полносвязный слой для классификации
        self.model.add(Dense(units=32, activation='relu'))
        # Выходной слой: два нейрона для предсказания классов [1, 0] (RDP) и [0, 1] (не RDP)
        self.model.add(Dense(units=2, activation='softmax'))
        # Компиляция модели
        self.model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
        print('\nМодель LSTM определена успешно')


    # Запись входных векторов в файл
    def write_data_to_file(self, filename='x_input.log'):
        with open(filename, 'a+') as f:
            f.write(f"{self.cntPeriods}-th interval\n")
            for ports, row in self.x_input:
                f.write(f'{ports}:')
                for el in row:
                    f.write(f'{el},')
                f.write('!\n')
    

    # Считывание входных векторов с файла
    def read_data_from_file(self, filename='x_input.log'):
        self.x_input.clear()
        self.y_input.clear()
        cur_xs = []
        cur_ys = []

        with open(filename, 'r') as f:
            data = f.read().splitlines()
            for row in data:
                if '-th' in row:
                    if cur_xs:
                        self.x_input.append(np.array(cur_xs))
                        self.y_input.append(np.array(cur_ys))
                    cur_xs.clear()
                    cur_ys.clear()
                elif ':' in row:
                    if '(3389' in row or '3389)' in row:
                    # if '(3389' in row or '3389)' in row or '(4899' in row or '4899)' in row:
                        cur_ys.append([1, 0])
                    else:
                        cur_ys.append([0, 1])
                    values = row.split(':')[1].split(',')
                    tmp = [float(el) for el in values if el and '!' not in el]
                    cur_xs.append(tmp)
            if cur_xs:
                self.x_input.append(np.array(cur_xs))
                self.y_input.append(np.array(cur_ys))


    def save_vectors(self, filename='vectors.log'):
        n = len(self.x_input)
        num = 1
        with open(filename, 'w') as f:
            for i in range(n):
                m = len(self.x_input[i])
                for j in range(m):
                    xs_data = ','.join(map(str, self.x_input[i][j]))
                    ys_data = ','.join(map(str, self.y_input[i][j]))
                    f.write(f'{num}:{xs_data}---{ys_data}\n')
                    num += 1


    def load_selected_vectors(self, nums, filename='vectors.log'):
        cur_x = []
        cur_y = []
        
        with open(filename, 'r') as f:
            for line in f:
                num = int(line.split(':')[0])
                
                if num in nums:
                    xs_data, ys_data = line.strip().split('---')
                    xs_data = list(map(float, xs_data.split(':')[1].split(',')))
                    ys_data = list(map(float, ys_data.split(',')))
                    cur_x.append(xs_data)
                    cur_y.append(ys_data)
        cur_x = np.array(cur_x).reshape(-1, self.sizeX)  # исходя из размерности данных в x_input
        cur_y = np.array(cur_y).reshape(-1, self.sizeY)   # исходя из размерности данных в y_input
        
        return cur_x, cur_y
    

    # Форматирование данных и обучение модели
    def train_model(self, epochs=50, batch_size=16):
        x_padded = pad_sequences(
            self.x_input,
            maxlen=None,
            dtype='float32',
            padding='post',
            value=0.0
        )
        
        y_padded = pad_sequences(
            self.y_input,
            maxlen=None,
            dtype='int32',
            padding='post',
            value=[0, 1]
        )

        # Проверка формата и формы массива
        print("Форма x_padded:", x_padded.shape)
        print("Форма y_padded:", y_padded.shape)
        # print(x_padded, y_padded)

        self.model.fit(x_padded, y_padded, epochs=epochs, batch_size=batch_size, verbose=1)


    def get_prediction(self, vec):
        prediction = self.model.predict(vec)
        print("Предсказание:", prediction)
        for i in range(prediction.shape[1]):
            if prediction[0, i, 0] > 0.5 and prediction[0, i, 1] < 0.5:
                print('Обнаружена RDP-сессия!!!')
            else:
                print('Данная сессия не является RDP')


    def save_model(self, filename='model.keras'):
        os.makedirs('../model_directory', exist_ok=True)
        file_path = os.path.join('../model_directory', filename)
        self.model.save(file_path)
        print(f"\nМодель успешно сохранена в {file_path}")


    def load_LSTM_model(self, filename='model.keras'):
        try:
            self.model = load_model(f'../model_directory/{filename}')
        except Exception as ex:
            print(ex)
            return False
        else:
            print('\nМодель успешно загружена!')
            return True


def main():
    while True:
        print('\n1. Обучение модели'
              '\n2. Проверка данных на корректность'
              '\n3. Выход')
        bl = input('Выберите опцию: ')
        if bl == '1':
            bl1 = input('Обучить заново (0) Продолжить обучение (1): ')
            if bl1 == '0':
                c = ModelInit()
                c.define_model()
                filename = input('\nНазвание файла, где лежат входные вектора (по умолчанию x_input.log): ')
                if filename != '':
                    c.read_data_from_file(filename)
                else:
                    c.read_data_from_file()
                c.train_model()
                filename = input('\nСохранить модель в файл? (по умолчанию /model_directory/model.keras): ')
                if filename != '':
                    c.save_model(filename)
            elif bl == '1':
                c = ModelInit()
                filename = input('Название файла для модели: ')
                if filename != '':
                    fl = c.load_LSTM_model(filename)
                else:
                    fl =c.load_LSTM_model()
                if not fl:
                    continue
                xs_data = input('\nНазвание файла, где лежат входные вектора (по умолчанию x_input.log): ')
                if xs_data != '':
                    c.read_data_from_file(xs_data)
                else:
                    c.read_data_from_file()
                c.train_model()
                fl = input('\nСохранить модель в файл? (1 - да): ')
                if fl == '1':
                    if filename != '':
                        c.save_model(filename)
                    else:
                        c.save_model()
        elif bl == '2':
            c = ModelInit()
            filename = input('Название файла для модели (по умолчанию model.keras): ')
            if filename != '':
                fl = c.load_LSTM_model(filename)
            else:
                fl = c.load_LSTM_model()
            if not fl:
                continue
            xs_data = input('\nНазвание файла, где лежат входные вектора (по умолчанию x_input.log): ')
            if xs_data != '':
                c.read_data_from_file(xs_data)
            else:
                c.read_data_from_file()
            c.save_vectors()
            nums = list(map(int, input('Введите номера строк: ').split()))
            if nums == '':
                continue
            xs, ys = c.load_selected_vectors(nums)
            print(xs, '\n', ys)
            xs = np.expand_dims(xs, axis=0)
            ys = np.expand_dims(ys, axis=0)
            print('\nИзначальные выходные данные:\n', ys)
            c.get_prediction(xs)
        elif bl == '3':
            break


if __name__ == '__main__':
    main()