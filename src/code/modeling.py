from keras.models import Sequential, load_model
from keras.layers import LSTM, Dense
from keras.preprocessing.sequence import pad_sequences
import numpy as np

class ModelInit:

    def __init__(self) -> None:
        self.model = None
        self.train_mode = True
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


    # Запись входных векторов в файл
    def write_data_to_file(self, filename='x_input.log'):
        with open(filename, 'a+') as f:
            f.write(f"{self.cntPeriods}-th\n")
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
                        self.x_input.append(cur_xs)
                        self.y_input.append(cur_ys)
                    cur_xs.clear()
                    cur_ys.clear()
                elif ':' in row:
                    if row.find('3389') != -1:
                        cur_ys.append([1, 0])
                    else:
                        cur_ys.append([0, 1])
                    values = row.split(':')[1].split(',')
                    tmp = [float(el) for el in values if el and '!' not in el]
                    cur_xs.append(tmp)

            if cur_xs:
                self.x_input.append(cur_xs)
                self.y_input.append(cur_ys)


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
        if prediction[0, 0, 0] > 0.5 and prediction[0, 0, 1] < 0.5:
            print('Обнаружена RDP-сессия!!!')
        else:
            print('Данная сессия не является RDP')


    def save_model(self, path='../model_directory/model.h5'):
        self.model.save(path)
        print(f"\nМодель успешно сохранена в {path}")


    def load_LSTM_model(self, path='../model_directory/model.h5'):
        self.model = load_model(path)


def main():
    print('\n1. Обучение модели')
    print('\n2. Проверка данных на корректность')
    bl = input('Выберите опцию: ')
    if bl == '1':
        pass
    elif bl == '2':
        pass

    print('Выберите опцию:')
if __name__ == '__main__':
    c = ModelInit()
    c.read_data_from_file('x_input.log')
    print(len(c.x_input), len(c.y_input))
    c.define_model()
    # c.data_preparation()
    c.train_model(epochs=50, batch_size=50)
    xtmp = np.array([[7.09155798e-01, 1.47045898e+00, 1.48380327e+00, 2.20483541e-02,
    1.37500000e+00, 7.27272749e-01, 0.00000000e+00, 1.38181824e+02,
    7.96250000e+01, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
    0.00000000e+00, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
    0.00000000e+00, 0.00000000e+00]])
    xtmp = xtmp.reshape((1, 1, 18))
    c.get_prediction(xtmp)
    xtmp = np.array([[[2.39968300e-03, 0.00000000e+00, 0.00000000e+00, 2.39968300e-03,
   1.00000000e+00, 1.00000000e+00, 0.00000000e+00, 5.90000000e+02,
   3.29000000e+02, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
   0.00000000e+00, 0.00000000e+00, 0.00000000e+00, 0.00000000e+00,
   0.00000000e+00, 0.00000000e+00]]])
    xtmp = xtmp.reshape((1, 1, 18))
    c.get_prediction(xtmp)
    xtmp = np.array([[[0.012621216063803814,0.10497452924380339,0.02294456593222675,0.00013065338134765625,0.3548387096774194,2.8181818181818183,0.0,114.42857142857143,897.4043778801844,0.10714285714285714,0.9539170506912442,1.0,1.0,0.10714285714285714,0.9539170506912442,560,1002.5263605442177,39.266666666666666]]])
    xtmp.reshape((1, 1, 18))
    c.get_prediction(xtmp)