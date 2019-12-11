#kmadetect
#By Mai Nghia

import numpy as np
import pandas as pd
import random
from tflearn.data_utils import to_categorical
from detect.Data import *


def readFileCsv(path):
    data = pd.read_csv(path, header=None)
    return data

def standardizedData(data, IMG_SIZE, N_CLASSES, rowData):

    data = np.array(data, dtype='float32')
    train_data = data[:, 1:]
    train_label = data[:, 0]
    shuffle_order = list(range(rowData))
    random.shuffle(shuffle_order)
    train_data = np.array(train_data)
    train_label = np.array(train_label)

    train_data = train_data[shuffle_order]
    train_y = train_label[shuffle_order]

    train_data = train_data.reshape(-1, IMG_SIZE, IMG_SIZE, 1)
    train_label = to_categorical(train_y, N_CLASSES)

    return Data(train_data, train_label)

def standardizedDataTest(data, IMG_SIZE, N_CLASSES, rowData):
    dataTest = np.array(data, dtype='float32')
    dataTest = dataTest.reshape(-1, IMG_SIZE, IMG_SIZE, 1)

    return dataTest

def raito(numsRow):
    _train = 0.8
    _val = 0.1
    _test = 0.1
    train = int(round(numsRow * 0.8, 0))
    test = val = int(round(numsRow * 0.9, 0))
    return train, val, test

