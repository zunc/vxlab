__author__ = 'khoai'

import pickle

def dumpData(data, file):
    output = open(file, 'wb')
    pickle.dump(data, output)
    output.close()

def loadData(file):
    pkl_file = open(file, 'rb')
    data = pickle.load(pkl_file)
    pkl_file.close()
    return data