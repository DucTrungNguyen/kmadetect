#kmadetect
#By Nguyen Trung

import os
import fnmatch
import json

from detect import Test as test
from tqdm import tqdm

PATH_CONFIG = '../reverse/config.json'
PATH_DATACSV_CLIENT = 'reverse/DataCSV_Client'
PATH_CONFIGCNNs = 'detect/configCNNs.json'
PATH_DATACSV = '../reverse/DataCSV'



def trainModel():
    # doc file configCNNs
    with open(PATH_CONFIGCNNs, "r+") as f:
        dataConfigCNNs = json.load(f)

    BATCH_SIZE = dataConfigCNNs["BATCH_SIZE"]
    IMG_SIZE = dataConfigCNNs["IMG_SIZE"]
    N_CLASSES = dataConfigCNNs["N_CLASSES"]
    LR = dataConfigCNNs["LR"]
    N_EPOCHS = dataConfigCNNs["N_EPOCHS"]

    # doc configRevere
    with open(PATH_CONFIG, "r+") as fp:
        dataConfig = json.load(fp)
    partTrained = dataConfig["partTrained"]

    isTrain = True

    csv_list = list_files(PATH_DATACSV, "*.csv")

    for dataCSV in tqdm(csv_list):
        if isTrain:
            test.train(dataCSV,
                  BATCH_SIZE=BATCH_SIZE,
                  IMG_SIZE=IMG_SIZE,
                  N_CLASSES=N_CLASSES,
                  N_EPOCHS=N_EPOCHS)
            isTrain = False
        else:
            test.tranfer(dataCSV,
                    BATCH_SIZE=BATCH_SIZE,
                    IMG_SIZE=IMG_SIZE,
                    N_CLASSES=N_CLASSES,
                    N_EPOCHS=N_EPOCHS)
        partTrained += 1

    dataConfig["partTrained"] = partTrained
    with open(str(PATH_CONFIG), 'w+') as fp:
        json.dump(dataConfig, fp, indent=4)

    fp.close()

def tranferModel():

    # doc file config
    with open(PATH_CONFIGCNNs, "r+") as f:
        dataConfigCNNs = json.load(f)


    BATCH_SIZE = dataConfigCNNs["BATCH_SIZE"]
    IMG_SIZE = dataConfigCNNs["IMG_SIZE"]
    N_CLASSES = dataConfigCNNs["N_CLASSES"]
    LR = dataConfigCNNs["LR"]
    N_EPOCHS = dataConfigCNNs["N_EPOCHS"]

    # doc configRevere
    with open(PATH_CONFIG, "r+") as fp:
        dataConfig = json.load(fp)
    partTrained = dataConfig["partTrained"]



    csv_list = list_files(PATH_DATACSV, "*.csv")

    for dataCSV in tqdm(csv_list):
            head, tail = os.path.split(dataCSV)
            part = int(tail[0:1])
            if part > partTrained - 1:
                test.tranfer(dataCSV,
                        BATCH_SIZE=BATCH_SIZE,
                        IMG_SIZE=IMG_SIZE,
                        N_CLASSES=N_CLASSES,
                        N_EPOCHS=N_EPOCHS)
                partTrained += 1

    dataConfig["partTrained"] = partTrained
    with open(str(PATH_CONFIG), 'w+') as fp:
        json.dump(dataConfig, fp, indent=4)

    fp.close()

def detectApk(nameApk):

    pathApkCSV = os.path.join(PATH_DATACSV_CLIENT, nameApk+ '.csv')

    # doc file config
    with open(PATH_CONFIGCNNs, "r+") as f:
        dataConfigCNNs = json.load(f)

    BATCH_SIZE = dataConfigCNNs["BATCH_SIZE"]
    IMG_SIZE = dataConfigCNNs["IMG_SIZE"]
    N_CLASSES = dataConfigCNNs["N_CLASSES"]
    LR = dataConfigCNNs["LR"]
    N_EPOCHS = dataConfigCNNs["N_EPOCHS"]



    predictjson = test.detect(pathApkCSV,
            BATCH_SIZE=BATCH_SIZE,
            IMG_SIZE=IMG_SIZE,
            N_CLASSES=N_CLASSES,
            N_EPOCHS=N_EPOCHS)
    print(predictjson)
    return predictjson

def list_files(directory, string):
    result = []
    for dirpath, dirnames, files in os.walk(directory):
        for file in fnmatch.filter(files, string):
            result.append(os.path.join(dirpath, file))
    return result


if __name__ == '__main__':
    trainModel()
    # detectApk('d80e4f88ed36dde12da1863794ea143bcf53eaae22e511e3eb7402cef5224d4d.csv')
