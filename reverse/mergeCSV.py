#kmadetect
#By Nguyen Trung

import os
import csv
import json
import datetime

from tqdm import tqdm

config_file = 'config.json'
DataCSVClient = 'reverse/DataCSV_Client/'

def mergeCSV():
    with open(config_file, 'w+') as file:
        dataConfig = json.load(file)

    merge = dataConfig['mergeCSV']
    partData = dataConfig['partData']
    csv_list = list_files(DataCSVClient, '*.csv')

    if merge < len(csv_list):
        time = datetime.datetime.now()
        partDataFile = str(partData) + '_' + str(time).strip() + '.csv'
        csvFile = open(r'reverse/DataCSV/' + partDataFile, 'w+', newline='')
        writer = csvFile.writer(csvFile, delimiter=',')
        for csvFileClient in tqdm(csv_list):
            reader = csv.reader(csvFileClient, delimiter=",")
            writer.writerow(reader[0])

    # luu part data
    partData += 1
    dataConfig['partData'] = partData
    with open(str(config_file), 'w+') as fp:
        json.dump(dataConfig, fp, indent=4)
    fp.close()

    csvFile.close()
    delCSVFileClient()



def delCSVFileClient():
    csv_list = list_files(DataCSVClient, '*.csv')
    for csv in tqdm(csv_list):
        os.remove(csv)
