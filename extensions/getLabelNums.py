#kmadetect
#By Nguyen Trung
import json
import os
import collections


from collections import Counter
PATH = r'/home/nguyentrung/NCKH_19-20/AndroZoo/names/proposed.json'

labels = []
frequency = []
standarLabels = ['']


def getLabels():
    frequencyLabels = collections.OrderedDict()
    labesNum = collections.OrderedDict()


    with open(PATH, 'r') as fileLabels:
        data = json.load(fileLabels)
    for name in data:
        label = data[name]
        if label == 'fakeinstb':
            label = 'fakeinst'
        labels.append(label)


    frequencyLabels['Labels'] = Counter(labels).most_common()

    labelsNum = 0
    a = collections.OrderedDict()
    for frequency in frequencyLabels['Labels']:

        labelsNum += 1
        lst = list(frequency)

        a[lst[0]] = labelsNum

    with open(str('LabelsNum.json'), 'w') as fp:
        json.dump(a, fp, indent=4)

    with open(str('FrequencyLabels.json'), 'w') as fp:
        json.dump(frequencyLabels['Labels'], fp, indent=4)


if __name__ == '__main__':
    getLabels()