#kmadetect
#By Mai Nghia

class Data:

    def __init__(self, dataTrain, dataLabel):
        self.dataTrain = dataTrain
        self.dataLabel = dataLabel

    def getDataTrain(self):
        return self.dataTrain

    def getDataLabel(self):
        return self.dataLabel
