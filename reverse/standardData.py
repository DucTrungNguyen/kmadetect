#kmadetect
#By Nguyen Trung

import os
import argparse
import json

SUM_ACII = 8128

Permissions = []
APICalls = []
Activity = []
Intent = []
Url = []
Services = []
Service_receiver = []

def standardData(pre_static_dict, static_analysis_dict):

    features = []

    getPermissions(static_analysis_dict['Permissions'], features = features)
    getAPICalls(static_analysis_dict['API_calls'], features = features)
    getStrings(static_analysis_dict['Strings'], features = features)
    getActivities(static_analysis_dict['Main_activity'], features = features)
    # service = static_analysis_dict['Services']
    getServices(static_analysis_dict['Services'], features= features)
    getReceivers(static_analysis_dict['Receivers'], features = features)


    features.extend(Permissions)
    features.extend(APICalls)
    features.extend(Activity)
    features.extend(Intent)
    features.extend(Url)
    features.extend(Services)
    features.extend(Service_receiver)

    if len(features) > 5184:
        temp = features[:5184]
        # features = []
        features = temp

    extendFeatures = ['0'] * 5184

    for i in range(len(features)):
        extendFeatures[i] = convertToNumber(features[i])

    Permissions.clear()
    APICalls.clear()
    Activity.clear()
    Intent.clear()
    Url.clear()
    Services.clear()
    Service_receiver.clear()

    return extendFeatures



def getPermissions(static_analysis_dict, features):

    Permissions.extend(static_analysis_dict)

def getAPICalls(static_analysis_dict, features):

    for api in static_analysis_dict:
        if sumChar(api) > 8128:
            continue
        if "Activity" in api:
            Activity.append(api)
        else:
            if ".Intent." in api:
                Intent.append(api)
            else:
                try:
                    APICalls.append(api)
                except:
                    continue



def getStrings(static_analysis_dict, features):

    for str in static_analysis_dict:
        if sumChar(str) > 8128:
            continue
        if "http://" in str:
            Url.append(str)
        if ".Intent." in str:
            Intent.append(str)


def getIntents(static_analysis_dict, features):

    Intent.extend( static_analysis_dict)


def getActivities(static_analysis_dict, features):
    if static_analysis_dict != None:
        Activity.extend(static_analysis_dict)


def getServices(static_analysis_dict, features):

    for service in static_analysis_dict:
        Services.extend(service)


def getReceivers(static_analysis_dict, features):
    if static_analysis_dict != None:
        Service_receiver.extend(static_analysis_dict)

def sumChar(features):
    sum = 0
    for c in features:
        sum += ord(c)
    return sum


def convertToNumber(line):

    sumChar = 0
    for c in line:
        sumChar += ord(c)
    return str(round((sumChar / SUM_ACII), 6))






