#kmadetect
#By Nguyen Trung
import sys
import argparse
import collections
import hashlib
import json
import csv
import os


from reverse.standardData import *
from tqdm import tqdm
from os.path import join as join_dir
from reverse.features_managment import *
from reverse.mergeCSV import *
from androguard.core.bytecodes.apk import APK
from collections import Counter

#define constant
TEMP = 'templeApks/'
API_PACKAGES_LIST = []
API_CLASSES_LIST = []
package_index_file = 'reverse/info/package_index.txt'
classes_index_file = 'reverse/info/class_index.txt'
system_commands_file = 'reverse/info/system_commands.txt'
output_folder = 'reverse/JsonData/'
labels = '/reverse/resources/all.labels'
config_file = 'config.json'
LabelsNum_file = 'reverse/resources/LabelsNum.json'
DataCSVClient = 'reverse/DataCSV_Client/'
LABELSNUMANDTEXT = collections.OrderedDict()
maxLabelsNum = 0
POSSIBLE_DYNAMIC_FILES_EXTENSIONS = [".csv", ".json", ".txt"]
BASE = os.path.dirname(os.path.abspath(__file__))


def main():
    print("Reverse Apk")
    parser = argparse.ArgumentParser(
        description="Reverse Apk with kmadetect\n\n")

    parser.add_argument('-s', '--signleApk', help='SignleApk True or False', required=True)

    parser.add_argument('-p', '--path', help='Path folder apk',
                        required=True)  # param Features file

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    pathFolder = args.path
    signleApk = args.signleApk

    if signleApk:
        optionReverse(path=pathFolder, signleApk=signleApk)
    else:
        optionReverse(path= pathFolder, signleApk= signleApk)


def optionReverse(path, signleApk):


    if signleApk:
        reverse(path)
    else:
        apk_list = list_files(path, '*.apk')
        for pathAnalyze_apk in tqdm(apk_list):
            reverse(pathAnalyze_apk)

    return 0


def reverse(nameApk):

    # doc file config
    with open(config_file, "r+") as f:
        dataConfig = json.load(f)

    maxLabelsNum = dataConfig['maxLabelsNum']

    # Label tong hop
    # with open(LabelsNum_file, "r+") as file_LabeslNum:
    #     LABELSNUMANDTEXT = json.load(file_LabeslNum)



    # Load Android API packages and classes
    global API_PACKAGES_LIST, API_CLASSES_LIST, API_SYSTEM_COMMANDS


    ############################################################
    # READING PACKAGES, CLASSES AND SYSTEM COMMANDS
    ############################################################
    package_file = load_file(str(package_index_file))
    API_PACKAGES_LIST = [x.strip() for x in package_file]

    class_file = load_file(str(classes_index_file))
    API_CLASSES_LIST = [x.strip() for x in class_file]

    commands_file = load_file(str(system_commands_file))
    API_SYSTEM_COMMANDS = [x.strip() for x in commands_file]
    static_analysis_dict = collections.OrderedDict()
    try:

        analyze_apk = os.path.join(TEMP,nameApk)
        # Getting the name of the folder that contains all apks and folders with apks
        base_folder = TEMP.split("/")[-1]

        apk_filename = join_dir(base_folder, analyze_apk.replace(TEMP, ''))
        apk_filename = apk_filename.replace("//", "/")

        apk_name_no_extensions = "".join(apk_filename.split("/")[-1].split(".")[:-1])

        # export to monggoDB
        # if os.path.isfile(join_dir(output_folder, apk_filename.split("/")[-1].replace('.apk', '-analysis.json'))):
        #    database[apk_filename.replace('.apk', '')] = json.load(
        #        open(join_dir(output_folder, apk_filename.split("/")[-1].
        #                      replace('.apk', '-analysis.json'))))
        #    continue

        pre_static_dict = collections.OrderedDict()

        pre_static_dict['Filename'] = apk_filename

        hasher_md5 = hashlib.md5()
        hasher_sha256 = hashlib.sha256()
        hasher_sha1 = hashlib.sha1()
        with open(analyze_apk, 'rb') as afile:
            buf = afile.read()
            hasher_md5.update(buf)
            hasher_sha256.update(buf)
            hasher_sha1.update(buf)

        md5 = hasher_md5.hexdigest()
        sha256 = hasher_sha256.hexdigest()
        sha1 = hasher_sha1.hexdigest()

        pre_static_dict["md5"] = md5
        pre_static_dict["sha256"] = sha256
        pre_static_dict["sha1"] = sha1

        """
        if label is not None:
            pre_static_dict["Label"] = label
        else:
            pre_static_dict["Label"] = "/".join(apk_filename.split("/")[:-1])
        """
        pre_static_dict["VT_positives"] = None
        apk_Oject = APK(analyze_apk)

        # get package name
        static_analysis_dict['Package_name'] = apk_Oject.get_package()

        # get Permission
        static_analysis_dict['Permissions'] = apk_Oject.get_permissions()

        # Activities
        try:
            list_activities = apk_Oject.get_activities()
        except UnicodeEncodeError:
            list_activities = []

        # get Main ACtivity
        static_analysis_dict['Main_activity'] = apk_Oject.get_main_activity()

        # Receivers
        try:
            list_receivers = apk_Oject.get_receivers()
        except UnicodeEncodeError:
            list_receivers = []

        # Services
        try:
            list_services = apk_Oject.get_services()
        except UnicodeEncodeError:
            list_services = []

        # API calls and Strings
        list_smali_api_calls, list_smali_strings = read_strings_and_apicalls(analyze_apk, API_PACKAGES_LIST,
                                                                             API_CLASSES_LIST)
        for api_call in list_smali_api_calls.keys():
            new_api_call = '.'.join(api_call.split(".")[:-1])
            if new_api_call in list_smali_api_calls.keys():
                list_smali_api_calls[new_api_call] = list_smali_api_calls[new_api_call] + list_smali_api_calls[
                    api_call]
            else:
                list_smali_api_calls[new_api_call] = list_smali_api_calls[api_call]
                del list_smali_api_calls[api_call]
        static_analysis_dict['API_calls'] = list_smali_api_calls
        static_analysis_dict['Strings'] = Counter(filter(None, list_smali_strings))

        # API packages

        API_packages_dict = collections.OrderedDict()
        android_list_packages_lenghts = [len(x.split(".")) for x in API_PACKAGES_LIST]

        list_api_calls_keys = list_smali_api_calls.keys()
        for api_call in list_api_calls_keys:
            score = 0
            package_chosen = None
            for i, package in enumerate(API_PACKAGES_LIST):
                len_package = android_list_packages_lenghts[i]
                if api_call.startswith(package) and len_package > score:
                    score = len_package
                    package_chosen = package
            if package_chosen is not None:
                if not package_chosen in API_packages_dict.keys():
                    API_packages_dict[package_chosen] = list_smali_api_calls[api_call]
                else:
                    API_packages_dict[package_chosen] += list_smali_api_calls[api_call]

        static_analysis_dict['API_packages'] = API_packages_dict

        # Intents
        try:
            static_analysis_dict['Intents'] = intents_analysis(join_dir(analyze_apk.replace('.apk', ''),
                                                                        'AndroidManifest.xml'))
        except:
            static_analysis_dict['Intents'] = {'Failed to extract intents': 0}

        # Intents of activities
        intents_activities = collections.OrderedDict()
        for activity in list_activities:
            intents_activities[activity] = check_for_intents(join_dir(analyze_apk.replace('.apk', ''),
                                                                      'AndroidManifest.xml'),
                                                             activity, 'activity')
        static_analysis_dict['Activities'] = intents_activities

        # Intents of services
        intents_services = collections.OrderedDict()
        for service in list_services:
            intents_services[service] = check_for_intents(join_dir(analyze_apk.replace('.apk', ''),
                                                                   'AndroidManifest.xml'),
                                                          service, 'service')
        static_analysis_dict['Services'] = intents_services

        # Intents of receivers
        intents_receivers = collections.OrderedDict()
        for intent in list_receivers:
            intents_receivers[intent] = check_for_intents(join_dir(analyze_apk.replace('.apk', '/'),
                                                                   'AndroidManifest.xml'),
                                                          intent, 'receiver')
        static_analysis_dict['Receivers'] = intents_receivers
        static_analysis_dict['Receivers'] = intents_receivers

        apk_total_analysis = collections.OrderedDict([("Pre_static_analysis", pre_static_dict),
                                                       ("Static_analysis", static_analysis_dict)])
        #
        # save_as_json(apk_total_analysis, output_name=join_dir(output_folder, apk_name_no_extensions +
        #                                                       "-analysis.json"))

        row = standardData(pre_static_dict, static_analysis_dict)
        csvFileClient = open(DataCSVClient + md5 + '.csv', 'w+', newline='')
        writer = csv.writer(csvFileClient, delimiter=',')
        writer.writerow(row)
        csvFileClient.close()
        delAPk(analyze_apk)
        if checkMerge(DataCSVClient, dataConfig['mergeCSV']):
            mergeCSV()
        return md5, apk_total_analysis


    except Exception as e:
        print('Exception: ', e)
        return 'Error', 'No features'


if __name__ == '__main__':
    reverse('0e6ee4269afc600e91e6b6cb1c8d5f53.apk')