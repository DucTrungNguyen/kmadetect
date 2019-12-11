#kmadetect
#By Nguyen Trung
# lấy features từ tập virusshare 24k mẫu để làm dữ liệu train
# sử dụng androguard

import  csv
import hashlib
import collections
import json
import datetime

# from tqdm import tqdm
# from os.path import join as join_dir
# from androguard.core.bytecodes.apk import APK
# from collections import Counter
from standardData import *
from tqdm import tqdm
from os.path import join as join_dir
from features_managment import *# features_managment import *
from mergeCSV import  *
from androguard.core.bytecodes.apk import APK
from collections import Counter

ARRNAME = []
ARRLABELS = []
API_PACKAGES_LIST = []
API_CLASSES_LIST = []
package_index_file = r'info/package_index.txt'
classes_index_file = r'info/class_index.txt'
system_commands_file = r'info/system_commands.txt'
output_folder = 'JsonData/'
labels = 'resources/all.labels'
config_file = 'config.json'
LabelsNum_file = 'resources/LabelsNum.json'
LABELSNUMANDTEXT = collections.OrderedDict()
maxLabelsNum = 0
BASE = os.path.dirname(os.path.abspath(__file__))

global dataConfig

def main():

    # print("Get features VirusShare 24k")
    # parser = argparse.ArgumentParser(
    #     description="Reverse Apk with kmadetect\n\n")
    #
    # #parser.add_argument('-s', '', help='SignleApk True or False', required=True)
    #
    # parser.add_argument('-p', '--path', help='Path folder apk', required=True)  # param Features file
    #
    # args = parser.parse_args()


    getFeatures(source_directory=r'/home/nguyentrung/Data_VirusAndroid/VirusShare-1')
    getFeatures(source_directory=r'/home/nguyentrung/Data_VirusAndroid/VirusShare-2')
    getFeatures(source_directory=r'/home/nguyentrung/Data_VirusAndroid/VirusShare-3')
    getFeatures(source_directory=r'/home/nguyentrung/Data_VirusAndroid/VirusShare-4')
    getFeatures(source_directory=r'/home/nguyentrung/Data_VirusAndroid/VirusShare-5')
    getFeatures(source_directory=r'/home/nguyentrung/Data_VirusAndroid/VirusShare-6')
    getFeatures(source_directory=r'/home/nguyentrung/Data_VirusAndroid/VirusShare-7')
    getFeatures(source_directory=r'/home/nguyentrung/Data_VirusAndroid/VirusShare-8')
    getFeatures(source_directory=r'/home/nguyentrung/Data_VirusAndroid/VirusShare-9')

def getFeatures(source_directory):
    ############################################################
    # Label tong hop
    with open(LabelsNum_file, "r+") as file_LabeslNum:
        LABELSNUMANDTEXT = json.load(file_LabeslNum)

    # doc file config
    with open(config_file, "r+") as f:
        dataConfig = json.load(f)

    maxLabelsNum = dataConfig['maxLabelsNum']
    #lay part Data
    partData = dataConfig['partData']
    time = datetime.datetime.now()
    partDataFile = str(partData) + '_' + str(time).strip() + '.csv'
    csvFile = open(r'DataCSV/'+ partDataFile, 'w+', newline='')
    writer = csv.writer(csvFile, delimiter=',')


    source_directory = str(source_directory)

    #if not os.path.exists(output_folder):
    #    os.makedirs(output_folder)

    # Load Android API packages and classes
    global API_PACKAGES_LIST, API_CLASSES_LIST, API_SYSTEM_COMMANDS

    ############################################################
    # get name and labels
    ARRNAME,  ARRLABELS = load_NameandLabels(labels)

    ############################################################
    # READING PACKAGES, CLASSES AND SYSTEM COMMANDS
    ############################################################
    package_file = load_file(str(package_index_file))
    API_PACKAGES_LIST = [x.strip() for x in package_file]

    class_file = load_file(str(classes_index_file))
    API_CLASSES_LIST = [x.strip() for x in class_file]

    commands_file = load_file(str(system_commands_file))
    API_SYSTEM_COMMANDS = [x.strip() for x in commands_file]
    ############################################################

    ############################################################


    apk_list = list_files(source_directory, '*.apk')

    for analyze_apk in tqdm(apk_list):

        # Getting the name of the folder that contains all apks and folders with apks
        base_folder = source_directory.split("/")[-1]

        apk_filename = join_dir(base_folder, analyze_apk.replace(source_directory, ''))
        apk_filename = apk_filename.replace("//", "/")

        apk_name_no_extensions = "".join(apk_filename.split("/")[-1].split(".")[:-1])

        # export to monggoDB
        #if os.path.isfile(join_dir(output_folder, apk_filename.split("/")[-1].replace('.apk', '-analysis.json'))):
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

        try:
            androguard_apk_object = APK(analyze_apk)
        except Exception:
            print ("ERROR in APK: " + apk_name_no_extensions)
            continue

        static_analysis_dict = collections.OrderedDict()
        # Package name
        static_analysis_dict['Package_name'] = androguard_apk_object.get_package()

        # Permissions
        static_analysis_dict['Permissions'] = androguard_apk_object.get_permissions()


        # Activities
        try:
            list_activities = androguard_apk_object.get_activities()
        except UnicodeEncodeError:
            list_activities = []

        # Main activity
        static_analysis_dict['Main_activity'] = androguard_apk_object.get_main_activity()

        # Receivers
        try:
            list_receivers = androguard_apk_object.get_receivers()
        except UnicodeEncodeError:
            list_receivers = []

        # Services
        try:
            list_services = androguard_apk_object.get_services()
        except UnicodeEncodeError:
            list_services = []

        # API calls and Strings
        list_smali_api_calls, list_smali_strings = read_strings_and_apicalls(analyze_apk, API_PACKAGES_LIST,
                                                                             API_CLASSES_LIST)
        for api_call in list_smali_api_calls.keys():
            new_api_call = '.'.join(api_call.split(".")[:-1])
            if new_api_call in list_smali_api_calls.keys():
                list_smali_api_calls[new_api_call] = list_smali_api_calls[new_api_call] + list_smali_api_calls[api_call]
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



        row = standardData(pre_static_dict, static_analysis_dict)
        if md5 in ARRNAME:
            index = -1
            if md5 in ARRNAME:
                index = ARRNAME.index(md5)
            if sha256 in ARRNAME:
                index = ARRNAME.index(sha256)

            if index != -1:
                label = ARRLABELS[index]
                try:
                    if label not in LABELSNUMANDTEXT:
                        if 'SINGLETON' in label:
                            continue
                        continue
                        # maxLabelsNum += 1
                        # temp = collections.OrderedDict()
                        # temp[label] = maxLabelsNum
                        # LABELSNUMANDTEXT[label] = maxLabelsNum

                except:
                    continue
                labelNum = [LABELSNUMANDTEXT[label]]
                labelNum.extend(row)
                writer.writerow(labelNum)

        # apk_total_analysis = collections.OrderedDict([("Pre_static_analysis", pre_static_dict),
        #                                   ("Static_analysis", static_analysis_dict)])
        #
        # save_as_json(apk_total_analysis, output_name=join_dir(output_folder, apk_name_no_extensions +
        #                                                       "-analysis.json"))

    #save labelsnum neu co them nhan moo
    with open(str(LabelsNum_file), 'w+') as fp:
        json.dump(LABELSNUMANDTEXT, fp, indent=4)
    fp.close()





    # Save data config
    partData += 1
    dataConfig['partData'] = partData
    dataConfig['maxLabelsNum'] = maxLabelsNum

    with open(str(config_file), 'w+') as fp:
        json.dump(dataConfig, fp, indent=4)

    fp.close()

    csvFile.close()

if __name__ == '__main__':
    main()