
import os
import json
import fnmatch

PATH_CONFIG = '../reverse/config.json'

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MEDIA_ROOT = os.path.join(BASE_DIR, '../reverse/tempApks')



fnmatch.filter('ads', '.csv')
x = 2