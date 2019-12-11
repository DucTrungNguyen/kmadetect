"""
WSGI config for kmadetect project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/howto/deployment/wsgi/
"""


import sys, os
import site

from django.core.wsgi import get_wsgi_application
# INTERP = "/home/ubuntu/local/bin/python"
# INTERP is present twice so that the new python interpreter
# knows the actual executable path
# if sys.executable != INTERP: os.execl(INTERP, INTERP, *sys.argv)

# cwd = os.getcwd()
# sys.path.append(cwd)
# sys.path.append(cwd + '/kmadetect')  # You must add your project here
#
# # sys.path.insert(0, cwd + '/my_project/bin')
# sys.path.insert(0, cwd + '/kmadetect/venv/lib/python3.6/site-packages')
#
# # Activate your virtual env
# # activate_env=os.path.expanduser("~/.virtualenvs/myprojectenv/bin/activate_this.py")
# # activate_env=os.path.expanduser("~/kmadetect/kmadetect/venv/bin/activate")
# activate_env=os.path.expanduser("/home/nguyentrung/NCKH_19-20/kma-det/venv/bin/activate")
# exec(open(activate_env).read())
# # exec(activate_env, dict(__file__=activate_env))



os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'kmadetect.settings')

application = get_wsgi_application()
