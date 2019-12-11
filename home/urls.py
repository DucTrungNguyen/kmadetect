from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
urlpatterns = [
    path('', views.checkapk, name="index"),
    path('downloadapk', views.pagedownload, name="pagedownload"),
    path('checkapk', views.checkapk, name="checkapk"),
    path('^file$/', views.upload, name='upload'),
   #path('/files', views.resuilt(), name='resuilt')
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)