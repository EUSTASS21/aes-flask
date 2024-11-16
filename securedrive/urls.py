from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('upload/', views.upload_file, name='upload_file'),
    path('download/', views.list_files, name='list_files'),
    path('download_file/<str:file_id>/', views.download_file, name='download_file'),
]
