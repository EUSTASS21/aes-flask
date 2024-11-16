from django.contrib import admin
from django.urls import path
from securedrive import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('signup/', views.signup, name='signup'),
    path('home/', views.index, name='index'),
    path('upload/', views.upload, name='upload'),
    path('download/', views.list_files, name='download'),
    path('download_file/<file_id>/', views.download_file, name='download_file'),
]