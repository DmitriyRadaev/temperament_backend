from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.static import serve
from django.conf import settings
from main import views


urlpatterns = [
    path('admin/', admin.site.urls),
    #Авторизация
    path("api/auth/login/", views.loginView, name="login"),
    path("api/auth/logout/", views.logoutView, name="logout"),
    path("api/auth/refresh_token/", views.CookieTokenRefreshView.as_view(), name="token_refresh"),

    # Регистрация
    path("api/auth/register/student/", views.StudentRegisterView.as_view(), name="student_register"),
    path("api/auth/register/admin/", views.AdminRegisterView.as_view(), name="admin_register"),

    re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)