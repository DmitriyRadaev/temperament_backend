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

    path("api/task-category/all/", views.TaskCategoryCRUD.as_view()),
    path("api/task-category/create/", views.TaskCategoryCRUD.as_view()),
    path("api/task-category/<int:pk>/update/", views.TaskCategoryCRUD.as_view()),
    path("api/category-config/create/", views.CategoryConfigCRUD.as_view()),
    path("api/category-config/<int:pk>/update/", views.CategoryConfigCRUD.as_view()),

    # Справочники (Base)
    path("api/complexity/all/", views.ComplexityCRUD.as_view()),
    path("api/complexity/create/", views.ComplexityCRUD.as_view()),
    path("api/colors/all/", views.ColorsMarkupCRUD.as_view()),
    path("api/colors/create/", views.ColorsMarkupCRUD.as_view()),
    path("api/markup/all/", views.CategoryMarkupCRUD.as_view()),
    path("api/markup/create/", views.CategoryMarkupCRUD.as_view()),
    path("api/markup/<int:pk>/update/", views.CategoryMarkupCRUD.as_view()),

    # Задачи и Контент
    path("api/task/all/", views.TaskCRUD.as_view()),
    path("api/task/create/", views.TaskCRUD.as_view()),
    path("api/task/<int:pk>/update/", views.TaskCRUD.as_view()),
    path("api/question/create/", views.QuestionCRUD.as_view()),
    path("api/answer/create/", views.AnswerCRUD.as_view()),

    # Студент: Обучение
    path("api/tasks/education/random/", views.EducationTasksAPI.as_view()),
    path("api/submissions/education/check/", views.EducationSubmitAPI.as_view()),

    # Студент: Контроль
    path("api/tasks/control/random/", views.ControlTaskAPI.as_view()),
    path("api/submissions/control/submit/", views.ControlSubmitAPI.as_view()),

    # Отчеты
    path("api/admin/submissions/all/", views.AdminAllSubmissionsAPI.as_view()),
    path("api/admin/submissions/<int:pk>/", views.AdminSubmissionDetailAPI.as_view()),


    re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)