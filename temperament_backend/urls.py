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

    # Задачи
    path("api/categories/all/", views.CategoryListAPI.as_view(), name="category_all"),
    path("api/categories/create/", views.CategoryCreateAPI.as_view(), name="category_create"),
    path("api/categories/<int:pk>/delete/", views.CategoryDeleteAPI.as_view(), name="category_delete"),
    # Дисциплины
    path("api/disciplines/all/", views.DisciplineListAPI.as_view(), name="discipline-all"),
    path("api/disciplines/create/", views.DisciplineCreateAPI.as_view(), name="discipline-create"),
    path("api/disciplines/<int:pk>/delete/", views.DisciplineDeleteAPI.as_view(), name="discipline-delete"),

    # Задачи
    path("api/tasks/all/", views.TaskListAPI.as_view(), name="task_all"),
    path("api/tasks/create/", views.TaskCreateAPI.as_view(), name="task-create"),
    path("api/tasks/<int:pk>/detail/", views.TaskDetailAPI.as_view(), name="task_detail"),
    path("api/tasks/<int:pk>/update/", views.TaskUpdateAPI.as_view(), name="task_update"),
    path("api/tasks/<int:pk>/delete/", views.TaskDeleteAPI.as_view(), name="task_delete"),

    # Забитие контента (Вопросы и Опции)
    path("api/questions/create/", views.QuestionCreateAPI.as_view(), name="question_create"),
    path("api/final-options/create/", views.FinalOptionCreateAPI.as_view(), name='final_option_create'),

    # Попытки
    path("api/submissions/submit/", views.SubmissionSubmitAPI.as_view(), name="submission_submit"),
    path("api/submissions/history/", views.SubmissionHistoryAPI.as_view(), name="submission_history"),


    re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)