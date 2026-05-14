from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, re_path
from django.views.static import serve
from django.conf import settings
from drf_spectacular.views import SpectacularSwaggerView, SpectacularAPIView

from main import views

urlpatterns = [
    path('admin/', admin.site.urls),

    # Авторизация
    path("api/auth/login/",         views.loginView,                        name="login"),
    path("api/auth/logout/",        views.logoutView,                       name="logout"),
    path("api/auth/refresh_token/", views.CookieTokenRefreshView.as_view(), name="token_refresh"),

    # Регистрация
    path("api/auth/register/student/", views.StudentRegisterView.as_view(), name="student_register"),
    path("api/auth/register/admin/",   views.AdminRegisterView.as_view(),   name="admin_register"),

    # TaskCategory
    path("api/task-category/all/",             views.TaskCategoryListView.as_view()),
    path("api/task-category/create/",          views.TaskCategoryCreateView.as_view()),
    path("api/task-category/<int:pk>/",        views.TaskCategoryRetrieveView.as_view()),
    path("api/task-category/<int:pk>/update/", views.TaskCategoryUpdateView.as_view()),
    path("api/task-category/<int:pk>/delete/", views.TaskCategoryDestroyView.as_view()),

    # СategoryConfig
    path("api/category-config/all/",             views.CategoryConfigListView.as_view()),
    path("api/category-config/create/",          views.CategoryConfigCreateView.as_view()),
    path("api/category-config/<int:pk>/",        views.CategoryConfigRetrieveView.as_view()),
    path("api/category-config/<int:pk>/update/", views.CategoryConfigUpdateView.as_view()),
    path("api/category-config/<int:pk>/delete/", views.CategoryConfigDestroyView.as_view()),

    # TaskComplexity
    path("api/complexity/all/",             views.ComplexityListView.as_view()),
    path("api/complexity/create/",          views.ComplexityCreateView.as_view()),
    path("api/complexity/<int:pk>/",        views.ComplexityRetrieveView.as_view()),
    path("api/complexity/<int:pk>/update/", views.ComplexityUpdateView.as_view()),
    path("api/complexity/<int:pk>/delete/", views.ComplexityDestroyView.as_view()),

    # ColorsMarkup
    path("api/colors/all/",             views.ColorsMarkupListView.as_view()),
    path("api/colors/create/",          views.ColorsMarkupCreateView.as_view()),
    path("api/colors/<int:pk>/",        views.ColorsMarkupRetrieveView.as_view()),
    path("api/colors/<int:pk>/update/", views.ColorsMarkupUpdateView.as_view()),
    path("api/colors/<int:pk>/delete/", views.ColorsMarkupDestroyView.as_view()),

    # CategoryMarkup
    path("api/markup/all/",             views.CategoryMarkupListView.as_view()),
    path("api/markup/create/",          views.CategoryMarkupCreateView.as_view()),
    path("api/markup/<int:pk>/",        views.CategoryMarkupRetrieveView.as_view()),
    path("api/markup/<int:pk>/update/", views.CategoryMarkupUpdateView.as_view()),
    path("api/markup/<int:pk>/delete/", views.CategoryMarkupDestroyView.as_view()),

    # MarkupOption
    path("api/markup-option/all/",             views.MarkupOptionListView.as_view()),
    path("api/markup-option/create/",          views.MarkupOptionCreateView.as_view()),
    path("api/markup-option/<int:pk>/",        views.MarkupOptionRetrieveView.as_view()),
    path("api/markup-option/<int:pk>/update/", views.MarkupOptionUpdateView.as_view()),
    path("api/markup-option/<int:pk>/delete/", views.MarkupOptionDestroyView.as_view()),

    # Task
    path("api/task/all/",             views.TaskListView.as_view()),
    path("api/task/create/",          views.TaskCreateView.as_view()),
    path("api/task/<int:pk>/",        views.TaskRetrieveView.as_view()),
    path("api/task/<int:pk>/update/", views.TaskUpdateView.as_view()),
    path("api/task/<int:pk>/delete/", views.TaskDestroyView.as_view()),

    # TaskQuestion
    path("api/question/all/",             views.QuestionListView.as_view()),
    path("api/question/create/",          views.QuestionCreateView.as_view()),
    path("api/question/<int:pk>/",        views.QuestionRetrieveView.as_view()),
    path("api/question/<int:pk>/update/", views.QuestionUpdateView.as_view()),
    path("api/question/<int:pk>/delete/", views.QuestionDestroyView.as_view()),

    # TaskAnswer
    path("api/answer/all/",             views.AnswerListView.as_view()),
    path("api/answer/create/",          views.AnswerCreateView.as_view()),
    path("api/answer/<int:pk>/",        views.AnswerRetrieveView.as_view()),
    path("api/answer/<int:pk>/update/", views.AnswerUpdateView.as_view()),
    path("api/answer/<int:pk>/delete/", views.AnswerDestroyView.as_view()),

    # Submission
    path("api/submission/all/",             views.SubmissionListView.as_view()),
    path("api/submission/create/",          views.SubmissionCreateView.as_view()),
    path("api/submission/<int:pk>/",        views.SubmissionRetrieveView.as_view()),
    path("api/submission/<int:pk>/update/", views.SubmissionUpdateView.as_view()),
    path("api/submission/<int:pk>/delete/", views.SubmissionDestroyView.as_view()),

    # Студент: Обучение
    path("api/tasks/education/random/",      views.EducationTasksAPI.as_view()),
    path("api/submissions/education/check/", views.EducationSubmitAPI.as_view()),

    # Студент: Профиль
    path("api/profile/", views.UserProfileView.as_view(), name="user_profile"),

    # Студент: Контроль
    path("api/tasks/control/random/",       views.ControlTaskAPI.as_view()),
    path("api/submissions/control/submit/", views.ControlSubmitAPI.as_view()),
    path("api/submissions/<int:pk>/",       views.StudentSubmissionDetailAPI.as_view()),

    # Отчеты
    path("api/admin/submissions/all/",      views.AdminAllSubmissionsAPI.as_view()),
    path("api/admin/submissions/<int:pk>/", views.AdminSubmissionDetailAPI.as_view()),

    # Банк заданий
    path("api/task-bank/",             views.TaskBankListView.as_view()),
    path("api/task-bank/create/",      views.TaskBankCreateView.as_view()),
    path("api/task-bank/<int:pk>/",    views.TaskBankDetailView.as_view()),

    # Конфиг формы создания задачи
    path("api/category-config/form/",  views.CategoryConfigFormView.as_view()),

    # Swagger
    path('api/schema/',            SpectacularAPIView.as_view(),                         name='schema'),
    path('api/schema/swagger-ui/', SpectacularSwaggerView.as_view(url_name='schema'),    name='swagger-ui'),

    re_path(r'^media/(?P<path>.*)$',  serve, {'document_root': settings.MEDIA_ROOT}),
    re_path(r'^static/(?P<path>.*)$', serve, {'document_root': settings.STATIC_ROOT}),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)