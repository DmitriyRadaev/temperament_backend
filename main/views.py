# views.py
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, permissions, response, decorators, status, generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt import tokens, views as jwt_views, serializers as jwt_serializers, \
    exceptions as jwt_exceptions
from django.contrib.auth import authenticate
from django.conf import settings
from django.middleware import csrf
from rest_framework import exceptions as rest_exceptions

from .models import *
from .permissions import IsSuperAdmin, IsAdminOrSuperAdmin
from .serializers import *

Account = get_user_model()



def custom_exception_handler(exc, context):
    from rest_framework.views import exception_handler
    drf_response = exception_handler(exc, context)

    if drf_response is None:
        return None

    data = drf_response.data
    if isinstance(data, dict):
        message = data.get("detail") or next(iter(data.values()), "Ошибка")
        if isinstance(message, list):
            message = message[0]
        message = str(message)
    elif isinstance(data, list):
        message = str(data[0]) if data else "Ошибка"
    else:
        message = str(data)

    drf_response.data = {"ok": False, "error": message}
    return drf_response


# ОБЁРТКИ ОТВЕТОВ

def ok(data=None, status_code=status.HTTP_200_OK):
    return Response({"ok": True, "data": data}, status=status_code)

def created(data=None):
    return ok(data, status_code=status.HTTP_201_CREATED)

def err(message: str, details=None, status_code=status.HTTP_400_BAD_REQUEST):
    body = {"ok": False, "error": message}
    if details is not None and settings.DEBUG:
        body["details"] = details
    return Response(body, status=status_code)

def _serializer_hint(errors: dict) -> str:
    hints = []
    for field, messages in errors.items():
        text = "; ".join(str(m) for m in messages) if isinstance(messages, list) else str(messages)
        hints.append(text if field == "non_field_errors" else f"{field}: {text}")
    return " | ".join(hints)


# AUTH

def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {"refresh_token": str(refresh), "access_token": str(refresh.access_token)}


@decorators.api_view(["POST"])
@decorators.permission_classes([])
def loginView(request):
    email = request.data.get("email")
    password = request.data.get("password")
    if not email or not password:
        return err("Email и пароль обязательны", status_code=status.HTTP_400_BAD_REQUEST)

    user = authenticate(email=email, password=password)
    if not user:
        return err("Неверный email или пароль", status_code=status.HTTP_401_UNAUTHORIZED)

    tokens_dict = get_user_tokens(user)
    res = Response({"ok": True, "data": {"detail": "Вход выполнен успешно"}})
    res.set_cookie(key=settings.SIMPLE_JWT['AUTH_COOKIE'], value=tokens_dict["access_token"],
                   expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                   secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                   httponly=settings.SIMPLE_JWT.get('AUTH_COOKIE_HTTP_ONLY', True),
                   samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'))
    res.set_cookie(key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'], value=tokens_dict["refresh_token"],
                   expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                   secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                   httponly=settings.SIMPLE_JWT.get('AUTH_COOKIE_HTTP_ONLY', True),
                   samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'))
    res.set_cookie(key="user_role", value="admin" if user.is_staff else "student",
                   max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                   secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                   httponly=True, samesite='Lax')
    res["X-CSRFToken"] = csrf.get_token(request)
    return res


@csrf_exempt
@decorators.api_view(["POST"])
@decorators.permission_classes([permissions.AllowAny])
def logoutView(request):
    try:
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        if refresh_token:
            tokens.RefreshToken(refresh_token).blacklist()
    except Exception:
        pass

    res = Response({"ok": True, "data": {"detail": "Выход выполнен успешно"}}, status=status.HTTP_200_OK)
    res.delete_cookie(key=settings.SIMPLE_JWT['AUTH_COOKIE'], path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'), samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'))
    res.delete_cookie(key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'], path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'), samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'))
    res.delete_cookie(key="user_role", path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'), samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'))
    res.delete_cookie(key="is_staff", path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'), samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'))
    res.delete_cookie(key=settings.CSRF_COOKIE_NAME, path='/', samesite=settings.CSRF_COOKIE_SAMESITE)
    res.delete_cookie(key="X-CSRFToken", path='/', samesite=settings.CSRF_COOKIE_SAMESITE)
    return res


class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        if attrs['refresh']:
            return super().validate(attrs)
        raise jwt_exceptions.InvalidToken("No valid refresh token in cookie")


class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response_obj, *args, **kwargs):
        if response_obj.data.get("access"):
            response_obj.set_cookie(key=settings.SIMPLE_JWT['AUTH_COOKIE'], value=response_obj.data['access'],
                                    expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                                    secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                                    httponly=True, samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'))
            del response_obj.data["access"]
        if response_obj.data.get("refresh"):
            response_obj.set_cookie(key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'], value=response_obj.data['refresh'],
                                    expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                                    secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                                    httponly=True, samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax'))
            del response_obj.data["refresh"]
        response_obj["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response_obj, *args, **kwargs)


class StudentRegisterView(generics.CreateAPIView):
    serializer_class = StudentRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Ошибка регистрации", _serializer_hint(serializer.errors))


class AdminRegisterView(generics.CreateAPIView):
    serializer_class = AdminRegistrationSerializer
    permission_classes = [IsSuperAdmin]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Ошибка регистрации администратора", _serializer_hint(serializer.errors))


class SuperAdminRegisterView(generics.CreateAPIView):
    serializer_class = SuperAdminRegistrationSerializer
    permission_classes = [IsSuperAdmin]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Ошибка регистрации супер-администратора", _serializer_hint(serializer.errors))


# TaskCategory

class TaskCategoryListView(APIView):
    def get(self, request):
        return ok(TaskCategoryCRUDSerializer(TaskCategory.objects.all(), many=True).data)

class TaskCategoryCreateView(APIView):
    def post(self, request):
        serializer = TaskCategoryCRUDSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class TaskCategoryRetrieveView(APIView):
    def get(self, request, pk):
        return ok(TaskCategoryCRUDSerializer(get_object_or_404(TaskCategory, pk=pk)).data)

class TaskCategoryUpdateView(APIView):
    def put(self, request, pk):
        serializer = TaskCategoryCRUDSerializer(get_object_or_404(TaskCategory, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    def patch(self, request, pk):
        serializer = TaskCategoryCRUDSerializer(get_object_or_404(TaskCategory, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class TaskCategoryDestroyView(APIView):
    def delete(self, request, pk):
        get_object_or_404(TaskCategory, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# CategoryConfig
class CategoryConfigListView(APIView):
    def get(self, request):
        return ok(CategoryConfigCRUDSerializer(CategoryConfig.objects.all(), many=True).data)

class CategoryConfigCreateView(APIView):
    def post(self, request):
        serializer = CategoryConfigCRUDSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class CategoryConfigRetrieveView(APIView):
    def get(self, request, pk):
        return ok(CategoryConfigCRUDSerializer(get_object_or_404(CategoryConfig, pk=pk)).data)

class CategoryConfigUpdateView(APIView):
    def put(self, request, pk):
        serializer = CategoryConfigCRUDSerializer(get_object_or_404(CategoryConfig, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    def patch(self, request, pk):
        serializer = CategoryConfigCRUDSerializer(get_object_or_404(CategoryConfig, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class CategoryConfigDestroyView(APIView):
    def delete(self, request, pk):
        get_object_or_404(CategoryConfig, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# TaskComplexity

class ComplexityListView(APIView):
    def get(self, request):
        return ok(TaskComplexitySerializer(TaskComplexity.objects.all(), many=True).data)

class ComplexityCreateView(APIView):
    def post(self, request):
        serializer = TaskComplexitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class ComplexityRetrieveView(APIView):
    def get(self, request, pk):
        return ok(TaskComplexitySerializer(get_object_or_404(TaskComplexity, pk=pk)).data)

class ComplexityUpdateView(APIView):
    def put(self, request, pk):
        serializer = TaskComplexitySerializer(get_object_or_404(TaskComplexity, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    def patch(self, request, pk):
        serializer = TaskComplexitySerializer(get_object_or_404(TaskComplexity, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class ComplexityDestroyView(APIView):
    def delete(self, request, pk):
        get_object_or_404(TaskComplexity, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# ColorsMarkup

class ColorsMarkupListView(APIView):
    def get(self, request):
        return ok(ColorsMarkupSerializer(ColorsMarkup.objects.all(), many=True).data)

class ColorsMarkupCreateView(APIView):
    def post(self, request):
        serializer = ColorsMarkupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class ColorsMarkupRetrieveView(APIView):
    def get(self, request, pk):
        return ok(ColorsMarkupSerializer(get_object_or_404(ColorsMarkup, pk=pk)).data)

class ColorsMarkupUpdateView(APIView):
    def put(self, request, pk):
        serializer = ColorsMarkupSerializer(get_object_or_404(ColorsMarkup, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    def patch(self, request, pk):
        serializer = ColorsMarkupSerializer(get_object_or_404(ColorsMarkup, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class ColorsMarkupDestroyView(APIView):
    def delete(self, request, pk):
        get_object_or_404(ColorsMarkup, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# CategoryMarkup

class CategoryMarkupListView(APIView):
    def get(self, request):
        return ok(CategoryMarkupSerializer(CategoryMarkup.objects.all(), many=True).data)

class CategoryMarkupCreateView(APIView):
    def post(self, request):
        serializer = CategoryMarkupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class CategoryMarkupRetrieveView(APIView):
    def get(self, request, pk):
        return ok(CategoryMarkupSerializer(get_object_or_404(CategoryMarkup, pk=pk)).data)

class CategoryMarkupUpdateView(APIView):
    def put(self, request, pk):
        serializer = CategoryMarkupSerializer(get_object_or_404(CategoryMarkup, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    def patch(self, request, pk):
        serializer = CategoryMarkupSerializer(get_object_or_404(CategoryMarkup, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class CategoryMarkupDestroyView(APIView):
    def delete(self, request, pk):
        get_object_or_404(CategoryMarkup, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# Task

class TaskListView(APIView):
    def get(self, request):
        return ok(TaskAdminSerializer(Task.objects.all(), many=True).data)

class TaskCreateView(APIView):
    def post(self, request):
        serializer = TaskAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class TaskRetrieveView(APIView):
    def get(self, request, pk):
        return ok(TaskAdminSerializer(get_object_or_404(Task, pk=pk)).data)

class TaskUpdateView(APIView):
    def put(self, request, pk):
        serializer = TaskAdminSerializer(get_object_or_404(Task, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    def patch(self, request, pk):
        serializer = TaskAdminSerializer(get_object_or_404(Task, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class TaskDestroyView(APIView):
    def delete(self, request, pk):
        get_object_or_404(Task, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# TaskQuestion

class QuestionListView(APIView):
    def get(self, request):
        return ok(TaskQuestionAdminSerializer(TaskQuestion.objects.all(), many=True).data)

class QuestionCreateView(APIView):
    def post(self, request):
        serializer = TaskQuestionAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class QuestionRetrieveView(APIView):
    def get(self, request, pk):
        return ok(TaskQuestionAdminSerializer(get_object_or_404(TaskQuestion, pk=pk)).data)

class QuestionUpdateView(APIView):
    def put(self, request, pk):
        serializer = TaskQuestionAdminSerializer(get_object_or_404(TaskQuestion, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    def patch(self, request, pk):
        serializer = TaskQuestionAdminSerializer(get_object_or_404(TaskQuestion, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class QuestionDestroyView(APIView):
    def delete(self, request, pk):
        get_object_or_404(TaskQuestion, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


#  TaskAnswer
class AnswerListView(APIView):
    def get(self, request):
        return ok(TaskAnswerAdminSerializer(TaskAnswer.objects.all(), many=True).data)

class AnswerCreateView(APIView):
    def post(self, request):
        serializer = TaskAnswerAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class AnswerRetrieveView(APIView):
    def get(self, request, pk):
        return ok(TaskAnswerAdminSerializer(get_object_or_404(TaskAnswer, pk=pk)).data)

class AnswerUpdateView(APIView):
    def put(self, request, pk):
        serializer = TaskAnswerAdminSerializer(get_object_or_404(TaskAnswer, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    def patch(self, request, pk):
        serializer = TaskAnswerAdminSerializer(get_object_or_404(TaskAnswer, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class AnswerDestroyView(APIView):
    def delete(self, request, pk):
        get_object_or_404(TaskAnswer, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# Submission

class SubmissionListView(APIView):
    def get(self, request):
        return ok(SubmissionSerializer(Submission.objects.all(), many=True).data)

class SubmissionCreateView(APIView):
    def post(self, request):
        serializer = SubmissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class SubmissionRetrieveView(APIView):
    def get(self, request, pk):
        return ok(SubmissionSerializer(get_object_or_404(Submission, pk=pk)).data)

class SubmissionUpdateView(APIView):
    def put(self, request, pk):
        serializer = SubmissionSerializer(get_object_or_404(Submission, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    def patch(self, request, pk):
        serializer = SubmissionSerializer(get_object_or_404(Submission, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

class SubmissionDestroyView(APIView):
    def delete(self, request, pk):
        get_object_or_404(Submission, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# EVALUATION MIXIN

class EvaluationMixin:
    def _evaluate(self, task, data):
        ref_all = task.reference_markup
        ref_relevant = [r for r in ref_all if r['category_slug'] != 'useless']
        stu_markup = data.get('answer_markup', [])

        matches = sum(1 for r in ref_relevant if any(
            s['start'] == r['start'] and s['category_slug'] == r['category_slug']
            for s in stu_markup
        ))
        score_markup = (matches / len(ref_relevant) * 100) if ref_relevant else 100

        score_questions = 100.0
        if task.complexity.level in [3, 4]:
            correct_q_ids = set(task.questions.filter(is_correct=True).values_list('id', flat=True))
            student_q_ids = set(data.get('selected_question_ids', []))
            if correct_q_ids:
                score_questions = (len(correct_q_ids & student_q_ids) / len(correct_q_ids)) * 100
            penalty = len(student_q_ids - correct_q_ids) * 10
            score_questions = max(0, score_questions - penalty)

        score_answer = 0.0
        student_ans_obj = None
        correct_ans_obj = task.answers.filter(is_correct=True).first()
        selected_answer_id = data.get('selected_answer_id')
        if selected_answer_id:
            try:
                student_ans_obj = task.answers.get(id=selected_answer_id)
                if student_ans_obj.is_correct:
                    score_answer = 100.0
            except TaskAnswer.DoesNotExist:
                pass

        level = task.complexity.level
        if level == 1:
            total = score_markup
        elif level == 2:
            total = score_markup * 0.7 + score_answer * 0.3
        elif level == 3:
            total = score_markup * 0.5 + score_questions * 0.3 + score_answer * 0.2
        else:
            total = score_markup * 0.4 + score_questions * 0.4 + score_answer * 0.2

        if total >= 85:
            grade = "Отлично"
        elif total > 65:
            grade = "Хорошо"
        elif total > 40:
            grade = "Удовлетворительно"
        else:
            grade = "Попробуйте еще раз"

        markups = CategoryMarkup.objects.filter(task_category=task.category).select_related('color_markup')
        styles = {m.slug: m.color_markup.style for m in markups}
        stu_chars = data.get('student_characteristics', {})

        def format_markup(items):
            return [
                {"start": x['start'], "end": x['end'], "style": styles.get(x['category_slug'], "bg-gray-100")}
                for x in items
            ]

        return {
            "total_score": total,
            "grade": grade,
            "response": {
                "grade": grade,
                "spent_time": data.get("time_spent", "00:00"),
                "text": task.text,
                "studentAnswer": {
                    "id": student_ans_obj.id if student_ans_obj else None,
                    "text": student_ans_obj.text if student_ans_obj else "Нет ответа",
                },
                "correctAnswer": {
                    "id": correct_ans_obj.id if correct_ans_obj else None,
                    "text": correct_ans_obj.text if correct_ans_obj else "Не задан",
                },
                "studentMarkup": format_markup(stu_markup),
                "correctMarkup": format_markup(ref_all),
                "studentQuestions": [
                    {"id": q.id, "question": q.text, "answer": q.answer}
                    for q in task.questions.filter(id__in=data.get('selected_question_ids', []))
                ],
                "correctQuestions": [
                    {"id": q.id, "question": q.text, "answer": q.answer}
                    for q in task.questions.filter(is_correct=True)
                ],
                "characteristics": [
                    {
                        "name": m.name,
                        "color": m.color_markup.style,
                        "studentCharacteristics": stu_chars.get(m.slug),
                        "correctCharacteristics": task.correct_characteristics.get(m.slug),
                    }
                    for m in markups
                ],
            },
        }


#  STUDENT API

class EducationTasksAPI(APIView):
    def get(self, request):
        res = [
            TaskStudentSerializer(Task.objects.filter(complexity__level=lv).order_by('?').first()).data
            for lv in [1, 2, 3, 4]
            if Task.objects.filter(complexity__level=lv).exists()
        ]
        return ok(res)


class EducationSubmitAPI(APIView, EvaluationMixin):
    def post(self, request):
        task_id = request.data.get('task_id')
        if not task_id:
            return err("Поле task_id обязательно")
        task = get_object_or_404(Task, id=task_id)
        return ok(self._evaluate(task, request.data)['response'])


class ControlTaskAPI(APIView):
    def get(self, request):
        t = Task.objects.filter(complexity__level__in=[3, 4]).order_by('?').first()
        if not t:
            return err("Нет доступных задач для контроля", status_code=status.HTTP_404_NOT_FOUND)
        return ok(TaskStudentSerializer(t).data)


class ControlSubmitAPI(APIView, EvaluationMixin):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        task_id = data.get('task_id')
        if not task_id:
            return err("Поле task_id обязательно")
        task = get_object_or_404(Task, id=task_id)
        result = self._evaluate(task, data)

        attempts = Submission.objects.filter(student=request.user).order_by('created_at')
        submission_data = {
            "task": task,
            "total_score": result['total_score'],
            "grade": result['grade'],
            "spent_time": str(data.get('time_spent', "00:00")),
            "start_time": data.get('start_time'),
            "answer_markup": data.get('answer_markup', []),
            "selected_question_ids": data.get('selected_question_ids', []),
            "student_characteristics": data.get('student_characteristics', {}),
            "selected_answer_id": data.get('selected_answer_id'),
        }

        if attempts.count() >= 3:
            obj = attempts.first()
            for key, value in submission_data.items():
                setattr(obj, key, value)
            obj.save()
        else:
            obj = Submission.objects.create(student=request.user, **submission_data)

        return ok({**result['response'], "submission_id": obj.id})


# ADMIN API

class AdminAllSubmissionsAPI(APIView):
    permission_classes = [IsAdminOrSuperAdmin]

    def get(self, request):
        students = Account.objects.filter(submission__isnull=False).distinct()
        return ok(StudentStatementSerializer(students, many=True).data)


class AdminSubmissionDetailAPI(APIView, EvaluationMixin):
    permission_classes = [IsAdminOrSuperAdmin]

    def get(self, request, pk):
        submission = get_object_or_404(Submission, pk=pk)
        data_to_compare = {
            "answer_markup": submission.answer_markup,
            "selected_question_ids": submission.selected_question_ids,
            "selected_answer_id": submission.selected_answer_id,
            "student_characteristics": submission.student_characteristics,
            "time_spent": submission.spent_time,
        }
        return ok(self._evaluate(submission.task, data_to_compare)['response'])