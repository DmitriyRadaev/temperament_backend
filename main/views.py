# views.py
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, permissions, response, decorators, status
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


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {"refresh_token": str(refresh), "access_token": str(refresh.access_token)}


@decorators.api_view(["POST"])
@decorators.permission_classes([])
def loginView(request):
    email = request.data.get("email")
    password = request.data.get("password")
    if not email or not password:
        raise rest_exceptions.ValidationError({"detail": "Email and password required"})

    user = authenticate(email=email, password=password)
    if not user:
        raise rest_exceptions.AuthenticationFailed("Email or password is incorrect!")

    tokens_dict = get_user_tokens(user)
    res = response.Response(tokens_dict)

    res.set_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE'],
        value=tokens_dict["access_token"],
        expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
        secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
        httponly=settings.SIMPLE_JWT.get('AUTH_COOKIE_HTTP_ONLY', True),
        samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax')
    )
    res.set_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
        value=tokens_dict["refresh_token"],
        expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
        secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
        httponly=settings.SIMPLE_JWT.get('AUTH_COOKIE_HTTP_ONLY', True),
        samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax')
    )
    res.set_cookie(
        key="user_role",
        value="admin" if user.is_staff else "student",
        max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
        secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
        httponly=True,
        samesite='Lax'
    )

    res["X-CSRFToken"] = csrf.get_token(request)
    return res

@csrf_exempt
@decorators.api_view(["POST"])
@decorators.permission_classes([permissions.AllowAny])
def logoutView(request):
    try:
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        if refresh_token:
            token = tokens.RefreshToken(refresh_token)
            token.blacklist()
    except Exception:
        pass

    res = response.Response({"detail": "Logged out successfully"}, status=status.HTTP_200_OK)

    res.delete_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE'],
        path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
        samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax')
    )

    res.delete_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
        path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
        samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax')
    )

    res.delete_cookie(
        key="user_role",
        path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
        samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax')
    )

    res.delete_cookie(
        key="is_staff",
        path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
        samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax')
    )

    res.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path='/',
        samesite=settings.CSRF_COOKIE_SAMESITE
    )

    res.delete_cookie(
        key="X-CSRFToken",
        path='/',
        samesite=settings.CSRF_COOKIE_SAMESITE
    )

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
            response_obj.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                value=response_obj.data['access'],
                expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                httponly=True,
                samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax')
            )
            del response_obj.data["access"]

        if response_obj.data.get("refresh"):
            response_obj.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=response_obj.data['refresh'],
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT.get('AUTH_COOKIE_SECURE', False),
                httponly=True, # Жестко True
                samesite=settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE', 'Lax')
            )
            del response_obj.data["refresh"]

        response_obj["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response_obj, *args, **kwargs)


@decorators.api_view(["GET"])
@decorators.permission_classes([permissions.IsAuthenticated])
def current_user_view(request):
    serializer = AccountSerializer(request.user)
    return response.Response(serializer.data)

class StudentRegisterView(generics.CreateAPIView):
    serializer_class = StudentRegistrationSerializer
    permission_classes = [permissions.AllowAny]


class AdminRegisterView(generics.CreateAPIView):
    serializer_class = AdminRegistrationSerializer
    permission_classes = [IsSuperAdmin]


class SuperAdminRegisterView(generics.CreateAPIView):
    serializer_class = SuperAdminRegistrationSerializer
    permission_classes = [IsSuperAdmin]


class StudentProfileViewSet(viewsets.ModelViewSet):
    queryset = StudentProfile.objects.select_related("user").all()
    serializer_class = StudentProfileSerializer
    permission_classes = [IsAdminOrSuperAdmin]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return super().get_queryset()
        return StudentProfile.objects.filter(user=user)


class EvaluationMixin:
    def _evaluate(self, task, data):
        # 1. Расчет баллов за разметку
        ref_all = task.reference_markup
        ref_relevant = [r for r in ref_all if r['category_slug'] != 'useless']
        stu_markup = data.get('answer_markup', [])

        matches = sum(1 for r in ref_relevant if any(
            s['start'] == r['start'] and s['category_slug'] == r['category_slug']
            for s in stu_markup
        ))
        score_markup = (matches / len(ref_relevant) * 100) if ref_relevant else 100

        # 2. Оценка вопросов чат-бота + штрафы
        score_questions = 100.0
        if task.complexity.level in [3, 4]:
            correct_q_query = task.questions.filter(is_correct=True)
            correct_q_ids = set(correct_q_query.values_list('id', flat=True))
            student_q_ids = set(data.get('selected_question_ids', []))

            if correct_q_ids:
                hits = len(correct_q_ids & student_q_ids)
                misses = len(student_q_ids - correct_q_ids)
                score_questions = max(0, (hits / len(correct_q_ids) * 100) - (misses * 20))
            else:
                score_questions = 100.0 if not student_q_ids else 0

        # 3. Оценка финального ответа
        correct_ans_obj = task.answers.filter(is_correct=True).first()
        student_ans_obj = TaskAnswer.objects.filter(id=data.get('selected_answer_id')).first()
        score_final = 100.0 if student_ans_obj and student_ans_obj.is_correct else 0.0

        # Итог (40/30/30)
        total = (score_markup * 0.4) + (score_questions * 0.3) + (score_final * 0.3)

        # Подбор грейда
        if total > 85:
            grade = "Отлично"
        elif total > 65:
            grade = "Хорошо"
        elif total > 40:
            grade = "Удовлетворительно"
        else:
            grade = "Попробуйте еще раз"

        # 4. Сборка характеристик (таблица сравнения)
        markups = CategoryMarkup.objects.filter(task_category=task.category).select_related('color_markup')
        styles = {m.slug: m.color_markup.style for m in markups}

        consolidated_characteristics = []
        stu_chars = data.get('student_characteristics', {})
        for m in markups:
            consolidated_characteristics.append({
                "name": m.name,
                "color": m.color_markup.style,
                "studentCharacteristics": stu_chars.get(m.slug),
                "correctCharacteristics": task.correct_characteristics.get(m.slug)
            })

        # Форматирование макапов
        def format_markup(items):
            return [{"start": x['start'], "end": x['end'], "style": styles.get(x['category_slug'], "bg-gray-100")} for x
                    in items]

        # Итоговый JSON-ответ
        return {
            "total_score": total,
            "grade": grade,
            "response": {
                "grade": grade,
                "spent_time": data.get("time_spent", "00:00"),
                "text": task.text,
                "studentAnswer": {
                    "id": student_ans_obj.id if student_ans_obj else None,
                    "text": student_ans_obj.text if student_ans_obj else "Нет ответа"
                },
                "correctAnswer": {
                    "id": correct_ans_obj.id if correct_ans_obj else None,
                    "text": correct_ans_obj.text if correct_ans_obj else "Не задан"
                },
                "studentMarkup": format_markup(stu_markup),
                "correctMarkup": format_markup(ref_all),
                # ДОБАВЛЕНО ПОЛЕ ANSWER
                "studentQuestions": [
                    {"id": q.id, "question": q.text, "answer": q.answer}
                    for q in task.questions.filter(id__in=data.get('selected_question_ids', []))
                ],
                # ДОБАВЛЕНО ПОЛЕ ANSWER
                "correctQuestions": [
                    {"id": q.id, "question": q.text, "answer": q.answer}
                    for q in task.questions.filter(is_correct=True)
                ],
                "characteristics": consolidated_characteristics
            }
        }


# --- STUDENT FACING API ---


# --- ГЕНЕРИЧЕСКИЙ КЛАСС ДЛЯ CRUD ---
class BaseCRUDView(APIView):
    model = None
    serializer_class = None

    def get(self, request, pk=None):
        if pk:
            obj = get_object_or_404(self.model, pk=pk)
            return Response(self.serializer_class(obj).data)
        objs = self.model.objects.all()
        return Response(self.serializer_class(objs, many=True).data)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, 201)
        return Response(serializer.errors, 400)

    def patch(self, request, pk):
        obj = get_object_or_404(self.model, pk=pk)
        serializer = self.serializer_class(obj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, 400)

    def delete(self, request, pk):
        obj = get_object_or_404(self.model, pk=pk)
        obj.delete()
        return Response(status=204)


# --- РЕАЛИЗАЦИЯ CRUD ---
class TaskCategoryCRUD(BaseCRUDView):
    model = TaskCategory
    serializer_class = TaskCategoryStudentSerializer


class CategoryConfigCRUD(BaseCRUDView):
    model = CategoryConfig
    serializer_class = CategoryConfigCRUDSerializer


class ComplexityCRUD(BaseCRUDView):
    model = TaskComplexity
    serializer_class = TaskComplexitySerializer


class ColorsMarkupCRUD(BaseCRUDView):
    model = ColorsMarkup
    serializer_class = ColorsMarkupSerializer


class CategoryMarkupCRUD(BaseCRUDView):
    model = CategoryMarkup
    serializer_class = CategoryMarkupSerializer


class TaskCRUD(BaseCRUDView):
    model = Task
    serializer_class = TaskAdminSerializer


class QuestionCRUD(BaseCRUDView):
    model = TaskQuestion
    serializer_class = TaskQuestionAdminSerializer


class AnswerCRUD(BaseCRUDView):
    model = TaskAnswer
    serializer_class = TaskAnswerAdminSerializer



# --- STUDENT API ---
class EducationTasksAPI(APIView):
    def get(self, request):
        res = [TaskStudentSerializer(Task.objects.filter(complexity__level=lv).order_by('?').first()).data for lv in
               [1, 2, 3, 4] if Task.objects.filter(complexity__level=lv).exists()]
        return Response(res)


class EducationSubmitAPI(APIView, EvaluationMixin):
    def post(self, request):
        task = get_object_or_404(Task, id=request.data.get('task_id'))
        res = self._evaluate(task, request.data)
        return Response(res['response'])


class ControlTaskAPI(APIView):
    def get(self, request):
        t = Task.objects.filter(complexity__level__in=[3, 4]).order_by('?').first()
        return Response(TaskStudentSerializer(t).data if t else {}, status=200 if t else 404)


class ControlSubmitAPI(APIView, EvaluationMixin):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        task = get_object_or_404(Task, id=data.get('task_id'))
        res = self._evaluate(task, data)
        Submission.objects.create(
            task=task, student=request.user, total_score=res['total_score'], grade=res['grade'],
            spent_time=data.get('time_spent', "00:00"), answer_markup=data.get('answer_markup'),
            student_characteristics=data.get('student_characteristics'),
            selected_answer_id=data.get('selected_answer_id'),
            selected_question_ids=data.get('selected_question_ids')
        )
        return Response(res['response'])


class AdminAllSubmissionsAPI(APIView):
    permission_classes = [IsAdminOrSuperAdmin]

    def get(self, request):
        subs = Submission.objects.all().select_related('student', 'task').order_by('-created_at')
        return Response(SubmissionAdminSerializer(subs, many=True).data)