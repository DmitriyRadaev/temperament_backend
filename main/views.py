# views.py
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, permissions, response, decorators, status
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


class DisciplineListAPI(APIView):
    def get(self, request):
        items = Discipline.objects.all()
        return Response(DisciplineSerializer(items, many=True).data)

class DisciplineCreateAPI(APIView):
    def post(self, request):
        serializer = DisciplineSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DisciplineDeleteAPI(APIView):
    def delete(self, request, pk):
        item = get_object_or_404(Discipline, pk=pk)
        item.delete()
        return Response({"status": "deleted"}, status=status.HTTP_204_NO_CONTENT)


# --- КАТЕГОРИИ (Цвета) ---
class CategoryListAPI(APIView):
    def get(self, request):
        items = Category.objects.all()
        return Response(CategorySerializer(items, many=True).data)


class CategoryCreateAPI(APIView):
    def post(self, request):
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CategoryDeleteAPI(APIView):
    def delete(self, request, pk):
        category = get_object_or_404(Category, pk=pk)
        category.delete()
        return Response({"message": "Category deleted"}, status=status.HTTP_204_NO_CONTENT)

# --- ЗАДАЧИ ---
class TaskListAPI(APIView):
    def get(self, request):
        tasks = Task.objects.all().order_by('-created_at')
        return Response(TaskSerializer(tasks, many=True).data)


class TaskDetailAPI(APIView):
    def get(self, request, pk):
        task = get_object_or_404(Task, pk=pk)
        return Response(TaskSerializer(task).data)


class TaskCreateAPI(APIView):
    def post(self, request):
        serializer = TaskSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TaskUpdateAPI(APIView):
    def patch(self, request, pk):
        task = get_object_or_404(Task, pk=pk)
        serializer = TaskSerializer(task, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TaskDeleteAPI(APIView):
    def delete(self, request, pk):
        task = get_object_or_404(Task, pk=pk)
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- ЗАБИТИЕ ВОПРОСОВ И ОПЦИЙ ---
class QuestionCreateAPI(APIView):
    def post(self, request):
        serializer = TaskQuestionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FinalOptionCreateAPI(APIView):
    def post(self, request):
        serializer = TaskFinalOptionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# --- ПРОВЕРКА РЕШЕНИЯ ---
class SubmissionSubmitAPI(APIView):
    def post(self, request):
        data = request.data
        task = get_object_or_404(Task, id=data.get('task'))

        # 1. Баллы за разметку (Текст)
        stu_markup = data.get('answer_markup', [])
        ref_markup = task.reference_markup
        matches = 0
        for r in ref_markup:
            for s in stu_markup:
                if (s['start'] == r['start'] and s['end'] == r['end'] and s['category_slug'] == r['category_slug']):
                    matches += 1
                    break
        score_markup = (matches / len(ref_markup) * 100) if ref_markup else 100

        # 2. Баллы за чат-бота (Вопросы)
        correct_q_ids = set(task.questions.filter(is_correct=True).values_list('id', flat=True))
        student_q_ids = set(data.get('selected_question_ids', []))
        if correct_q_ids:
            q_matches = len(correct_q_ids & student_q_ids)
            # Штрафуем за лишние неверные ответы
            wrong_choices = len(student_q_ids - correct_q_ids)
            score_questions = max(0, (q_matches / len(correct_q_ids) * 100) - (wrong_choices * 10))
        else:
            score_questions = 100 if not student_q_ids else 0

        # 3. Баллы за финальный выбор
        final_id = data.get('selected_final_option_id')
        is_final_correct = task.final_options.filter(id=final_id, is_correct=True).exists()
        score_final = 100.0 if is_final_correct else 0.0

        # Итог
        total_score = (score_markup + score_questions + score_final) / 3

        serializer = SubmissionSerializer(data=data)
        if serializer.is_valid():
            serializer.save(
                score_markup=round(score_markup, 2),
                score_questions=round(score_questions, 2),
                score_final=round(score_final, 2),
                total_score=round(total_score, 2)
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SubmissionHistoryAPI(APIView):
    def get(self, request):
        items = Submission.objects.all().order_by('-created_at')
        return Response(SubmissionSerializer(items, many=True).data)