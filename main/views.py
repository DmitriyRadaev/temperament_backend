from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, permissions, response, decorators, status, generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt import tokens, views as jwt_views, serializers as jwt_serializers, exceptions as jwt_exceptions
from django.contrib.auth import authenticate
from django.conf import settings
from django.middleware import csrf
from rest_framework import exceptions as rest_exceptions
from drf_spectacular.utils import extend_schema, OpenApiResponse, inline_serializer
from rest_framework import serializers as s

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


# вспомогательные inline-схемы для swagger
def _ok_response(serializer_class, many=False):
    """Оборачивает сериализатор в {"ok": true, "data": ...} для swagger."""
    data_field = serializer_class(many=many) if many else serializer_class()
    return inline_serializer(
        name=f"Ok{serializer_class.__name__}{'List' if many else ''}",
        fields={"ok": s.BooleanField(), "data": data_field}
    )

def _err_response():
    return inline_serializer(
        name="ErrorResponse",
        fields={"ok": s.BooleanField(), "error": s.CharField()}
    )

def _deleted_response():
    return inline_serializer(
        name="DeletedResponse",
        fields={"ok": s.BooleanField(), "data": inline_serializer(name="DeletedData", fields={"detail": s.CharField()})}
    )


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {"refresh_token": str(refresh), "access_token": str(refresh.access_token)}


# AUTH

@extend_schema(
    tags=["Auth"],
    request=inline_serializer("LoginRequest", fields={"email": s.EmailField(), "password": s.CharField()}),
    responses={
        200: inline_serializer("LoginResponse", fields={"ok": s.BooleanField(), "data": inline_serializer("LoginData", fields={"detail": s.CharField()})}),
        400: _err_response(),
        401: _err_response(),
    }
)
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


@extend_schema(
    tags=["Auth"],
    request=None,
    responses={200: inline_serializer("LogoutResponse", fields={"ok": s.BooleanField(), "data": inline_serializer("LogoutData", fields={"detail": s.CharField()})})}
)
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


@extend_schema(tags=["Auth"])
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


@extend_schema(tags=["Auth"], request=StudentRegistrationSerializer, responses={201: _ok_response(StudentRegistrationSerializer), 400: _err_response()})
class StudentRegisterView(generics.CreateAPIView):
    serializer_class = StudentRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Ошибка регистрации", _serializer_hint(serializer.errors))


@extend_schema(tags=["Auth"], request=AdminRegistrationSerializer, responses={201: _ok_response(AdminRegistrationSerializer), 400: _err_response()})
class AdminRegisterView(generics.CreateAPIView):
    serializer_class = AdminRegistrationSerializer
    permission_classes = [IsSuperAdmin]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Ошибка регистрации администратора", _serializer_hint(serializer.errors))


@extend_schema(tags=["Auth"], request=SuperAdminRegistrationSerializer, responses={201: _ok_response(SuperAdminRegistrationSerializer), 400: _err_response()})
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

@extend_schema(tags=["TaskCategory"])
class TaskCategoryListView(APIView):
    @extend_schema(responses={200: _ok_response(TaskCategoryCRUDSerializer, many=True)})
    def get(self, request):
        return ok(TaskCategoryCRUDSerializer(TaskCategory.objects.all(), many=True).data)

@extend_schema(tags=["TaskCategory"])
class TaskCategoryCreateView(APIView):
    @extend_schema(request=TaskCategoryCRUDSerializer, responses={201: _ok_response(TaskCategoryCRUDSerializer), 400: _err_response()})
    def post(self, request):
        serializer = TaskCategoryCRUDSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["TaskCategory"])
class TaskCategoryRetrieveView(APIView):
    @extend_schema(responses={200: _ok_response(TaskCategoryCRUDSerializer)})
    def get(self, request, pk):
        return ok(TaskCategoryCRUDSerializer(get_object_or_404(TaskCategory, pk=pk)).data)

@extend_schema(tags=["TaskCategory"])
class TaskCategoryUpdateView(APIView):
    @extend_schema(request=TaskCategoryCRUDSerializer, responses={200: _ok_response(TaskCategoryCRUDSerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = TaskCategoryCRUDSerializer(get_object_or_404(TaskCategory, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=TaskCategoryCRUDSerializer, responses={200: _ok_response(TaskCategoryCRUDSerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = TaskCategoryCRUDSerializer(get_object_or_404(TaskCategory, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["TaskCategory"])
class TaskCategoryDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
    def delete(self, request, pk):
        get_object_or_404(TaskCategory, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# CategoryConfig

@extend_schema(tags=["CategoryConfig"])
class CategoryConfigListView(APIView):
    @extend_schema(responses={200: _ok_response(CategoryConfigCRUDSerializer, many=True)})
    def get(self, request):
        return ok(CategoryConfigCRUDSerializer(CategoryConfig.objects.all(), many=True).data)

@extend_schema(tags=["CategoryConfig"])
class CategoryConfigCreateView(APIView):
    @extend_schema(request=CategoryConfigCRUDSerializer, responses={201: _ok_response(CategoryConfigCRUDSerializer), 400: _err_response()})
    def post(self, request):
        serializer = CategoryConfigCRUDSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["CategoryConfig"])
class CategoryConfigRetrieveView(APIView):
    @extend_schema(responses={200: _ok_response(CategoryConfigCRUDSerializer)})
    def get(self, request, pk):
        return ok(CategoryConfigCRUDSerializer(get_object_or_404(CategoryConfig, pk=pk)).data)

@extend_schema(tags=["CategoryConfig"])
class CategoryConfigUpdateView(APIView):
    @extend_schema(request=CategoryConfigCRUDSerializer, responses={200: _ok_response(CategoryConfigCRUDSerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = CategoryConfigCRUDSerializer(get_object_or_404(CategoryConfig, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=CategoryConfigCRUDSerializer, responses={200: _ok_response(CategoryConfigCRUDSerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = CategoryConfigCRUDSerializer(get_object_or_404(CategoryConfig, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["CategoryConfig"])
class CategoryConfigDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
    def delete(self, request, pk):
        get_object_or_404(CategoryConfig, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# TaskComplexity

@extend_schema(tags=["Complexity"])
class ComplexityListView(APIView):
    @extend_schema(responses={200: _ok_response(TaskComplexitySerializer, many=True)})
    def get(self, request):
        return ok(TaskComplexitySerializer(TaskComplexity.objects.all(), many=True).data)

@extend_schema(tags=["Complexity"])
class ComplexityCreateView(APIView):
    @extend_schema(request=TaskComplexitySerializer, responses={201: _ok_response(TaskComplexitySerializer), 400: _err_response()})
    def post(self, request):
        serializer = TaskComplexitySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Complexity"])
class ComplexityRetrieveView(APIView):
    @extend_schema(responses={200: _ok_response(TaskComplexitySerializer)})
    def get(self, request, pk):
        return ok(TaskComplexitySerializer(get_object_or_404(TaskComplexity, pk=pk)).data)

@extend_schema(tags=["Complexity"])
class ComplexityUpdateView(APIView):
    @extend_schema(request=TaskComplexitySerializer, responses={200: _ok_response(TaskComplexitySerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = TaskComplexitySerializer(get_object_or_404(TaskComplexity, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=TaskComplexitySerializer, responses={200: _ok_response(TaskComplexitySerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = TaskComplexitySerializer(get_object_or_404(TaskComplexity, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Complexity"])
class ComplexityDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
    def delete(self, request, pk):
        get_object_or_404(TaskComplexity, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# ColorsMarkup

@extend_schema(tags=["Colors"])
class ColorsMarkupListView(APIView):
    @extend_schema(responses={200: _ok_response(ColorsMarkupSerializer, many=True)})
    def get(self, request):
        return ok(ColorsMarkupSerializer(ColorsMarkup.objects.all(), many=True).data)

@extend_schema(tags=["Colors"])
class ColorsMarkupCreateView(APIView):
    @extend_schema(request=ColorsMarkupSerializer, responses={201: _ok_response(ColorsMarkupSerializer), 400: _err_response()})
    def post(self, request):
        serializer = ColorsMarkupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Colors"])
class ColorsMarkupRetrieveView(APIView):
    @extend_schema(responses={200: _ok_response(ColorsMarkupSerializer)})
    def get(self, request, pk):
        return ok(ColorsMarkupSerializer(get_object_or_404(ColorsMarkup, pk=pk)).data)

@extend_schema(tags=["Colors"])
class ColorsMarkupUpdateView(APIView):
    @extend_schema(request=ColorsMarkupSerializer, responses={200: _ok_response(ColorsMarkupSerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = ColorsMarkupSerializer(get_object_or_404(ColorsMarkup, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=ColorsMarkupSerializer, responses={200: _ok_response(ColorsMarkupSerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = ColorsMarkupSerializer(get_object_or_404(ColorsMarkup, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Colors"])
class ColorsMarkupDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
    def delete(self, request, pk):
        get_object_or_404(ColorsMarkup, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# CategoryMarkup

@extend_schema(tags=["Markup"])
class CategoryMarkupListView(APIView):
    @extend_schema(responses={200: _ok_response(CategoryMarkupSerializer, many=True)})
    def get(self, request):
        return ok(CategoryMarkupSerializer(CategoryMarkup.objects.all(), many=True).data)

@extend_schema(tags=["Markup"])
class CategoryMarkupCreateView(APIView):
    @extend_schema(request=CategoryMarkupSerializer, responses={201: _ok_response(CategoryMarkupSerializer), 400: _err_response()})
    def post(self, request):
        serializer = CategoryMarkupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Markup"])
class CategoryMarkupRetrieveView(APIView):
    @extend_schema(responses={200: _ok_response(CategoryMarkupSerializer)})
    def get(self, request, pk):
        return ok(CategoryMarkupSerializer(get_object_or_404(CategoryMarkup, pk=pk)).data)

@extend_schema(tags=["Markup"])
class CategoryMarkupUpdateView(APIView):
    @extend_schema(request=CategoryMarkupSerializer, responses={200: _ok_response(CategoryMarkupSerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = CategoryMarkupSerializer(get_object_or_404(CategoryMarkup, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=CategoryMarkupSerializer, responses={200: _ok_response(CategoryMarkupSerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = CategoryMarkupSerializer(get_object_or_404(CategoryMarkup, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Markup"])
class CategoryMarkupDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
    def delete(self, request, pk):
        get_object_or_404(CategoryMarkup, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# Task

@extend_schema(tags=["Task"])
class TaskListView(APIView):
    @extend_schema(responses={200: _ok_response(TaskAdminSerializer, many=True)})
    def get(self, request):
        return ok(TaskAdminSerializer(Task.objects.all(), many=True).data)

@extend_schema(tags=["Task"])
class TaskCreateView(APIView):
    @extend_schema(request=TaskAdminSerializer, responses={201: _ok_response(TaskAdminSerializer), 400: _err_response()})
    def post(self, request):
        serializer = TaskAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Task"])
class TaskRetrieveView(APIView):
    @extend_schema(responses={200: _ok_response(TaskAdminSerializer)})
    def get(self, request, pk):
        return ok(TaskAdminSerializer(get_object_or_404(Task, pk=pk)).data)

@extend_schema(tags=["Task"])
class TaskUpdateView(APIView):
    @extend_schema(request=TaskAdminSerializer, responses={200: _ok_response(TaskAdminSerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = TaskAdminSerializer(get_object_or_404(Task, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=TaskAdminSerializer, responses={200: _ok_response(TaskAdminSerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = TaskAdminSerializer(get_object_or_404(Task, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Task"])
class TaskDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
    def delete(self, request, pk):
        get_object_or_404(Task, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# TaskQuestion

@extend_schema(tags=["Question"])
class QuestionListView(APIView):
    @extend_schema(responses={200: _ok_response(TaskQuestionAdminSerializer, many=True)})
    def get(self, request):
        return ok(TaskQuestionAdminSerializer(TaskQuestion.objects.all(), many=True).data)

@extend_schema(tags=["Question"])
class QuestionCreateView(APIView):
    @extend_schema(request=TaskQuestionAdminSerializer, responses={201: _ok_response(TaskQuestionAdminSerializer), 400: _err_response()})
    def post(self, request):
        serializer = TaskQuestionAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Question"])
class QuestionRetrieveView(APIView):
    @extend_schema(responses={200: _ok_response(TaskQuestionAdminSerializer)})
    def get(self, request, pk):
        return ok(TaskQuestionAdminSerializer(get_object_or_404(TaskQuestion, pk=pk)).data)

@extend_schema(tags=["Question"])
class QuestionUpdateView(APIView):
    @extend_schema(request=TaskQuestionAdminSerializer, responses={200: _ok_response(TaskQuestionAdminSerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = TaskQuestionAdminSerializer(get_object_or_404(TaskQuestion, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=TaskQuestionAdminSerializer, responses={200: _ok_response(TaskQuestionAdminSerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = TaskQuestionAdminSerializer(get_object_or_404(TaskQuestion, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Question"])
class QuestionDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
    def delete(self, request, pk):
        get_object_or_404(TaskQuestion, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# TaskAnswer

@extend_schema(tags=["Answer"])
class AnswerListView(APIView):
    @extend_schema(responses={200: _ok_response(TaskAnswerAdminSerializer, many=True)})
    def get(self, request):
        return ok(TaskAnswerAdminSerializer(TaskAnswer.objects.all(), many=True).data)

@extend_schema(tags=["Answer"])
class AnswerCreateView(APIView):
    @extend_schema(request=TaskAnswerAdminSerializer, responses={201: _ok_response(TaskAnswerAdminSerializer), 400: _err_response()})
    def post(self, request):
        serializer = TaskAnswerAdminSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Answer"])
class AnswerRetrieveView(APIView):
    @extend_schema(responses={200: _ok_response(TaskAnswerAdminSerializer)})
    def get(self, request, pk):
        return ok(TaskAnswerAdminSerializer(get_object_or_404(TaskAnswer, pk=pk)).data)

@extend_schema(tags=["Answer"])
class AnswerUpdateView(APIView):
    @extend_schema(request=TaskAnswerAdminSerializer, responses={200: _ok_response(TaskAnswerAdminSerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = TaskAnswerAdminSerializer(get_object_or_404(TaskAnswer, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=TaskAnswerAdminSerializer, responses={200: _ok_response(TaskAnswerAdminSerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = TaskAnswerAdminSerializer(get_object_or_404(TaskAnswer, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Answer"])
class AnswerDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
    def delete(self, request, pk):
        get_object_or_404(TaskAnswer, pk=pk).delete()
        return ok({"detail": "Запись удалена"})


# Submission

@extend_schema(tags=["Submission"])
class SubmissionListView(APIView):
    @extend_schema(responses={200: _ok_response(SubmissionSerializer, many=True)})
    def get(self, request):
        return ok(SubmissionSerializer(Submission.objects.all(), many=True).data)

@extend_schema(tags=["Submission"])
class SubmissionCreateView(APIView):
    @extend_schema(request=SubmissionSerializer, responses={201: _ok_response(SubmissionSerializer), 400: _err_response()})
    def post(self, request):
        serializer = SubmissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Submission"])
class SubmissionRetrieveView(APIView):
    @extend_schema(responses={200: _ok_response(SubmissionSerializer)})
    def get(self, request, pk):
        return ok(SubmissionSerializer(get_object_or_404(Submission, pk=pk)).data)

@extend_schema(tags=["Submission"])
class SubmissionUpdateView(APIView):
    @extend_schema(request=SubmissionSerializer, responses={200: _ok_response(SubmissionSerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = SubmissionSerializer(get_object_or_404(Submission, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=SubmissionSerializer, responses={200: _ok_response(SubmissionSerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = SubmissionSerializer(get_object_or_404(Submission, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Submission"])
class SubmissionDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
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


# STUDENT API

@extend_schema(tags=["Student"], responses={200: _ok_response(TaskStudentSerializer, many=True)})
class EducationTasksAPI(APIView):
    def get(self, request):
        res = [
            TaskStudentSerializer(Task.objects.filter(complexity__level=lv).order_by('?').first()).data
            for lv in [1, 2, 3, 4]
            if Task.objects.filter(complexity__level=lv).exists()
        ]
        return ok(res)


@extend_schema(
    tags=["Student"],
    request=inline_serializer("EducationSubmitRequest", fields={"task_id": s.IntegerField()}),
    responses={200: inline_serializer("EducationSubmitResponse", fields={"ok": s.BooleanField(), "data": s.DictField()}), 400: _err_response()}
)
class EducationSubmitAPI(APIView, EvaluationMixin):
    def post(self, request):
        task_id = request.data.get('task_id')
        if not task_id:
            return err("Поле task_id обязательно")
        task = get_object_or_404(Task, id=task_id)
        return ok(self._evaluate(task, request.data)['response'])


@extend_schema(tags=["Control"], responses={200: _ok_response(TaskStudentSerializer), 404: _err_response()})
class ControlTaskAPI(APIView):
    def get(self, request):
        t = Task.objects.filter(complexity__level__in=[3, 4]).order_by('?').first()
        if not t:
            return err("Нет доступных задач для контроля", status_code=status.HTTP_404_NOT_FOUND)
        return ok(TaskStudentSerializer(t).data)


@extend_schema(
    tags=["Control"],
    request=inline_serializer("ControlSubmitRequest", fields={
        "task_id": s.IntegerField(),
        "time_spent": s.CharField(),
        "start_time": s.CharField(required=False),
        "answer_markup": s.ListField(child=s.DictField(), required=False),
        "selected_question_ids": s.ListField(child=s.IntegerField(), required=False),
        "student_characteristics": s.DictField(required=False),
        "selected_answer_id": s.IntegerField(required=False),
    }),
    responses={200: inline_serializer("ControlSubmitResponse", fields={"ok": s.BooleanField(), "data": s.DictField()}), 400: _err_response()}
)
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

@extend_schema(
    tags=["Auth"],
    responses={200: _ok_response(UserProfileSerializer)}
)
class UserProfileView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_object(self):
        return self.request.user

# ADMIN API

@extend_schema(tags=["Admin"], responses={200: _ok_response(StudentStatementSerializer, many=True)})
class AdminAllSubmissionsAPI(APIView):
    permission_classes = [IsAdminOrSuperAdmin]

    def get(self, request):
        students = Account.objects.filter(submission__isnull=False).distinct()
        return ok(StudentStatementSerializer(students, many=True).data)


@extend_schema(
    tags=["Admin"],
    responses={200: inline_serializer("AdminSubmissionDetailResponse", fields={"ok": s.BooleanField(), "data": s.DictField()})}
)
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