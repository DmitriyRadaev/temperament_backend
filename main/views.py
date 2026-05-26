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
    drf_response.data = {"error": message}
    return drf_response


def ok(data=None, status_code=status.HTTP_200_OK):
    return Response(data, status=status_code)

def created(data=None):
    return Response(data, status=status.HTTP_201_CREATED)

def err(message: str, details=None, status_code=status.HTTP_400_BAD_REQUEST):
    body = {"error": message}
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
    if many:
        return serializer_class(many=True)
    return serializer_class()

_err_counter = 0
def _err_response():
    global _err_counter
    _err_counter += 1
    return inline_serializer(
        name=f"ErrorResponse{_err_counter}",
        fields={"error": s.CharField()}
    )

_deleted_counter = 0
def _deleted_response():
    global _deleted_counter
    _deleted_counter += 1
    return inline_serializer(
        name=f"DeletedResponse{_deleted_counter}",
        fields={"detail": s.CharField()}
    )


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {"refresh_token": str(refresh), "access_token": str(refresh.access_token)}


# AUTH

@extend_schema(
    tags=["Auth"],
    request=inline_serializer("LoginRequest", fields={"email": s.EmailField(), "password": s.CharField()}),
    responses={
        200: inline_serializer("LoginData", fields={"detail": s.CharField()}),
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
    res = Response({"detail": "Вход выполнен успешно"})
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
    responses={200: inline_serializer("LogoutData", fields={"detail": s.CharField()})}
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
    res = Response({"detail": "Выход выполнен успешно"}, status=status.HTTP_200_OK)
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


# MarkupOption

@extend_schema(tags=["Варианты характеристик (MarkupOption)"])
class MarkupOptionListView(APIView):
    @extend_schema(summary="Все варианты характеристик", responses={200: _ok_response(MarkupOptionSerializer, many=True)})
    def get(self, request):
        return ok(MarkupOptionSerializer(MarkupOption.objects.all(), many=True).data)

@extend_schema(tags=["Варианты характеристик (MarkupOption)"])
class MarkupOptionCreateView(APIView):
    @extend_schema(summary="Создать вариант характеристики", request=MarkupOptionSerializer, responses={201: _ok_response(MarkupOptionSerializer), 400: _err_response()})
    def post(self, request):
        serializer = MarkupOptionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return created(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Варианты характеристик (MarkupOption)"])
class MarkupOptionRetrieveView(APIView):
    @extend_schema(summary="Получить вариант характеристики", responses={200: _ok_response(MarkupOptionSerializer)})
    def get(self, request, pk):
        return ok(MarkupOptionSerializer(get_object_or_404(MarkupOption, pk=pk)).data)

@extend_schema(tags=["Варианты характеристик (MarkupOption)"])
class MarkupOptionUpdateView(APIView):
    @extend_schema(request=MarkupOptionSerializer, responses={200: _ok_response(MarkupOptionSerializer), 400: _err_response()})
    def put(self, request, pk):
        serializer = MarkupOptionSerializer(get_object_or_404(MarkupOption, pk=pk), data=request.data)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

    @extend_schema(request=MarkupOptionSerializer, responses={200: _ok_response(MarkupOptionSerializer), 400: _err_response()})
    def patch(self, request, pk):
        serializer = MarkupOptionSerializer(get_object_or_404(MarkupOption, pk=pk), data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return ok(serializer.data)
        return err("Неверные данные", _serializer_hint(serializer.errors))

@extend_schema(tags=["Варианты характеристик (MarkupOption)"])
class MarkupOptionDestroyView(APIView):
    @extend_schema(responses={200: _deleted_response()})
    def delete(self, request, pk):
        get_object_or_404(MarkupOption, pk=pk).delete()
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


# Элемент покраски (вход)
_markup_item_in = inline_serializer("MarkupItemIn", fields={
    "start":         s.IntegerField(help_text="Символьная позиция начала выделения"),
    "end":           s.IntegerField(help_text="Символьная позиция конца выделения"),
    "category_slug": s.CharField(help_text="Slug характеристики, напр. 'strength'"),
})

# Элемент покраски в ответе
_markup_item_out = inline_serializer("MarkupItemOut", fields={
    "start": s.IntegerField(),
    "end":   s.IntegerField(),
    "style": s.CharField(help_text="CSS-класс цвета, напр. 'bg-blue-200'"),
})

# Вопрос в ответе
_question_out = inline_serializer("QuestionOut", fields={
    "id":       s.IntegerField(),
    "question": s.CharField(),
    "answer":   s.CharField(),
})

# Ответ (финальный вариант)
_answer_out = inline_serializer("AnswerOut", fields={
    "id":   s.IntegerField(),
    "text": s.CharField(),
})

# Характеристика в результате
_characteristic_result = inline_serializer("CharacteristicResult", fields={
    "name":                   s.CharField(help_text="Название характеристики, напр. 'Сила'"),
    "color":                  s.CharField(help_text="CSS-класс цвета"),
    "studentCharacteristics": s.CharField(allow_null=True, help_text="Slug выбранной студентом опции"),
    "correctCharacteristics": s.CharField(allow_null=True, help_text="Slug правильной опции"),
})


from rest_framework.serializers import Serializer as _S

def _make_serializer(name, field_dict):
    """Создаёт именованный класс сериализатора — можно использовать как child= и many=True."""
    return type(name, (_S,), field_dict)

MarkupItemOutSerializer = _make_serializer("MarkupItemOut", {
    "start": s.IntegerField(),
    "end":   s.IntegerField(),
    "style": s.CharField(),
})

MarkupItemInSerializer = _make_serializer("MarkupItemIn", {
    "start":         s.IntegerField(),
    "end":           s.IntegerField(),
    "category_slug": s.CharField(),
})

QuestionOutSerializer = _make_serializer("QuestionOut", {
    "id":       s.IntegerField(),
    "question": s.CharField(),
    "answer":   s.CharField(),
})

CharacteristicResultSerializer = _make_serializer("CharacteristicResult", {
    "name":                   s.CharField(),
    "color":                  s.CharField(),
    "studentCharacteristics": s.CharField(allow_null=True),
    "correctCharacteristics": s.CharField(allow_null=True),
})

CharacteristicOptionSerializer = _make_serializer("CharacteristicOption", {
    "id":   s.CharField(),
    "name": s.CharField(),
})

CharacteristicInTaskSerializer = _make_serializer("CharacteristicInTask", {
    "id":      s.CharField(),
    "name":    s.CharField(),
    "color":   s.CharField(),
    "options": CharacteristicOptionSerializer(many=True),
})

QuestionInTaskSerializer = _make_serializer("QuestionInTask", {
    "id":     s.IntegerField(),
    "text":   s.CharField(),
    "answer": s.CharField(),
})

AnswerOptionInTaskSerializer = _make_serializer("AnswerOptionInTask", {
    "id":   s.IntegerField(),
    "text": s.CharField(),
})

AnswerOutSerializer = _make_serializer("AnswerOut", {
    "id":   s.IntegerField(),
    "text": s.CharField(),
})

# Результат оценивания (общий для submit и detail)
_evaluation_result = inline_serializer("EvaluationResult", fields={
    "grade":            s.CharField(help_text="Отлично / Хорошо / Удовлетворительно / Попробуйте еще раз"),
    "spent_time":       s.CharField(),
    "text":             s.CharField(help_text="Текст задачи"),
    "studentAnswer":    AnswerOutSerializer(),
    "correctAnswer":    AnswerOutSerializer(),
    "studentMarkup":    MarkupItemOutSerializer(many=True),
    "correctMarkup":    MarkupItemOutSerializer(many=True),
    "studentQuestions": QuestionOutSerializer(many=True),
    "correctQuestions": QuestionOutSerializer(many=True),
    "characteristics":  CharacteristicResultSerializer(many=True),
})

# Результат submit (evaluation + submission_id)
_submit_result = inline_serializer("SubmitResult", fields={
    "grade":            s.CharField(),
    "spent_time":       s.CharField(),
    "text":             s.CharField(),
    "submission_id":    s.IntegerField(help_text="ID сохранённой попытки"),
    "studentAnswer":    AnswerOutSerializer(),
    "correctAnswer":    AnswerOutSerializer(),
    "studentMarkup":    MarkupItemOutSerializer(many=True),
    "correctMarkup":    MarkupItemOutSerializer(many=True),
    "studentQuestions": QuestionOutSerializer(many=True),
    "correctQuestions": QuestionOutSerializer(many=True),
    "characteristics":  CharacteristicResultSerializer(many=True),
})

# Схема запроса submit (общая для обучения и контроля)
_submit_request = inline_serializer("SubmitRequest", fields={
    "task_id":    s.IntegerField(help_text="ID задачи"),
    "time_spent": s.CharField(help_text="Затраченное время HH:MM:SS"),
    "start_time": s.CharField(required=False, help_text="ISO datetime начала, напр. '2025-01-15T10:00:00'"),
    "answer_markup": MarkupItemInSerializer(many=True),
    "selected_question_ids": s.ListField(
        required=False,
        child=s.IntegerField(),
        help_text="ID вопросов чат-бота, которые задал студент",
    ),
    "student_characteristics": s.DictField(
        required=False,
        child=s.CharField(),
        help_text='Ключ — slug характеристики, значение — slug опции. Пример: {"strength": "strong"}',
    ),
    "selected_answer_id": s.IntegerField(required=False, help_text="ID выбранного варианта финального ответа"),
})

# Полная схема задачи для студента
TaskStudentSchemaSerializer = _make_serializer("TaskStudentSchema", {
    "id":               s.IntegerField(),
    "text":             s.CharField(),
    "condition":        s.CharField(),
    "complexity_level": s.IntegerField(),
    "characteristics":  CharacteristicInTaskSerializer(many=True),
    "questions":        QuestionInTaskSerializer(many=True),
    "answerOptions":    AnswerOptionInTaskSerializer(many=True),
})
_task_student_schema = TaskStudentSchemaSerializer()  # инстанс для одиночного использования

# ─── Student API ──────────────────────────────────────────────────────────────

@extend_schema(
    tags=["Обучение"],
    summary="Получить задачи для обучения (по одной на каждый уровень сложности 1–4)",
    responses={200: TaskStudentSchemaSerializer(many=True),}
)
class EducationTasksAPI(APIView):
    def get(self, request):
        res = [
            TaskStudentSerializer(Task.objects.filter(complexity__level=lv).order_by('?').first()).data
            for lv in [1, 2, 3, 4]
            if Task.objects.filter(complexity__level=lv).exists()
        ]
        return ok(res)


@extend_schema(
    tags=["Обучение"],
    summary="Проверить решение обучающей задачи (без сохранения попытки)",
    request=_submit_request,
    responses={
        200: _evaluation_result,
        400: _err_response(),
    }
)
class EducationSubmitAPI(APIView, EvaluationMixin):
    def post(self, request):
        task_id = request.data.get('task_id')
        if not task_id:
            return err("Поле task_id обязательно")
        task = get_object_or_404(Task, id=task_id)
        return ok(self._evaluate(task, request.data)['response'])


@extend_schema(
    tags=["Контроль"],
    summary="Получить случайную задачу для контроля (уровень сложности 3 или 4)",
    responses={
        200: _task_student_schema,
        404: _err_response(),
    }
)
class ControlTaskAPI(APIView):
    def get(self, request):
        t = Task.objects.filter(complexity__level__in=[3, 4]).order_by('?').first()
        if not t:
            return err("Нет доступных задач для контроля", status_code=status.HTTP_404_NOT_FOUND)
        return ok(TaskStudentSerializer(t).data)


@extend_schema(
    tags=["Контроль"],
    summary="Отправить решение контрольной задачи (сохраняется, макс. 3 попытки)",
    request=_submit_request,
    responses={
        200: _submit_result,
        400: _err_response(),
    }
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
    tags=["Профиль студента"],
    summary="Профиль текущего авторизованного пользователя",
    responses={200: _ok_response(UserProfileSerializer)}
)
class UserProfileView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserProfileSerializer

    def get_object(self):
        return self.request.user


@extend_schema(
    tags=["Контроль"],
    summary="Результат попытки студента — оценка, покраска, правильный ответ",
    description="Студент видит только свои попытки. submission_id возвращается в ответе на submit.",
    responses={
        200: _evaluation_result,
        403: _err_response(),
        404: _err_response(),
    }
)
class StudentSubmissionDetailAPI(APIView, EvaluationMixin):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        submission = get_object_or_404(Submission, pk=pk)
        if submission.student != request.user:
            return err("Нет доступа к этой попытке", status_code=status.HTTP_403_FORBIDDEN)
        data_to_compare = {
            "answer_markup": submission.answer_markup,
            "selected_question_ids": submission.selected_question_ids,
            "selected_answer_id": submission.selected_answer_id,
            "student_characteristics": submission.student_characteristics,
            "time_spent": submission.spent_time,
        }
        return ok(self._evaluate(submission.task, data_to_compare)['response'])


# ADMIN API

@extend_schema(
    tags=["Отчёты (Admin)"],
    summary="Сводная таблица: все студенты со сданными попытками",
    responses={200: _ok_response(StudentStatementSerializer, many=True)}
)
class AdminAllSubmissionsAPI(APIView):
    permission_classes = [IsAdminOrSuperAdmin]

    def get(self, request):
        students = Account.objects.filter(submission__isnull=False).distinct()
        return ok(StudentStatementSerializer(students, many=True).data)


@extend_schema(
    tags=["Отчёты (Admin)"],
    summary="Детальный просмотр конкретной попытки студента",
    description="Возвращает полный разбор: покраска студента vs эталон, выбранный и правильный ответ, вопросы, характеристики.",
    responses={
        200: _evaluation_result,
        404: _err_response(),
    }
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

# ─── Банк заданий (TaskForm API) ──────────────────────────────────────────────

from django.db import transaction as db_transaction

# Swagger-схемы

_CharOptionSchema = type("CharOptionSchema", (_S,), {
    "id":   s.CharField(),
    "name": s.CharField(),
})

_CharacteristicSchema = type("CharacteristicSchema", (_S,), {
    "id":      s.CharField(),
    "name":    s.CharField(),
    "color":   s.CharField(),
    "options": _CharOptionSchema(many=True),
})

_AnswerOptionSchema = type("AnswerOptionSchema", (_S,), {
    "id":   s.IntegerField(),
    "text": s.CharField(),
})

_CategoryConfigSchema = type("CategoryConfigSchema", (_S,), {
    "id":              s.CharField(),
    "name":            s.CharField(),
    "characteristics": _CharacteristicSchema(many=True),
    "answerOptions":   _AnswerOptionSchema(many=True),
})

_QuestionOutSchema = type("QuestionOutSchema", (_S,), {
    "id":       s.CharField(),
    "question": s.CharField(),
    "answer":   s.CharField(),
    "correct":  s.BooleanField(),
})

_MarkupItemSchema = type("MarkupItemSchema", (_S,), {
    "start":         s.IntegerField(),
    "end":           s.IntegerField(),
    "category_slug": s.CharField(),
})

_TaskDetailSchema = type("TaskDetailSchema", (_S,), {
    "id":                    s.CharField(),
    "taskCategory":          s.CharField(),
    "complexity":            s.CharField(),
    "taskText":              s.CharField(),
    "characteristics":       _CharacteristicSchema(many=True),
    "correctCharacteristics": s.DictField(child=s.CharField()),
    "textMarkup":            _MarkupItemSchema(many=True),
    "answerOptions":         _AnswerOptionSchema(many=True),

    "questions":             _QuestionOutSchema(many=True),
})

# Request-схемы

class _QuestionInSerializer(serializers.Serializer):
    question = serializers.CharField()
    answer   = serializers.CharField()
    correct  = serializers.BooleanField(default=False)

class _MarkupInSerializer(serializers.Serializer):
    start         = serializers.IntegerField()
    end           = serializers.IntegerField()
    category_slug = serializers.CharField()

class _AnswerOptionInSerializer(serializers.Serializer):
    id        = serializers.IntegerField()
    text      = serializers.CharField()
    isCorrect = serializers.BooleanField(default=False)

class TaskFormCreateSerializer(serializers.Serializer):
    taskCategory            = serializers.CharField()
    complexity              = serializers.CharField()
    taskText                = serializers.CharField()
    correctCharacteristics  = serializers.DictField(child=serializers.CharField(), required=False, default=dict)
    textMarkup              = _MarkupInSerializer(many=True, required=False, default=list)
    answerOptions           = _AnswerOptionInSerializer(many=True, required=False, default=list)
    questions               = _QuestionInSerializer(many=True, required=False, default=list)

    def validate_taskCategory(self, value):
        if not TaskCategory.objects.filter(id=value).exists():
            raise serializers.ValidationError(f"Категория с id={value} не найдена")
        return value

    def validate_complexity(self, value):
        if not TaskComplexity.objects.filter(id=value).exists():
            raise serializers.ValidationError(f"Сложность с id={value} не найдена")
        return value


def _css_to_color_name(style: str) -> str:
    """bg-blue-200 → blue, bg-yellow-200 → yellow и т.д."""
    mapping = {
        "blue": "blue", "yellow": "yellow", "green": "green",
        "red": "red", "purple": "purple", "pink": "pink",
        "orange": "orange", "teal": "teal",
    }
    for key, name in mapping.items():
        if key in style:
            return name
    return style


def _build_task_response(task):
    """Формирует ответ в формате ожидаемом фронтом."""
    markups = (
        CategoryMarkup.objects
        .filter(task_category=task.category)
        .select_related("color_markup")
        .prefetch_related("options")
    )
    characteristics = [
        {
            "id":      m.slug,
            "name":    m.name,
            "color":   _css_to_color_name(m.color_markup.style),
            "options": [{"id": opt.slug, "name": opt.name} for opt in m.options.all()],
        }
        for m in markups
    ]

    answers = list(task.answers.all())
    answer_options = [{"id": a.id, "text": a.text, "isCorrect": a.is_correct} for a in answers]

    return {
        "id":                     str(task.id),
        "taskCategory":           str(task.category.id),
        "complexity":             str(task.complexity.id),
        "taskText":               task.text,
        "characteristics":        characteristics,
        "correctCharacteristics": task.correct_characteristics,
        "textMarkup":             task.reference_markup,
        "answerOptions":          answer_options,
        "questions": [
            {
                "id":       str(q.id),
                "question": q.text,
                "answer":   q.answer,
                "correct":  q.is_correct,
            }
            for q in task.questions.all()
        ],
    }


@extend_schema(
    tags=["Банк заданий (Admin)"],
    summary="GET /api/task-categories — конфиг всех категорий для формы создания задачи",
    responses={200: _CategoryConfigSchema(many=True),}
)
class TaskCategoriesView(APIView):
    permission_classes = [IsAdminOrSuperAdmin]

    def get(self, request):
        categories = TaskCategory.objects.prefetch_related(
            "markup_buttons__color_markup",
            "markup_buttons__options",
            "tasks__answers",
        ).all()

        result = []
        for cat in categories:
            first_task = cat.tasks.prefetch_related("answers").first()
            answer_options = (
                [{"id": a.id, "text": a.text} for a in first_task.answers.all()]
                if first_task else []
            )
            result.append({
                "id":   str(cat.id),
                "name": cat.name,
                "characteristics": [
                    {
                        "id":      m.slug,
                        "name":    m.name,
                        "color":   _css_to_color_name(m.color_markup.style),
                        "options": [{"id": opt.slug, "name": opt.name} for opt in m.options.all()],
                    }
                    for m in cat.markup_buttons.all()
                ],
                "answerOptions": answer_options,
            })
        return ok(result)


@extend_schema(
    tags=["Банк заданий (Admin)"],
    summary="GET /api/tasks/:taskId — задача для формы редактирования",
    responses={
        200: _TaskDetailSchema(),
        404: _err_response(),
    }
)
class TaskFormDetailView(APIView):
    permission_classes = [IsAdminOrSuperAdmin]

    def get(self, request, pk):
        task = get_object_or_404(
            Task.objects.select_related("complexity", "category")
                        .prefetch_related("questions", "answers"),
            pk=pk
        )
        return ok(_build_task_response(task))


@extend_schema(
    tags=["Банк заданий (Admin)"],
    summary="POST /api/tasks — создать задачу",
    request=TaskFormCreateSerializer,
    responses={
        201: _TaskDetailSchema(),
        400: _err_response(),
    }
)
class TaskFormCreateView(APIView):
    permission_classes = [IsAdminOrSuperAdmin]

    def post(self, request):
        serializer = TaskFormCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return err("Неверные данные", _serializer_hint(serializer.errors))

        data = serializer.validated_data
        questions_data  = data.pop("questions", [])

        with db_transaction.atomic():
            task = Task.objects.create(
                category_id             = data["taskCategory"],
                complexity_id           = data["complexity"],
                text                    = data["taskText"],
                condition               = "",
                reference_markup        = data.get("textMarkup", []),
                correct_characteristics = data.get("correctCharacteristics", {}),
            )
            TaskQuestion.objects.bulk_create([
                TaskQuestion(
                    task=task,
                    text=q["question"],
                    answer=q["answer"],
                    is_correct=q["correct"],
                )
                for q in questions_data
            ])

            # Создаём TaskAnswer из answerOptions
            answer_options_data = data.get("answerOptions", [])
            if answer_options_data:
                TaskAnswer.objects.bulk_create([
                    TaskAnswer(
                        task=task,
                        text=a["text"],
                        is_correct=a.get("isCorrect", False),
                    )
                    for a in answer_options_data
                ])
        task = Task.objects.select_related("complexity", "category") \
                           .prefetch_related("questions", "answers") \
                           .get(pk=task.pk)
        return created(_build_task_response(task))


@extend_schema(
    tags=["Банк заданий (Admin)"],
    summary="PUT /api/tasks/:taskId — обновить задачу (вопросы пересоздаются целиком)",
    request=TaskFormCreateSerializer,
    responses={
        200: _TaskDetailSchema(),
        400: _err_response(),
        404: _err_response(),
    }
)
class TaskFormUpdateView(APIView):
    permission_classes = [IsAdminOrSuperAdmin]

    def put(self, request, pk):
        task = get_object_or_404(Task, pk=pk)
        serializer = TaskFormCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return err("Неверные данные", _serializer_hint(serializer.errors))

        data = serializer.validated_data
        questions_data    = data.pop("questions", [])

        with db_transaction.atomic():
            task.category_id             = data["taskCategory"]
            task.complexity_id           = data["complexity"]
            task.text                    = data["taskText"]
            task.reference_markup        = data.get("textMarkup", [])
            task.correct_characteristics = data.get("correctCharacteristics", {})
            task.save()

            # Пересоздаём вопросы целиком
            task.questions.all().delete()
            TaskQuestion.objects.bulk_create([
                TaskQuestion(
                    task=task,
                    text=q["question"],
                    answer=q["answer"],
                    is_correct=q["correct"],
                )
                for q in questions_data
            ])

            # Пересоздаём ответы если пришли
            answer_options_data = data.get("answerOptions", [])
            if answer_options_data:
                task.answers.all().delete()
                TaskAnswer.objects.bulk_create([
                    TaskAnswer(
                        task=task,
                        text=a["text"],
                        is_correct=a.get("isCorrect", False),
                    )
                    for a in answer_options_data
                ])
        task = Task.objects.select_related("complexity", "category") \
                           .prefetch_related("questions", "answers") \
                           .get(pk=task.pk)
        return ok(_build_task_response(task))


# Список задач по категориям (банк)

_TaskBankItemSchema = type("TaskBankItemSchema", (_S,), {
    "id":            s.IntegerField(),
    "complexity":    s.CharField(),
    "complexity_id": s.IntegerField(),
    "task_category": s.CharField(),
    "task_text":     s.CharField(),
})

_TaskBankGroupSchema = type("TaskBankGroupSchema", (_S,), {
    "category_id":   s.IntegerField(),
    "category_slug": s.CharField(),
    "category_name": s.CharField(),
    "tasks":         _TaskBankItemSchema(many=True),
})


@extend_schema(
    tags=["Банк заданий (Admin)"],
    summary="Список всех задач, сгруппированных по категориям",
    responses={200: _TaskBankGroupSchema(many=True),}
)
class TaskBankListView(APIView):
    permission_classes = [IsAdminOrSuperAdmin]

    def get(self, request):
        categories = TaskCategory.objects.prefetch_related("tasks__complexity").all()
        result = [
            {
                "category_id":   cat.id,
                "category_slug": cat.slug,
                "category_name": cat.name,
                "tasks": [
                    {
                        "id":            t.id,
                        "complexity":    t.complexity.name,
                        "complexity_id": t.complexity.id,
                        "task_category": cat.name,
                        "task_text":     t.text,
                    }
                    for t in cat.tasks.select_related("complexity").all()
                ],
            }
            for cat in categories
        ]
        return ok(result)