from rest_framework import serializers, generics
from django.contrib.auth import get_user_model
from .models import *


Account = get_user_model()


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ("id", "email", "name", "surname", "patronymic", "is_active", "is_staff", "is_superuser", "created_at", "updated_at")
        read_only_fields = ("id", "created_at", "updated_at")


class StudentRegistrationSerializer(serializers.ModelSerializer):
    group = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, min_length=6)
    password2 = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = Account
        # Явно перечисляем новые поля
        fields = ("email", "name", "surname", "patronymic", "password", "password2", "group")

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("password2"):
            raise serializers.ValidationError({"password": "Пароли не совпадают"})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        group = validated_data.pop("group")
        password = validated_data.pop("password")
        user = Account.objects.create_student(
            email=validated_data["email"],
            name=validated_data["name"],
            surname=validated_data["surname"],
            patronymic=validated_data.get("patronymic", ""),
            password=password,
            group=group,
        )
        return user


class AdminRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)
    password2 = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = Account
        fields = ("email", "name", "surname", "patronymic", "password", "password2")

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("password2"):
            raise serializers.ValidationError({"password": "Пароли не совпадают"})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        # Передаем данные в create_admin
        user = Account.objects.create_admin(
            email=validated_data["email"],
            name=validated_data["name"],
            surname=validated_data["surname"],
            patronymic=validated_data.get("patronymic", ""),
            password=validated_data["password"]
        )
        return user


class SuperAdminRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)
    password2 = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = Account
        fields = ("email", "name", "surname", "patronymic", "password", "password2")

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("password2"):
            raise serializers.ValidationError({"password": "Пароли не совпадают"})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        user = Account.objects.create_superuser(
            email=validated_data["email"],
            name=validated_data["name"],
            surname=validated_data["surname"],
            patronymic=validated_data.get("patronymic", ""),
            password=validated_data["password"]
        )
        return user


class StudentProfileSerializer(serializers.ModelSerializer):
    user = AccountSerializer(read_only=True)

    class Meta:
        model = StudentProfile
        fields = ("id", "user", "group")



# Сериализаторы системы


# --- ADMIN SERIALIZERS (Для CRUD) ---
class TaskCategoryCRUDSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskCategory
        fields = '__all__'

class CategoryConfigCRUDSerializer(serializers.ModelSerializer):
    class Meta:
        model = CategoryConfig
        fields = '__all__'

class TaskComplexitySerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskComplexity
        fields = '__all__'

class ColorsMarkupSerializer(serializers.ModelSerializer):
    class Meta:
        model = ColorsMarkup
        fields = '__all__'

class CategoryMarkupSerializer(serializers.ModelSerializer):
    style = serializers.CharField(source='color_markup.style', read_only=True)
    class Meta:
        model = CategoryMarkup
        fields = ['id', 'name', 'slug', 'color_markup', 'task_category', 'style']

class TaskQuestionAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskQuestion
        fields = '__all__'

class TaskAnswerAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskAnswer
        fields = '__all__'

class TaskAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = '__all__'

# --- STUDENT SERIALIZERS (Для выдачи задач) ---
class TaskCategoryStudentSerializer(serializers.ModelSerializer):
    class ConfigSerializer(serializers.ModelSerializer):
        class Meta:
            model = CategoryConfig
            fields = ['button_title', 'short_description', 'detail_description']
    config = ConfigSerializer(read_only=True)
    class Meta:
        model = TaskCategory
        fields = ['id', 'name', 'slug', 'config']

class TaskStudentSerializer(serializers.ModelSerializer):
    characteristics = serializers.SerializerMethodField()
    correctQuestions = serializers.SerializerMethodField() # Пул вопросов для чат-бота
    answerOptions = serializers.SerializerMethodField()
    complexity_level = serializers.IntegerField(source='complexity.level', read_only=True)

    class Meta:
        model = Task
        fields = ['id', 'text', 'condition', 'complexity_level', 'characteristics', 'correctQuestions', 'answerOptions']

    def get_characteristics(self, obj):
        markups = CategoryMarkup.objects.filter(task_category=obj.category).select_related('color_markup')
        return [{"id": m.slug, "name": m.name, "color": m.color_markup.style} for m in markups]

    def get_correctQuestions(self, obj):
        return [{"id": q.id, "text": q.text, "answer": q.answer} for q in obj.questions.all()]

    def get_answerOptions(self, obj):
        return [{"id": a.id, "text": a.text} for a in obj.answers.all()]


class SubmissionAdminSerializer(serializers.ModelSerializer):
    student_fio = serializers.SerializerMethodField()
    task_title = serializers.SerializerMethodField()

    class Meta:
        model = Submission
        fields = [
            'id',
            'student_fio',
            'task_title',
            'total_score',
            'grade',
            'spent_time',
            'created_at'
        ]

    def get_student_fio(self, obj):
        # 1. Безопасно получаем данные пользователя
        user = obj.student
        surname = getattr(user, 'surname', '')
        name = getattr(user, 'name', '')

        # 2. Безопасно получаем группу из профиля
        group = "Нет группы"
        # Проверяем связь OneToOne
        if hasattr(user, 'student_profile'):
            group = user.student_profile.group

        return f"{surname} {name} ({group})".strip()

    def get_task_title(self, obj):
        # Если задача существует - берем текст, если нет - пишем заглушку
        if obj.task:
            return obj.task.text[:50] + "..."
        return "Задача не найдена или удалена"