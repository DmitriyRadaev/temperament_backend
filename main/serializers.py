from rest_framework import serializers, generics
from django.contrib.auth import get_user_model
from .models import *

Account = get_user_model()


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ("id", "email", "name", "surname", "patronymic", "is_active", "is_staff", "is_superuser", "created_at",
                  "updated_at")
        read_only_fields = ("id", "created_at", "updated_at")


class StudentRegistrationSerializer(serializers.ModelSerializer):
    group = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, min_length=6)
    password2 = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = Account
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


# Создание задачек и покраса

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
        fields = '__all__'  # теперь включает description


class ColorsMarkupSerializer(serializers.ModelSerializer):
    class Meta:
        model = ColorsMarkup
        fields = '__all__'


class CategoryMarkupSerializer(serializers.ModelSerializer):
    style = serializers.CharField(source='color_markup.style', read_only=True)

    class Meta:
        model = CategoryMarkup
        fields = ['id', 'name', 'slug', 'color_markup', 'task_category', 'style']


class MarkupOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = MarkupOption
        fields = '__all__'


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


class SubmissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Submission
        fields = '__all__'


# Задачи и попытки

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
    complexity_level = serializers.IntegerField(source='complexity.level', read_only=True)
    characteristics = serializers.SerializerMethodField()
    questions = serializers.SerializerMethodField()
    answerOptions = serializers.SerializerMethodField()

    class Meta:
        model = Task
        fields = ['id', 'text', 'condition', 'complexity_level', 'characteristics', 'questions', 'answerOptions']

    def get_characteristics(self, obj):
        markups = (
            CategoryMarkup.objects
            .filter(task_category=obj.category)
            .select_related('color_markup')
            .prefetch_related('options')
        )
        return [
            {
                "id": m.slug,
                "name": m.name,
                "color": m.color_markup.style,
                "options": [{"id": opt.slug, "name": opt.name} for opt in m.options.all()],
            }
            for m in markups
        ]

    def get_questions(self, obj):
        return [
            {"id": q.id, "text": q.text, "answer": q.answer}
            for q in obj.questions.all()
        ]

    def get_answerOptions(self, obj):
        return [{"id": a.id, "text": a.text} for a in obj.answers.all()]


class StudentStatementSerializer(serializers.ModelSerializer):
    student_fio = serializers.SerializerMethodField()
    group = serializers.SerializerMethodField()

    last_start = serializers.SerializerMethodField()
    last_end = serializers.SerializerMethodField()
    last_spent = serializers.SerializerMethodField()
    last_grade = serializers.SerializerMethodField()

    attempts = serializers.SerializerMethodField()

    class Meta:
        model = Account
        fields = [
            'student_fio', 'group',
            'last_start', 'last_end', 'last_spent', 'last_grade',
            'attempts'
        ]

    def get_student_fio(self, obj):
        return f"{obj.surname} {obj.name}"

    def get_group(self, obj):
        return obj.student_profile.group if hasattr(obj, 'student_profile') else "N/A"

    def _get_sorted_attempts(self, obj):
        return obj.submission_set.all().order_by('created_at')

    def get_last_start(self, obj):
        last = self._get_sorted_attempts(obj).last()
        return last.start_time.strftime("%H:%M:%S %d.%m.%Y") if last and last.start_time else "—"

    def get_last_end(self, obj):
        last = self._get_sorted_attempts(obj).last()
        return last.created_at.strftime("%H:%M:%S %d.%m.%Y") if last else "—"

    def get_last_spent(self, obj):
        last = self._get_sorted_attempts(obj).last()
        return last.spent_time if last else "—"

    def get_last_grade(self, obj):
        last = self._get_sorted_attempts(obj).last()
        return last.grade if last else "—"

    def get_attempts(self, obj):
        return [
            {"number": i + 1, "id": att.id}
            for i, att in enumerate(self._get_sorted_attempts(obj))
        ]


class UserProfileSerializer(serializers.ModelSerializer):
    # Достаем группу напрямую из связанной модели StudentProfile
    group = serializers.CharField(source='student_profile.group', read_only=True)

    class Meta:
        model = Account
        fields = ("id", "email", "name", "surname", "patronymic", "role", "group", "is_staff")
        read_only_fields = fields