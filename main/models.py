from django.conf import settings
from django.db import models, transaction
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db.models import F


class AccountManager(BaseUserManager):
    def create_user(self, email, name, surname, patronymic=None, password=None, role="STUDENT", **kwargs):
        if not email:
            raise ValueError("Email is required")
        if not name:
            raise ValueError("Name is required")
        if not surname:
            raise ValueError("Surname is required")

        email = self.normalize_email(email)
        # Сохраняем name, surname, patronymic
        user = self.model(
            email=email,
            name=name,
            surname=surname,
            patronymic=patronymic or "",  # Если None, пишем пустую строку
            role=role,
            **kwargs
        )
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, surname, password=None, **kwargs):
        # Передаем параметры в create_user
        user = self.create_user(
            email=email,
            name=name,
            surname=surname,
            password=password,
            role=Account.Role.SUPERADMIN,
            **kwargs
        )
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

    def create_admin(self, email, name, surname, password=None, **kwargs):
        user = self.create_user(
            email=email,
            name=name,
            surname=surname,
            password=password,
            role=Account.Role.ADMIN,
            **kwargs
        )
        user.is_staff = True
        user.save(using=self._db)
        return user

    def create_student(self, email, name, surname, patronymic=None, password=None, group=None,
                      **kwargs):
        user = self.create_user(
            email=email,
            name=name,
            surname=surname,
            patronymic=patronymic,
            password=password,
            role=Account.Role.STUDENT,
            **kwargs
        )

        if group is not None:
            StudentProfile.objects.update_or_create(user=user, defaults={
                "group": group or ""
            })
        return user


class Account(AbstractBaseUser, PermissionsMixin):
    class Role(models.TextChoices):
        SUPERADMIN = "SUPERADMIN", "Главный администратор"
        ADMIN = "ADMIN", "Администратор"
        STUDENT = "STUDENT", "Студент"

    email = models.EmailField(null=False, blank=False, unique=True)
    name = models.CharField(max_length=50, blank=False, null=False, verbose_name="Имя")
    surname = models.CharField(max_length=50, blank=False, null=False, verbose_name="Фамилия")
    patronymic = models.CharField(max_length=50, blank=True, default="", verbose_name="Отчество")

    role = models.CharField(max_length=20, choices=Role.choices, default=Role.STUDENT)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = AccountManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "surname"]

    def __str__(self):
        full_name = f"{self.surname} {self.name} {self.patronymic}".strip()
        return f"{full_name} ({self.role})"

    def has_perm(self, perm, obj=None):
        if self.is_superuser or self.role == Account.Role.SUPERADMIN:
            return True
        return super().has_perm(perm, obj)

    def has_module_perms(self, app_label):
        if self.is_superuser or self.role == Account.Role.SUPERADMIN:
            return True
        return True

    @property
    def is_superadmin(self):
        return self.role == Account.Role.SUPERADMIN

    @property
    def is_admin_role(self):
        return self.role == Account.Role.ADMIN

    @property
    def is_student(self):
        return self.role == Account.Role.STUDENT

class StudentProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="student_profile")
    group = models.CharField(max_length=255, blank=True, null=False)
    def __str__(self):
        return f"Profile for {self.user.email}"


class Discipline(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)

    def __str__(self):
        return self.name


class Category(models.Model):
    discipline = models.ForeignKey(Discipline, on_delete=models.CASCADE, related_name="categories")
    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    color = models.CharField(max_length=7)
    text_color = models.CharField(max_length=7, default="#FFFFFF")

    def __str__(self):
        return f"[{self.discipline.name}] {self.name}"


class Task(models.Model):
    discipline = models.ForeignKey(Discipline, on_delete=models.PROTECT)
    complexity = models.CharField(max_length=10)  # А+Б-, А-Б+ и т.д.
    title = models.CharField(max_length=255)
    task_text = models.TextField()  # Основной текст задачи
    task_description = models.TextField()  # Текст самого задания
    reference_markup = models.JSONField(default=list, blank=True)  # Эталон раскраски
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class TaskQuestion(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name="questions")
    text = models.TextField()
    is_correct = models.BooleanField(default=False)  # Релевантен ли вопрос задаче

    def __str__(self):
        return f"Q: {self.text[:50]}"


class TaskFinalOption(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name="final_options")
    text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)  # Является ли этот вариант правильным

    def __str__(self):
        return self.text


class Student(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=100)
    surname = models.CharField(max_length=100)
    group = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.surname} {self.name}"


class Submission(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    student = models.ForeignKey(Student, on_delete=models.CASCADE)

    # Ответы студента
    answer_markup = models.JSONField(default=list)
    selected_question_ids = models.JSONField(default=list)  # Массив ID выбранных вопросов
    selected_final_option_id = models.IntegerField(null=True)  # ID выбранного финала

    # Расчитанные баллы
    score_markup = models.FloatField(default=0.0)  # За раскраску
    score_questions = models.FloatField(default=0.0)  # За выбор вопросов чат-бота
    score_final = models.FloatField(default=0.0)  # За итоговый выбор
    total_score = models.FloatField(default=0.0)  # Средний балл

    created_at = models.DateTimeField(auto_now_add=True)