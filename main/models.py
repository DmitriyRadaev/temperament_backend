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
    # Поля, обязательные при создании суперюзера через консоль (кроме email и пароля)
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