from rest_framework import serializers, generics
from django.contrib.auth import get_user_model
from .models import (
    StudentProfile
)


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