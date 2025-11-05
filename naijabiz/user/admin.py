# user/admin.py
from django.contrib import admin
from .models import (
    User,
    EmailValidation,
    Business_categories,
    Market_region,
    Business_profile,
    Region,
    State,
    LGA,
    Expertise_area,
    Professional_profile,
    User_role,
)


@admin.register(User_role)
class User_roleAdmin(admin.ModelAdmin):
    list_display = [field.name for field in User_role._meta.fields]


@admin.register(Professional_profile)
class Professional_profileAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Professional_profile._meta.fields]


@admin.register(Expertise_area)
class Expertise_areaAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Expertise_area._meta.fields]


@admin.register(Region)
class RegionAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Region._meta.fields]


@admin.register(State)
class StateAdmin(admin.ModelAdmin):
    list_display = [field.name for field in State._meta.fields]


@admin.register(LGA)
class LGAAdmin(admin.ModelAdmin):
    list_display = [field.name for field in LGA._meta.fields]


@admin.register(EmailValidation)
class EmailValidationAdmin(admin.ModelAdmin):
    list_display = [field.name for field in EmailValidation._meta.fields]


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = [field.name for field in User._meta.fields]


@admin.register(Business_categories)
class Business_categoriesAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Business_categories._meta.fields]


@admin.register(Market_region)
class Market_regionAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Market_region._meta.fields]


@admin.register(Business_profile)
class Business_profileAdmin(admin.ModelAdmin):
    list_display = [field.name for field in Business_profile._meta.fields]
