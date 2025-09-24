from django.contrib import admin
from django.urls import path
from ninja import NinjaAPI
from user.api import router

api = NinjaAPI(
    title="NaijaBiz",
    version="1.0",
    description="API documentation",
    docs_url="/docs",  # Swagger UI (enabled by default)
    openapi_url="/openapi.json",  # Required for documentation to work
)

api.add_router("/auth/", router)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
]
