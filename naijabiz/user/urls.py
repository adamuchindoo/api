# user/urls.py
from django.urls import path, redirect
from ninja import NinjaAPI

from .views import router

api = NinjaAPI(title="User API", version="1.0")
api.add_router("", router)

urlpatterns = [
    path("", lambda request: redirect("/api/docs")),  # ← Redirect root to docs
    path("", api.urls),  # API routes: /api/docs, /api/openapi.json, etc.
]