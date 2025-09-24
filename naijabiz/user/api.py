from ninja import NinjaAPI
from django.http import HttpRequest
from .auth import get_current_user, validate_crftoken
from .models import User as users, RefreshSession, User, Region, State, LGA
from ninja import Router, Query
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse
from typing import List
from ninja.errors import HttpError
from .utils.token_hash import hash_token
from django.utils.timezone import now
from .utils.store_session import store_refresh_session
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Prefetch
from .utils.utils import send_verification_email
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from .tokens import account_activation_token
from .schemas import (
    UserLogin,
    Error_out,
    Login_response,
    UserOut,
    UserRegister,
    UserLogin,
    ErrorResponse,
    RegionListResponse,
    BulkRegionRequest,
    Region as region_in,
    BulkStateRequest,
    StateListResponse,
    Update_state_Schema,
    BulkLGSRequest,
    LGAListResponse,
    Update_lga_Schema,
    AccountInfoSchema
)

from .utils.jwt import create_access_token, create_refresh_token, decode_token
from .utils.csrf import generate_csrf_token

router = Router(tags=["API web version"])


@router.post(
    "/region/bulk",
    response={200: RegionListResponse, 403: ErrorResponse},
    tags=["Admin Administrative Divisions (web)"],
)
def bulk_create_regions(request, payload_in: BulkRegionRequest):
    user_id = get_current_user(request)
    try:
        user = users.objects.get(Q(id=user_id) & (Q(role="admin") | Q(role="manager")))
    except users.DoesNotExist:
        return 403, ErrorResponse(
            success=False, message="Permission denied", error_code="403", data=None
        )

    if validate_crftoken(request, user.csrf_token):
        pass
    existing = Region.objects.filter(name__in=payload_in.names)
    existing_names = set(existing.values_list("name", flat=True))
    new_region = [
        Region(name=name) for name in payload_in.names if name not in existing_names
    ]
    created = Region.objects.bulk_create(new_region)
    created_data = [{"id": r.id, "name": r.name} for r in created]
    return 200, RegionListResponse(
        success=True, message="Regions added successfully", data=created_data
    )


@router.get(
    "/region",
    response={200: RegionListResponse, 404: ErrorResponse},
    tags=["Admin Administrative Divisions (web)"],
)
def get_regions(request):
    user_id = get_current_user(request)
    try:
        user = users.objects.get(Q(id=user_id) & (Q(role="admin")))
    except users.DoesNotExist:
        return 404, ErrorResponse(
            success=False, message="Permission denied", error_code="403", data=None
        )
        # return JsonResponse({"message": "User not found"}, status=404)

    regions = Region.objects.all()

    region_list = []
    for region in regions:
        region_list.append(
            {
                "id": region.id,
                "name": region.name,
                # add other fields if needed
            }
        )
    return 200, RegionListResponse(
        success=True, message="Regions fetched successfully", data=region_list
    )


@router.put(
    "/region",
    response={200: RegionListResponse, 404: ErrorResponse},
    tags=["Admin Administrative Divisions (web)"],
)
def update_region(request, payload: region_in):
    user_id = get_current_user(request)
    try:
        user = users.objects.get(Q(id=user_id) & (Q(role="admin") | Q(role="manager")))
    except users.DoesNotExist:
        return 404, ErrorResponse(
            success=False, message="Permission denied", error_code="403", data=None
        )
    if validate_crftoken(request, user.csrf_token):
        pass
    region = get_object_or_404(Region, id=payload.id)
    region.name = payload.name
    region.save()

    region_data = [{"id": region.id, "name": region.name}]
    return 200, RegionListResponse(
        success=True, message="Regions updated successfully", data=region_data
    )


# state section
@router.post(
    "/state/bulk",
    response={200: RegionListResponse, 403: ErrorResponse},
    tags=["Admin Administrative Divisions (web)"],
)
def bulk_create_state(request, payload: BulkStateRequest):
    user_id = get_current_user(request)
    try:
        user = users.objects.get(Q(id=user_id) & (Q(role="admin") | Q(role="manager")))
    except users.DoesNotExist:
        return 403, ErrorResponse(
            success=False, message="Permission denied", error_code="403", data=None
        )

    if validate_crftoken(request, user.csrf_token):
        pass
    region = get_object_or_404(Region, id=payload.region_id)
    existing = State.objects.filter(region=region, name__in=payload.names)
    existing_names = set(existing.values_list("name", flat=True))
    new_region = [
        State(region=region, name=name)
        for name in payload.names
        if name not in existing_names
    ]
    created = State.objects.bulk_create(new_region)
    created_data = [{"id": r.id, "name": r.name} for r in created]
    return 200, RegionListResponse(
        success=True, message="State added successfully", data=created_data
    )


@router.get(
    "/state",
    response={200: StateListResponse, 404: ErrorResponse},
    tags=["Admin Administrative Divisions (web)"],
)
def get_state(request):
    user_id = get_current_user(request)
    try:
        user = users.objects.get(Q(id=user_id) & (Q(role="admin") | Q(role="manager")))
    except users.DoesNotExist:
        return 404, ErrorResponse(
            success=False, message="Permission denied", error_code="403", data=None
        )
    states = State.objects.select_related("region").all()

    state_list = []
    for state in states:
        state_list.append(
            {
                "id": state.id,
                "region": state.region.name,
                "name": state.name,
            }
        )
    return 200, StateListResponse(
        success=True, message="States fetched successfully", data=state_list
    )


@router.put(
    "/state",
    response={200: StateListResponse, 404: ErrorResponse},
    tags=["Admin Administrative Divisions (web)"],
)
def update_state(request, payload: Update_state_Schema):
    user_id = get_current_user(request)
    try:
        user = users.objects.get(Q(id=user_id) & (Q(role="admin") | Q(role="manager")))
    except users.DoesNotExist:
        return 404, ErrorResponse(
            success=False, message="Permission denied", error_code="403", data=None
        )
    if validate_crftoken(request, user.csrf_token):
        pass
    state = get_object_or_404(State, id=payload.state_id)
    if payload.region_id is not None:
        region = get_object_or_404(Region, id=payload.region_id)
        state.region = region
    if payload.name is not None:
        state.name = payload.name
    state.save()

    state_data = [{"id": state.id, "region": state.region.name, "name": state.name}]
    return 200, StateListResponse(
        success=True, message="State updated successfully", data=state_data
    )


# lga section
@router.post(
    "/lga",
    response={200: RegionListResponse, 403: ErrorResponse},
    tags=["Admin Administrative Divisions (web)"],
)
def bulk_create_lga(request, payload: BulkLGSRequest):
    user_id = get_current_user(request)
    try:
        user = users.objects.get(Q(id=user_id) & (Q(role="admin") | Q(role="manager")))
    except users.DoesNotExist:
        return 403, ErrorResponse(
            success=False, message="Permission denied", error_code="403", data=None
        )

    if validate_crftoken(request, user.csrf_token):
        pass
    state = get_object_or_404(State, id=payload.state_id)
    existing = LGA.objects.filter(state=state, name__in=payload.names)
    existing_names = set(existing.values_list("name", flat=True))
    new_region = [
        LGA(state=state, name=name)
        for name in payload.names
        if name not in existing_names
    ]
    created = LGA.objects.bulk_create(new_region)
    created_data = [{"id": r.id, "name": r.name} for r in created]
    return 200, RegionListResponse(
        success=True, message="LGA added successfully", data=created_data
    )


@router.get(
    "/lga/{state_id}",
    response={200: LGAListResponse, 404: ErrorResponse},
    tags=["Admin Administrative Divisions (web)"],
)
def get_lg(request, state_id: int):
    user_id = get_current_user(request)
    try:
        user = users.objects.get(Q(id=user_id) & (Q(role="admin") | Q(role="manager")))
    except users.DoesNotExist:
        return 404, ErrorResponse(
            success=False, message="Permission denied", error_code="403", data=None
        )
    state = get_object_or_404(State.objects.select_related("region"), id=state_id)
    lga = LGA.objects.filter(state=state).select_related("state__region")

    lga_list = []
    for lga in lga:
        lga_list.append(
            {
                "id": lga.id,
                "region": lga.state.region.name,
                "state": lga.state.name,
                "name": lga.name,
            }
        )
    return 200, LGAListResponse(
        success=True, message="LGA fetched successfully", data=lga_list
    )


@router.put(
    "/lga",
    response={200: LGAListResponse, 404: ErrorResponse},
    tags=["Admin Administrative Divisions (web)"],
)
def update_lga(request, payload: Update_lga_Schema):
    user_id = get_current_user(request)
    try:
        user = users.objects.get(Q(id=user_id) & (Q(role="admin") | Q(role="manager")))
    except users.DoesNotExist:
        return 404, ErrorResponse(
            success=False, message="Permission denied", error_code="403", data=None
        )
    if validate_crftoken(request, user.csrf_token):
        pass
    lga = get_object_or_404(
        LGA.objects.select_related("state__region"), id=payload.lga_id
    )
    if payload.state_id is not None:
        state = get_object_or_404(State, id=payload.state_id)
        lga.state = state
    if payload.name is not None:
        lga.name = payload.name
    lga.save()

    lga_data = [
        {
            "id": lga.id,
            "region": lga.state.region.name,
            "state": lga.state.name,
            "name": lga.name,
        }
    ]
    return 200, LGAListResponse(
        success=True, message="LGA updated successfully", data=lga_data
    )


# ------------------ REGISTER ------------------
@router.post(
    "/register",
    response={201: UserOut, 400: dict},
    auth=None,
    tags=["Web Authentication"],
)
def register(request: HttpRequest, data: UserRegister):
    if data.password != data.confirm_password:
        return 400, {"message": "Passwords do not match"}

    if User.objects.filter(email=data.email).exists():
        return 400, {"message": "Email already registered"}

    if User.objects.filter(username=data.username).exists():
        return 400, {"message": "Username already taken"}

    lga = get_object_or_404(
        LGA.objects.select_related("state__region"),
        id=data.lga_id
    )
    if str(lga.state.id) != data.state_id:
        return JsonResponse({"message": f"LGA does not belong to the given State st-{lga.state.id}"}, status=404)

    state = lga.state
    region = state.region
    
    user = User.objects.create_user(
        username=data.username,
        email=data.email,
        password=data.password,
        role=data.role,
        phone=data.phone,
        region=region,
        state = state,
        lga = lga,
        first_name =data.first_name,
        last_name =data.last_name,
        other_name =data.other_name,
        contact_address = data.contact_address,
        is_active=False,  # Wait for email verification
    )
    return JsonResponse({"message": f"Account created successfully"}, status=200)

    
# ------------------ VERIFY EMAIL ------------------
@router.get(
    "/verify-email/{uidb64}/{token}/",
    response={200: dict, 400: dict},
    tags=["Web Authentication"],
)
def verify_email(request: HttpRequest, uidb64: str, token: str):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_object_or_404(User, pk=uid)
    except Exception:
        return 400, {"message": "Invalid verification link"}

    if account_activation_token.check_token(user, token):
        user.is_verified = True
        user.is_active = True
        user.save()
        return 200, {"message": "Email verified successfully. You can now log in."}
    else:
        return 400, {"message": "Invalid or expired token"}


# --- LOGIN ---
@router.post(
    "/login", response={401: Error_out}, auth=None, tags=["Web Authentication"]
)
def login(request, data: UserLogin):
    try:
        user = users.objects.get(email=data.email)
    except users.DoesNotExist:
        return 401, Error_out(status="Error", message="Invalid credentials")

    if not check_password(data.password, user.password):
        return 401, Error_out(status="Error", message="Invalid credentials")

    # Generate tokens
    access_token = create_access_token({"sub": str(user.id)})
    refresh_token = create_refresh_token({"sub": str(user.id)})
    csrf_token = generate_csrf_token()  # just a random string
    RefreshSession.objects.filter(user=user, is_active=True).update(is_active=False)
    store_refresh_session(user, refresh_token, request)

    # update csrftoken
    user.csrf_token = csrf_token
    user.save()
    # Prepare response
    response = JsonResponse({"status": "Success", "message": f"Login successful"})

    # Access token cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="None",
        path="/",
        max_age=900,  # 15 minutes
    )

    # Refresh token cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="None",
        path="/api/auth/refresh-token",
        max_age=7 * 24 * 60 * 60,  # 7 days
    )

    # CSRF token (readable by JavaScript)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=True,
        samesite="Lax",
        path="/",
        max_age=900,  # Match access token lifespan
    )

    return response


@router.get("/profile", response={200:AccountInfoSchema}, tags=["Account managemeent info (web)"])
def profile(request):
    user_id = get_current_user(request)
    user = get_object_or_404(User.objects.select_related("region","state", "lga"), pk=user_id)
    return 200,AccountInfoSchema(
        first_name=user.first_name if user.first_name else None,
        last_name=user.last_name if user.last_name else None,
        other_name=user.other_name if user.other_name else None,
        contact_addrss=user.contact_address if user.contact_address else None,
        username=user.username,
        email=user.email if user.email else None,
        role=user.role ,
        phone=user.phone if user.email else None,
        region=user.region.name if user.region else None, 
        state=user.state.name if user.state else None,
        lga=user.lga.name if user.lga else None,
        account_status=user.is_active
    )



@router.post("/refresh-token", tags=["Web Authentication"])
def refresh_token(request):
    token = request.COOKIES.get("refresh_token")
    if not token:
        raise HttpError(401, f"No refresh token")

    try:
        payload = decode_token(token)
    except Exception:
        raise HttpError(401, "Invalid refresh token")

    new_access = create_access_token({"sub": payload["sub"]})
    csrf_token = generate_csrf_token()
    new_refresh = create_refresh_token({"sub": payload["sub"]})
    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    token_hash = hash_token(token)

    try:
        session = RefreshSession.objects.select_related("user").get(
            token_hash=token_hash, is_active=True
        )
    except RefreshSession.DoesNotExist:
        raise HttpError(401, f"Token reuse or invalid session")
    if session.expires_at < now():
        raise HttpError(401, "Refresh token expired")

    # Invalidate old session
    session.is_active = False
    session.save()

    user = session.user
    user.csrf_token = csrf_token
    user.save()
    # Save new session
    store_refresh_session(session.user, new_refresh, request)
    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>.
    response = JsonResponse({"message": "Token refreshed"})
    response.set_cookie(
        "refresh_token",
        new_refresh,
        httponly=True,
        secure=True,
        samesite="None",
        path="/api/auth/refresh-token",
        max_age=604800,
    )

    response.set_cookie(
        "access_token",
        new_access,
        httponly=True,
        secure=True,
        samesite="None",
        path="/",
    )

    response.set_cookie(
        "csrf_token", csrf_token, httponly=False, secure=True, samesite="None", path="/"
    )

    return response


@router.post("/signout", tags=["Web Authentication"])
def signout(request):
    # Get refresh token from cookie
    token = request.COOKIES.get("refresh_token")

    if token:
        # Hash the token to find session
        token_hash = hash_token(token)

        # Try to find and invalidate session in DB
        try:
            session = RefreshSession.objects.get(token_hash=token_hash, is_active=True)
            session.is_active = False
            session.save()
        except RefreshSession.DoesNotExist:
            pass  # Session already invalid or doesn't exist

    response = JsonResponse({"message": "Signed out successfully"})

    # Delete refresh token cookie by setting it to expired
    response.delete_cookie("refresh_token", path="/")  # match your cookie path

    # Also delete access token cookie
    response.delete_cookie("access_token", path="/")

    # Delete CSRF token cookie if applicable
    response.delete_cookie("csrf_token", path="/")

    return response
