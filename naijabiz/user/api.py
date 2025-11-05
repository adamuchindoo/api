from ninja import NinjaAPI
from django.http import HttpRequest
from datetime import datetime, timedelta
import random
from ninja.files import UploadedFile
from ninja import File
from django.core.mail import send_mail
from .auth import get_current_user, validate_crftoken
from .models import (
    User as users,
    RefreshSession,
    User,
    Region,
    State,
    LGA,
    EmailValidation,
    Business_profile,
    Business_categories,
    Market_region,
    Expertise_area,
    Professional_profile,
    User_role,
)
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
from .helper import generate_unique_username, save_uploaded_file
from .schemas import (
    UserLogin,
    Error_out,
    APIResponse,
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
    AccountInfoSchema,
    Bushiness_profile_Schema,
    Professional_profile_Schema,
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
    tags=["Create account (Web)"],
)
def register(request: HttpRequest, data: UserRegister):
    if data.password != data.confirm_password:
        return 400, {"message": "Passwords do not match"}

    if User.objects.filter(email=data.email).exists():
        return 400, {"message": "Email already registered"}
    role = get_object_or_404(User_role, code="b2c")

    user = User.objects.create_user(
        username=generate_unique_username(),
        email=data.email,
        password=data.password,
        phone=data.phone,
        role=role,
        is_active=False,  # Wait for email verification
    )
    return JsonResponse({"message": f"Account created successfully"}, status=200)


@router.get(
    "/request-email-validation",
    tags=["Create account (Web)"],
    response={400: dict, 200: APIResponse},
)
def new_user_email_validation_request(request):
    user_id = get_current_user(request)
    user = get_object_or_404(User.objects, pk=user_id)

    if user.is_verified:
        return 200, APIResponse(
            success=True,
            message="Email already verifed",
            data="Your email has already been verified.",
        )
    # Delete existing unused OTPs for this user
    EmailValidation.objects.filter(email=user.email).delete()
    otp_code = str(random.randint(100000, 999999))
    expires_at = datetime.now() + timedelta(minutes=15)
    EmailValidation.objects.create(
        email=user.email, code=otp_code, expires_at=expires_at
    )
    send_mail(
        "Email Validation OTP",
        f"Your OTP for E-mail validation is: {otp_code} (valid for 15 minutes)",
        "noreply@example.com",
        [user.email],
        fail_silently=False,
    )
    more_details = {"note": "Please check your email — we have sent you an OTP"}
    return 200, APIResponse(
        success=True, message="Otp send successfully", data=more_details
    )


@router.get("/email-validate/{otp}", tags=["Create account (Web)"])
def email_validations(request, otp: int):
    user_id = get_current_user(request)
    user = get_object_or_404(User.objects, pk=user_id)
    try:
        otp_record = EmailValidation.objects.get(
            email=user.email,
            code=otp,
            is_used=False,
            expires_at__gte=datetime.now(),
        )
    except EmailValidation.DoesNotExist:
        return JsonResponse({"detail": "Invalid OTP or Email"}, status=400)

    # Mark OTP as used
    otp_record.is_used = True
    otp_record.save()

    user.is_verified = True
    user.save()

    return {"detail": "Your email has been successfully verified."}


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
        samesite="None",
        path="/",
        max_age=900,  # Match access token lifespan
    )

    return response


@router.post(
    "/create-business-profile",
    response={200: APIResponse, 400: APIResponse, 403: APIResponse},
    tags=["User Roles (web)"],
)
def create_business_profile(
    request,
    payload: Bushiness_profile_Schema,
    cac_certificate: UploadedFile = File(...),
    trade_license: UploadedFile = File(...),
):
    user_id = get_current_user(request)
    user = get_object_or_404(User.objects, pk=user_id)
    if not user.email:
        more_details = {
            "details": "Email not verified. Please check your inbox for the verification link."
        }
        return 403, APIResponse(
            success=True, message="EMAIL_NOT_VERIFIED", data=more_details
        )
    region = get_object_or_404(Region, id=payload.region_id)
    state = get_object_or_404(State, id=payload.state_id, region=region)
    lga = get_object_or_404(LGA, id=payload.lga_id, state=state)
    business_category = get_object_or_404(Business_categories, id=payload.category_id)
    market_region = get_object_or_404(Market_region, id=payload.market_region_id)

    try:
        # Save the uploaded CAC certificate
        cac_file_path = save_uploaded_file(cac_certificate, "cac_certificates")

        # Save the uploaded logo (if provided)
        trade_license_path = save_uploaded_file(trade_license, "trade_license")

    except Exception as e:
        # Handle file upload errors gracefully
        return 400, {"status": "Error", "message": f"Failed to upload files: {str(e)}"}

    business_profile = Business_profile.objects.create(
        user=user,
        business_name=payload.business_name,
        category=business_category,
        business_phone_number=payload.business_phone_number,
        aditional_phone_number=payload.aditional_phone_number,
        business_address=payload.business_address,
        region=region,
        state=state,
        lga=lga,
        market_region=market_region,
        website=payload.website,
        cac_registration_number=payload.cac_registration_number,
        cac_file=cac_file_path,
        trade_license=trade_license_path,
        tax_identification_number=payload.tax_identification_number,
        owner_full_name=payload.owner_full_name,
        nin_number=payload.nin_number,
        address=payload.address,
    )
    return 200, APIResponse(
        success=True, message=f"Business profile submit successfully", data="done"
    )


@router.post(
    "/create-professional-profile",
    response={200: APIResponse, 400: APIResponse, 403: APIResponse},
    tags=["User Roles (web)"],
)
def create_professional_profile(
    request,
    payload: Professional_profile_Schema,
    certificate: UploadedFile = File(...),
):
    user_id = get_current_user(request)
    user = get_object_or_404(User.objects, pk=user_id)
    if not user.email:
        more_details = {
            "details": "Email not verified. Please check your inbox for the verification link."
        }
        return 403, APIResponse(
            success=True, message="EMAIL_NOT_VERIFIED", data=more_details
        )

    expertise_area = get_object_or_404(Expertise_area, id=payload.expertise_area_id)

    try:
        certificate_file_path = save_uploaded_file(
            certificate, "professional_certificates"
        )
    except Exception as e:
        return 400, {"status": "Error", "message": f"Failed to upload files: {str(e)}"}

    professional_profile = Professional_profile.objects.create(
        user=user,
        full_name=payload.full_name,
        short_bio=payload.short_bio,
        years_of_experiance=payload.years_of_experiance,
        expertise_area=expertise_area,
        website=payload.website,
        certification_reg_no=payload.certification_reg_no,
        tax_identification_number=payload.tax_identification_number,
        certificate_file=certificate_file_path,
    )
    return 200, APIResponse(
        success=True, message=f"Professional profile submit successfully", data="done"
    )


@router.get(
    "/profile",
    response={200: AccountInfoSchema},
    tags=["Account managemeent info (web)"],
)
def profile(request):
    user_id = get_current_user(request)
    user = get_object_or_404(
        User.objects.select_related("region", "state", "lga"), pk=user_id
    )
    return 200, AccountInfoSchema(
        first_name=user.first_name if user.first_name else None,
        last_name=user.last_name if user.last_name else None,
        other_name=user.other_name if user.other_name else None,
        contact_addrss=user.contact_address if user.contact_address else None,
        username=user.username,
        email=user.email if user.email else None,
        role=user.role.name,
        phone=user.phone if user.email else None,
        region=user.region.name if user.region else None,
        state=user.state.name if user.state else None,
        lga=user.lga.name if user.lga else None,
        account_status=user.is_active,
    )


@router.get(
    "/get-all-profile/",
    response={200: APIResponse},
    tags=["User Roles (web)"],
)
def get_all_profile(request):
    user_id = get_current_user(request)
    user = get_object_or_404(User.objects.prefetch_related('professional_user','b2b'), pk=user_id)
    profile_list = []
    profile_list.append(
        {
             "id":"b2c",
             "name":"Consumer"
        }
     )
    try:
     professional = user.professional_user
     profile_list.append(
        {
             "id":professional.id,
             "name":professional.role.name
        }
     )
    except Professional_profile.DoesNotExist:
     pass
 
    try:
     business_profile = user.b2b
     profile_list.append(
        {
             "id":business_profile.id,
             "name":business_profile.role.name
        }
     )
    except Business_profile.DoesNotExist:
     pass
    return 200, APIResponse(
        success=True, message=f"Professional profile submit successfully", data=profile_list
    )
    
@router.get(
    "/switch-profile/{role_id}",
    response={200: APIResponse},
    tags=["User Roles (web)"],
)
def profile_switch(request,role_id: str):
    user_id = get_current_user(request)
    user = get_object_or_404(User.objects.prefetch_related('professional_user','b2b'), pk=user_id)
  
    if hasattr(user, 'professional_user') and str(user.professional_user.id) == role_id:
        professional_profile_profile = get_object_or_404(Professional_profile, id=role_id)
        user.role = professional_profile_profile.role
        user.save(update_fields=['role'])
        return APIResponse(
            success=True,
            message="Professional profile submit successfully",
            data="Yes, professional profile"
        )

    elif hasattr(user, 'b2b') and str(user.b2b.id) == role_id:
        business_profile = get_object_or_404(Business_profile, id=role_id)
        user.role = business_profile.role
        user.save(update_fields=['role'])
        return APIResponse(
            success=True,
            message="Business profile submit successfully",
            data="Yes, business profile"
        )  
    else:
       return 200, APIResponse(
        success=True, message=f"Professional profile submit successfully", data="No No"
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
