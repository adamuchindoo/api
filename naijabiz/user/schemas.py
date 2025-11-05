# user/schemas.py
from ninja import Schema
from pydantic import Field
from typing import Optional, List, Any
from uuid import UUID
from pydantic import validator, root_validator
from .schema_helper import phone_number_validation, business_name


class UserOut(Schema):
    id: int
    username: str
    email: str
    role: str
    phone: Optional[str] = None
    is_verified: bool
    is_active: bool


class UserRegister(Schema):
    phone: Optional[str] = None
    email: str
    password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)


class UserLogin(Schema):
    email: str
    password: str


class SetNewPassword(Schema):
    password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)


class Error_out(Schema):
    status: str
    message: str


class Login_Out(Schema):
    first_name: str
    surname: str
    last_name: str
    role: str
    gender: str


class Login_response(Schema):
    status: str
    message: Login_Out


class ErrorResponse(Schema):
    success: bool
    message: str
    error_code: Optional[str] = None
    data: Optional[None] = None


class Region_in(Schema):
    id: int
    name: str


class Region(Schema):
    id: int
    name: str


class RegionListResponse(Schema):
    success: bool
    message: str
    data: List[Region]


class BulkRegionRequest(Schema):
    names: List[str]


class BulkStateRequest(Schema):
    region_id: int
    names: List[str]


class StateSchema(Schema):
    id: int
    region: str
    name: str


class StateListResponse(Schema):
    success: bool
    message: str
    data: List[StateSchema]


class Update_state_Schema(Schema):
    state_id: str
    region_id: Optional[int] = None
    name: Optional[str] = None


class BulkLGSRequest(Schema):
    state_id: int
    names: List[str]


class LgaSchema(Schema):
    id: int
    region: str
    state: str
    name: str

    class Config:
        orm_mode = True


class LGAListResponse(Schema):
    success: bool
    message: str
    data: List[LgaSchema]


class Update_lga_Schema(Schema):
    lga_id: str
    state_id: Optional[int] = None
    name: Optional[str] = None


class AccountInfoSchema(Schema):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    other_name: Optional[str] = None
    contact_addrss: Optional[str] = None
    username: str
    email: Optional[str] = None
    role: str
    phone: Optional[str] = None
    region: Optional[str] = None
    state: Optional[str] = None
    lga: Optional[str] = None
    account_status: bool


class APIResponse(Schema):
    success: bool
    message: str
    data: Any


class Bushiness_profile_Schema(Schema):
    business_name: str
    category_id: UUID
    business_phone_number: str
    aditional_phone_number: Optional[str]
    business_address: str
    region_id: int
    state_id: int
    lga_id: int
    market_region_id: UUID
    website: Optional[str]
    cac_registration_number: str
    tax_identification_number: str
    owner_full_name: str
    nin_number: str
    address: str

    _validate_business_phone = validator("business_phone_number", allow_reuse=True)(
        phone_number_validation
    )
    _aditional_phone_number = validator("aditional_phone_number", allow_reuse=True)(
        phone_number_validation
    )
    _business_name = validator("business_name", allow_reuse=True)(business_name)


class Professional_profile_Schema(Schema):
    full_name: str
    short_bio: str
    years_of_experiance: str
    expertise_area_id: str
    website: Optional[str]
    certification_reg_no: str
    tax_identification_number: str
