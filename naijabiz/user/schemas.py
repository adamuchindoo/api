# user/schemas.py
from ninja import Schema
from pydantic import Field
from typing import Optional, List


class UserOut(Schema):
    id: int
    username: str
    email: str
    role: str
    phone: Optional[str] = None
    is_verified: bool
    is_active: bool


class UserRegister(Schema):
    username: str
    email: str
    password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)
    role: str = "b2c"
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    other_name: Optional[str] = None
    phone: Optional[str] = None
    state_id: Optional[str] = None
    lga_id: Optional[str] = None
    contact_address: Optional[str] = None


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
    first_name: Optional[str]=None
    last_name:  Optional[str]=None
    other_name:  Optional[str]=None
    contact_addrss:  Optional[str]=None
    username: str
    email:  Optional[str]=None
    role: str
    phone:  Optional[str]=None
    region: Optional[str]=None
    state:  Optional[str]=None
    lga:  Optional[str]=None
    account_status: bool
    