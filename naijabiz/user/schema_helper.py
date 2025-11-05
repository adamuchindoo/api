def phone_number_validation(v: str) -> str:
    if len(v) != 11 or not v.isdigit():
        raise ValueError("Phone number must be exactly 11 digits")
    return v


def business_name(v: str) -> str:
    if len(v) > 100:
        raise ValueError("Business name  length must lessthan 100")
    return v
