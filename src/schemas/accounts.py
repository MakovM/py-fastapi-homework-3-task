from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class PasswordValidator:
    @classmethod
    def validate(cls, password: str) -> str:
        special_chars = "@$!%*?#&"
        if len(password) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        elif not any(el.isupper() for el in password):
            raise ValueError("Password must contain at least one uppercase letter.")
        elif not any(el.islower() for el in password):
            raise ValueError("Password must contain at least one lower letter.")
        elif not any(el.isdigit() for el in password):
            raise ValueError("Password must contain at least one digit.")
        elif not any(el in special_chars for el in password):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )
        return password


class AccountsErrorSchema(BaseModel):
    description: str


class UserBaseSchema(BaseModel):
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str

    model_config = ConfigDict(from_attributes=True)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return PasswordValidator.validate(value)


class UserRegistrationResponseSchema(UserBaseSchema):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(UserBaseSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBaseSchema):
    pass


class PasswordResetCompleteRequestSchema(UserBaseSchema):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return PasswordValidator.validate(value)


class UserLoginRequestSchema(UserBaseSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
