from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict, field_serializer


class UserBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    email: str = Field(..., min_length=3, max_length=255)


class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=100)


class UserUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    current_password: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=6, max_length=100)


class UserResponse(UserBase):
    id: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("created_at")
    def serialize_created_at(self, dt: datetime, _info):
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
