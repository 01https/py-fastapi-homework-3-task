from datetime import datetime, timezone, timedelta
from typing import cast
from uuid import uuid4

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from jose.exceptions import ExpiredSignatureError
from exceptions.security import TokenExpiredError
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from starlette.status import HTTP_403_FORBIDDEN

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def create_user(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        hashed = hash_password(user.password)
        group_id = 1
        db_user = UserModel(email=str(user.email), _hashed_password=hashed, group_id=group_id)

        USER_EXISTS_QUERY = await db.execute(select(UserModel).where(UserModel.email == user.email))
        USER_EXISTS_SCALAR = USER_EXISTS_QUERY.scalar_one_or_none()

        if USER_EXISTS_SCALAR:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user.email} already exists."
            )

        db.add(db_user)
        await db.flush()

        token = str(uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        activation_token = ActivationTokenModel(token=token, expires_at=expires_at, user_id=db_user.id)

        db.add(activation_token)

        await db.commit()
        await db.refresh(db_user)
        return {"id": db_user.id, "email": db_user.email}

    except HTTPException as e:
        await db.rollback()
        raise e

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=200)
async def activate_user_account(user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(UserModel)
        .options(
            joinedload(UserModel.activation_token)
        )
        .where(UserModel.email == user.email)
    )
    result = await db.execute(stmt)
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User should exist in the database."
        )

    if db_user and db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    if not db_user.activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, db_user.activation_token.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    await db.delete(db_user.activation_token)
    await db.commit()
    await db.refresh(db_user)
    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK
)
async def reset_password(user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        stmt = (
            select(UserModel)
            .options(
                joinedload(UserModel.password_reset_token)
            )
            .where(UserModel.email == user.email)
        )
        result = await db.execute(stmt)
        db_user = result.scalar_one_or_none()

        if not db_user or not db_user.is_active:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": "If you are registered, you will receive an email with instructions."}
            )

        if db_user and db_user.password_reset_token:
            await db.delete(db_user.password_reset_token)
            await db.commit()
            await db.refresh(db_user)

        token = str(uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        reset_password_token = PasswordResetTokenModel(token=token, expires_at=expires_at, user_id=db_user.id)

        db.add(reset_password_token)

        await db.commit()
        await db.refresh(db_user)

        return {"message": "If you are registered, you will receive an email with instructions."}

    except SQLAlchemyError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error")


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        stmt = (
            select(UserModel)
            .options(
                joinedload(UserModel.password_reset_token)
            )
            .where(UserModel.email == user.email)
        )
        result = await db.execute(stmt)
        db_user = result.scalar_one_or_none()

        if not db_user or not db_user.email or not db_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        if not db_user.password_reset_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        expires_at = cast(datetime, db_user.password_reset_token.expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= datetime.now(timezone.utc) or db_user.password_reset_token.token != user.token:
            await db.delete(db_user.password_reset_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        db_user._hashed_password = hash_password(user.password)

        await db.delete(db_user.password_reset_token)
        await db.commit()
        await db.refresh(db_user)

        return {"message": "Password reset successfully."}

    except HTTPException as e:
        await db.rollback()
        raise e

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    try:
        stmt = (
            select(UserModel)
            .where(UserModel.email == login_data.email)
        )
        result = await db.execute(stmt)
        db_user = result.scalar_one_or_none()

        if not db_user or not verify_password(login_data.password, str(db_user._hashed_password)):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

        if not db_user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

        access_token_expires = timedelta(minutes=30)
        refresh_token_expires = timedelta(days=1)

        access_token = jwt_manager.create_access_token(
            data={"sub": db_user.email, "user_id": db_user.id}, expires_delta=access_token_expires
        )
        refresh_token = jwt_manager.create_refresh_token(
            data={"sub": db_user.email, "user_id": db_user.id}, expires_delta=refresh_token_expires
        )

        db.add(RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=1,
            token=refresh_token
        ))

        await db.commit()

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
            },
        )

    except HTTPException as e:
        await db.rollback()
        raise e

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def update_refresh_token(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded = jwt_manager.decode_refresh_token(payload.refresh_token)
        print(decoded)
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token.")

    user_id = decoded.get("user_id")
    user_email = decoded.get("email")

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token)
    result = await db.execute(stmt)
    refresh_token_in_db = result.scalar_one_or_none()

    if not refresh_token_in_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if not user_email:
        access_token = jwt_manager.create_access_token({"user_id": user_id})
    else:
        access_token = jwt_manager.create_access_token({"sub": user_email, "user_id": user_id})

    return {"access_token": access_token}
