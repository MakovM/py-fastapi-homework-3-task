from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import UserModel, UserGroupEnum, UserGroupModel, ActivationTokenModel
from security.passwords import hash_password


async def get_user_by_email(db: AsyncSession, email: str):
    stmt = select(UserModel).where(UserModel.email == email)
    user = await db.scalar(stmt)

    return user


async def create_user(db: AsyncSession, user):
    try:
        user_group_stmt = select(UserGroupModel.id).where(UserGroupModel.name == UserGroupEnum.USER.value)
        user_group_id = await db.scalar(user_group_stmt)

        hashed = hash_password(user.password)
        db_user = UserModel(
            email=user.email,
            _hashed_password=hashed,
            group_id=user_group_id
        )

        db.add(db_user)
        await db.flush()

        user_token = ActivationTokenModel(user=db_user)
        db.add(user_token)

        await db.commit()
        await db.refresh(db_user)

        return db_user

    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")
