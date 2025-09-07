from datetime import datetime, timezone
from fastapi import APIRouter, Form, HTTPException, status, Depends
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError
import bcrypt
from auth.security import auth
from database import SessionDep
from models import User, Role
from schemas import UserCreate, UserResponse, UserLogin, Token, UserUpdate
from auth.security import create_access_token, verify_password
from authx import RequestToken
router = APIRouter(prefix="/users", tags=["Users"])



@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def add_user(user_data: UserCreate, session: SessionDep) -> Token:
    """
    Регистрация нового пользователя
    """
    try:
        # Проверяем существование пользователя с таким email
        result = await session.execute(
            select(User).where(User.email == user_data.email)
        )
        existing_user = result.scalar_one_or_none()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Пользователь с таким email уже существует"
            )

        # Получаем роль "user" по умолчанию
        result = await session.execute(
            select(Role).where(Role.name == "user")
        )
        user_role = result.scalar_one_or_none()

        if not user_role:
            # Если роль не найдена, создаем ее
            user_role = Role(name="user", description="Обычный пользователь")
            session.add(user_role)
            await session.commit()
            await session.refresh(user_role)

        # Хешируем пароль
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(user_data.password.encode('utf-8'), salt).decode('utf-8')

        # Создаем нового пользователя
        new_user = User(
            first_name=user_data.first_name.strip(),
            last_name=user_data.last_name.strip(),
            patronymic=user_data.patronymic.strip() if user_data.patronymic else None,
            email=user_data.email.lower().strip(),
            password_hash=password_hash,
            role_id=user_role.id
        )

        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)

        # Создаем access token
        access_token = create_access_token(
            new_user.email
        )

        # Формируем ответ
        user_response = UserResponse(
            id=new_user.id,
            first_name=new_user.first_name,
            last_name=new_user.last_name,
            patronymic=new_user.patronymic,
            email=new_user.email,
            is_active=new_user.is_active,
            role_id=new_user.role_id,
            role_name=user_role.name,
            created_at=new_user.created_at
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
            user=user_response
        )

    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ошибка при создании пользователя"
        )


@router.post("/login-form")
async def login_form(
        session: SessionDep,
        email: str = Form(...),
        password: str = Form(...),
):
    """
    Логин через форму (формат данных: application/x-www-form-urlencoded)
    """
    try:
        # Ищем пользователя
        result = await session.execute(
            select(User).where(User.email == email)
        )
        user = result.scalar_one_or_none()

        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверные учетные данные"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Аккаунт деактивирован"
            )

        # Получаем информацию о роли
        result = await session.execute(
            select(Role).where(Role.id == user.role_id)
        )
        user_role = result.scalar_one_or_none()

        # Создаем access token
        access_token = create_access_token(
            email
        )

        # Формируем ответ
        user_response = UserResponse(
            id=user.id,
            first_name=user.first_name,
            last_name=user.last_name,
            patronymic=user.patronymic,
            email=user.email,
            is_active=user.is_active,
            role_id=user.role_id,
            role_name=user_role.name if user_role else None,
            created_at=user.created_at
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
            user=user_response
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка при входе: {str(e)}"
        )


@router.post("/login", response_model=Token)
async def login(user_data: UserLogin, session: SessionDep):
    """
    Логин через JSON (формат данных: application/json)
    """
    try:
        # Ищем пользователя
        result = await session.execute(
            select(User).where(User.email == user_data.email)
        )
        user = result.scalar_one_or_none()

        if not user or not verify_password(user_data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверные учетные данные"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Аккаунт деактивирован"
            )

        # Получаем информацию о роли
        result = await session.execute(
            select(Role).where(Role.id == user.role_id)
        )
        user_role = result.scalar_one_or_none()

        # Создаем access token
        access_token = create_access_token(
            user_data.email
        )

        # Формируем ответ
        user_response = UserResponse(
            id=user.id,
            first_name=user.first_name,
            last_name=user.last_name,
            patronymic=user.patronymic,
            email=user.email,
            is_active=user.is_active,
            role_id=user.role_id,
            role_name=user_role.name if user_role else None,
            created_at=user.created_at
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
            user=user_response
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка при входе: {str(e)}"
        )


@router.get("/me", dependencies=[Depends(auth.get_token_from_request)], response_model=UserResponse)
async def get_current_user(
        session: SessionDep,
        token: RequestToken = Depends()
):
    """
    Получение информации о текущем пользователе
    """
    try:
        # Верифицируем токен и получаем email из токена
        email = auth.verify_token(token=token)

        # Получаем текущего пользователя из базы данных по email
        result = await session.execute(
            select(User).where(User.email == email.sub)
        )
        current_user = result.scalar_one_or_none()

        if not current_user:
            raise HTTPException(404, detail={"message": "Пользователь не найден"})

        # Получаем информацию о роли пользователя
        role_result = await session.execute(
            select(Role).where(Role.id == current_user.role_id)
        )
        user_role = role_result.scalar_one_or_none()

        return UserResponse(
            id=current_user.id,
            first_name=current_user.first_name,
            last_name=current_user.last_name,
            patronymic=current_user.patronymic,
            email=current_user.email,
            is_active=current_user.is_active,
            role_id=current_user.role_id,
            role_name=user_role.name if user_role else None,
            created_at=current_user.created_at
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(401, detail={"message": str(e)}) from e


@router.delete("/delete",dependencies=[Depends(auth.get_token_from_request)], response_model=dict)
async def delete_current_user(
        session: SessionDep,
        token: RequestToken = Depends()
) -> dict:
    """
    Мягкое удаление текущего пользователя
    """
    try:
        # Мягкое удаление
        email = auth.verify_token(token=token)
        # Получаем текущего пользователя из базы данных по email
        result = await session.execute(
            select(User).where(User.email == email.sub)
        )
        current_user = result.scalar_one_or_none()

        if not current_user:
            raise HTTPException(404, detail={"message": "Пользователь не найден"})
        current_user.is_active = False
        current_user.deleted_at = datetime.now(timezone.utc)
        await session.commit()

        return {
            "message": "Account deleted successfully",
            "detail": "Your account has been deactivated."
        }
    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting account: {str(e)}"
        )


@router.post("/logout", dependencies=[Depends(auth.get_token_from_request)])
async def logout_current_user(
        session: SessionDep,
        token: RequestToken = Depends()
):
    """
    Выход текущего пользователя из системы
    """
    try:

        email = auth.verify_token(token=token)
        result = await session.execute(
            select(User).where(User.email == email.sub)
        )
        current_user = result.scalar_one_or_none()
        if not current_user:
            raise HTTPException(404, detail={"message": "Пользователь не найден"})

        # Логирование выхода
        print(f"User {current_user.id} logged out successfully")

        return {
            "message": "Logged out successfully",
            "detail": "You have been successfully logged out."
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during logout: {str(e)}"
        )


@router.patch("/update_patch", dependencies=[Depends(auth.get_token_from_request)], response_model=UserResponse)
async def update_current_user(
        user_data: UserUpdate,
        session: SessionDep,
        token: RequestToken = Depends()
) -> UserResponse:
    """
    Обновление информации текущего пользователя (кроме email)
    """
    try:
        email = auth.verify_token(token=token)
        result = await session.execute(
            select(User).where(User.email == email.sub)
        )
        current_user = result.scalar_one_or_none()
        if not current_user:
            raise HTTPException(404, detail={"message": "Пользователь не найден"})

        # Удаляем email из данных для обновления, если он присутствует
        update_data = user_data.model_dump(exclude_unset=True)
        if 'email' in update_data:
            del update_data['email']

        # Обновляем только разрешенные поля
        for field, value in update_data.items():
            if value is not None:  # Обновляем только переданные поля
                setattr(current_user, field, value)

        # Обновляем updated_at
        current_user.updated_at = datetime.utcnow()

        # Сохраняем изменения
        await session.commit()
        await session.refresh(current_user)

        # Формируем ответ
        return UserResponse.from_orm(current_user)

    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ошибка при обновлении пользователя"
        )

    except Exception as e:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ошибка при обновлении профиля: {str(e)}"
        )


@router.put("/update_put", dependencies=[Depends(auth.get_token_from_request)], response_model=UserResponse)
async def replace_current_user(
        user_data: UserUpdate,
        session: SessionDep,
        token: RequestToken = Depends()
) -> UserResponse:
    """
    Полная замена информации текущего пользователя (PUT, кроме email)
    """
    try:
        email = auth.verify_token(token=token)
        result = await session.execute(
            select(User).where(User.email == email.sub)
        )
        current_user = result.scalar_one_or_none()
        if not current_user:
            raise HTTPException(404, detail={"message": "Пользователь не найден"})

        # Удаляем email из данных для обновления
        update_data = user_data.model_dump(exclude_unset=True)
        if 'email' in update_data:
            del update_data['email']

        # Обновляем только разрешенные поля
        for field, value in update_data.items():
            setattr(current_user, field, value)

        current_user.updated_at = datetime.utcnow()

        await session.commit()
        await session.refresh(current_user)

        return UserResponse.from_orm(current_user)

    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ошибка при обновлении пользователя"
        )
