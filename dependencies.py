# from fastapi import Depends, HTTPException, status, Security
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
#
# from sqlalchemy.future import select
# from typing import Annotated, AsyncGenerator
#
# from database import SessionDep, get_session
# from models import User
# from auth.security import auth
#
# # Инициализация HTTPBearer для работы с JWT токенами
# security = HTTPBearer()
#
#
# async def get_current_user(
#         session: SessionDep,
#         credentials: HTTPAuthorizationCredentials = Security(security),
# ) -> User:
#     """
#     Dependency для получения текущего пользователя из JWT токена
#     """
#     try:
#         payload = auth.verify_token(credentials.credentials)
#         if payload is None:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Неверный токен",
#                 headers={"WWW-Authenticate": "Bearer"},
#             )
#
#         user_id = int(payload.get("sub"))
#         email = payload.get("email")
#
#         if user_id is None or email is None:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Неверный токен",
#                 headers={"WWW-Authenticate": "Bearer"},
#             )
#
#         # Ищем пользователя
#         result = await session.execute(
#             select(User).where(User.id == user_id, User.email == email)
#         )
#         user = result.scalar_one_or_none()
#
#         if user is None:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Пользователь не найден",
#                 headers={"WWW-Authenticate": "Bearer"},
#             )
#
#         if not user.is_active:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Аккаунт деактивирован",
#                 headers={"WWW-Authenticate": "Bearer"},
#             )
#
#         return user
#
#
#
#     except jwt.PyJWTError:
#         return None
#
#
# # Создаем тип для аннотаций
# CurrentUser = Annotated[User, Depends(get_current_user)]
#
#
# # Дополнительные зависимости для проверки ролей
# async def get_admin_user(current_user: CurrentUser) -> User:
#     """
#     Dependency для проверки, что пользователь является администратором
#     """
#     # Получаем сессию для проверки роли
#     async with get_session() as session:
#         result = await session.execute(
#             select(User).where(User.id == current_user.id)
#         )
#         user_with_role = result.scalar_one_or_none()
#
#         if not user_with_role or user_with_role.role.name != "admin":
#             raise HTTPException(
#                 status_code=status.HTTP_403_FORBIDDEN,
#                 detail="Недостаточно прав. Требуется роль администратора"
#             )
#
#     return current_user
#
#
# async def get_manager_user(current_user: CurrentUser) -> User:
#     """
#     Dependency для проверки, что пользователь является менеджером или администратором
#     """
#     async with get_session() as session:
#         result = await session.execute(
#             select(User).where(User.id == current_user.id)
#         )
#         user_with_role = result.scalar_one_or_none()
#
#         if not user_with_role or user_with_role.role.name not in ["admin", "manager"]:
#             raise HTTPException(
#                 status_code=status.HTTP_403_FORBIDDEN,
#                 detail="Недостаточно прав. Требуется роль менеджера или администратора"
#             )
#
#     return current_user
#
#
# # Типы для аннотаций с проверкой ролей
# AdminUser = Annotated[User, Depends(get_admin_user)]
# ManagerUser = Annotated[User, Depends(get_manager_user)]