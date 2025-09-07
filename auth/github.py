import requests
from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse
from config import GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, FRONTEND_URL, REDIRECT_URI, GITHUB_AUTH_URL, GITHUB_TOKEN_URL, GITHUB_USERINFO_URL

auth_github_router = APIRouter(prefix="/auth/github", tags=["GitHub Auth"])

@auth_github_router.get("/")
def auth_github():
    return {
        "url": f"{GITHUB_AUTH_URL}?client_id={GITHUB_CLIENT_ID}&scope=user"
    }


@auth_github_router.get("/callback")
def auth_github_callback(code: str):
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
    }
    headers = {"Accept": "application/json"}

    response = requests.post(GITHUB_TOKEN_URL, data=data, headers=headers)
    token_info = response.json()

    if "access_token" not in token_info:
        raise HTTPException(status_code=400, detail="GitHub authentication failed")

    headers = {"Authorization": f"Bearer {token_info['access_token']}"}
    user_info = requests.get(GITHUB_USERINFO_URL, headers=headers).json()

    # Вместо перенаправления на фронтенд возвращаем данные напрямую
    return {
        "success": True,
        "username": user_info['login'],
        "user_info": user_info,
        "access_token": token_info['access_token']
    }
