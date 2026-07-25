import asyncio
import httpx
from httpx import ASGITransport
from app.main import app
from app.models.user import User
from beanie import init_beanie
from mongomock_motor import AsyncMongoMockClient
import sys

async def run_tests():
    # Mock MongoDB connection
    client = AsyncMongoMockClient()
    db = client.test_db
    await init_beanie(database=db, document_models=[User])
    
    test_email = "e2e_test@example.com"
        
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Register User
        resp1 = await client.post("/api/v1/auth/register", json={
            "username": "e2e_test_user",
            "email": test_email,
            "password": "Password123!",
            "full_name": "Test User"
        })
        assert resp1.status_code == 201, f"Failed Register: {resp1.text}"
        print("✔ Register user works")

        # 2. Duplicate Registration
        resp2 = await client.post("/api/v1/auth/register", json={
            "username": "e2e_test_user",
            "email": test_email,
            "password": "Password123!",
            "full_name": "Test User"
        })
        assert resp2.status_code == 409, f"Failed Duplicate Register: {resp2.text}"
        print("✔ Duplicate registration blocked (409)")

        # 3. Login User
        resp3 = await client.post("/api/v1/auth/login", json={
            "email": test_email,
            "password": "Password123!"
        })
        assert resp3.status_code == 200, f"Failed Login: {resp3.text}"
        data = resp3.json()
        access_token = data["access_token"]
        refresh_token = data["refresh_token"]
        print("✔ Login works (Returns Access Token, Refresh Token, User)")

        # 4. Invalid Password
        resp4 = await client.post("/api/v1/auth/login", json={
            "email": test_email,
            "password": "WrongPassword!"
        })
        assert resp4.status_code == 401, f"Failed Invalid Password: {resp4.text}"
        print("✔ Invalid password blocked (401)")

        for _ in range(4):
            await client.post("/api/v1/auth/login", json={"email": test_email, "password": "Wrong!"})
            
        # 6. Locked Account
        resp6 = await client.post("/api/v1/auth/login", json={
            "email": test_email,
            "password": "Wrong!"
        })
        assert resp6.status_code == 423, f"Failed Locked Account: {resp6.text}"
        print("✔ Locked account blocked (423)")

        user = await User.find_one(User.email == test_email)
        user.locked_until = None
        user.is_active = False
        await user.save()

        # 5. Inactive Account
        resp5 = await client.post("/api/v1/auth/login", json={
            "email": test_email,
            "password": "Password123!"
        })
        assert resp5.status_code == 403, f"Failed Inactive Account: {resp5.text}"
        print("✔ Inactive account blocked (403)")

        user.is_active = True
        await user.save()

        # 7. Protected Route
        resp7a = await client.get("/api/v1/protected")
        assert resp7a.status_code == 401, "Failed missing token"
        print("✔ Missing token blocked")

        resp7b = await client.get("/api/v1/protected", headers={"Authorization": f"Bearer {access_token}"})
        assert resp7b.status_code == 200, f"Failed valid token: {resp7b.text}"
        print("✔ Valid token accepted")

        resp7c = await client.get("/api/v1/protected", headers={"Authorization": f"Bearer {refresh_token}"})
        assert resp7c.status_code == 401, f"Failed refresh token test: {resp7c.text}"
        print("✔ Refresh token rejected for access")

        print("✔ All authentication flow tests passed!")
        
        await user.delete()

if __name__ == "__main__":
    asyncio.run(run_tests())
