from fastapi import FastAPI, Request, Form, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, Session, declarative_base, relationship
from datetime import datetime
from typing import Optional
import hashlib
import traceback

# БД
engine = create_engine("sqlite:///./project.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    games = relationship("Game", back_populates="user", cascade="all, delete-orphan")


class Game(Base):
    __tablename__ = "games"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    genre = Column(String(50))
    year = Column(Integer)
    status = Column(String(20), default="В планах")  # В планах, Граю, Завершено
    rating = Column(Integer, default=0)  # 0-10
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="games")
    created_at = Column(DateTime, default=datetime.utcnow)


# Створюємо таблиці
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Game Tracker Pro")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    """Хешування паролю для зберігання в БД"""
    return hashlib.sha256(password.encode()).hexdigest()


def get_current_user(request: Request, db: Session = Depends(get_db)):
    """Отримання поточного користувача з cookies"""
    user_id = request.cookies.get("user_id")
    session_token = request.cookies.get("session_token")

    if not user_id or not session_token:
        return None

    try:
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            return None

        # Перевірка сесії
        expected_token = hash_password(str(user.id) + user.email + user.password_hash)
        if session_token != expected_token:
            return None

        return user
    except Exception as e:
        print(f"Помилка при отриманні користувача: {e}")
        return None


@app.get("/", response_class=HTMLResponse)
def index(request: Request, form: Optional[str] = None, db: Session = Depends(get_db)):
    """Головна сторінка"""
    try:
        user = get_current_user(request, db)
        if not user:
            # Показуємо форму входу/реєстрації
            show_register = form == "register"
            return templates.TemplateResponse("welcome.html", {
                "request": request,
                "show_register": show_register
            })

        # Якщо користувач залогінений - показуємо бібліотеку
        games = db.query(Game).filter(Game.user_id == user.id).order_by(Game.created_at.desc()).all()
        return templates.TemplateResponse("index.html", {
            "request": request,
            "user": user,
            "games": games
        })
    except Exception as e:
        print(f"Помилка в index: {e}")
        traceback.print_exc()
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": "Сталася помилка. Спробуйте пізніше."
        })


@app.post("/auth/register")
def register(
        request: Request,
        username: str = Form(...),
        email: str = Form(...),
        password: str = Form(...),
        confirm_password: str = Form(...),
        db: Session = Depends(get_db)
):
    """Реєстрація нового користувача"""
    try:
        print(f"Спроба реєстрації: {username}, {email}")

        # Валідація
        if password != confirm_password:
            print("Паролі не співпадають")
            return templates.TemplateResponse("welcome.html", {
                "request": request,
                "show_register": True,
                "error": "Паролі не співпадають"
            })

        if len(password) < 6:
            print("Пароль закороткий")
            return templates.TemplateResponse("welcome.html", {
                "request": request,
                "show_register": True,
                "error": "Пароль повинен містити мінімум 6 символів"
            })

        if len(username) < 3:
            print("Нікнейм закороткий")
            return templates.TemplateResponse("welcome.html", {
                "request": request,
                "show_register": True,
                "error": "Нікнейм повинен містити мінімум 3 символи"
            })

        # Перевірка унікальності
        existing_email = db.query(User).filter(User.email == email).first()
        if existing_email:
            print("Email вже використовується")
            return templates.TemplateResponse("welcome.html", {
                "request": request,
                "show_register": True,
                "error": "Цей email вже використовується"
            })

        existing_username = db.query(User).filter(User.username == username).first()
        if existing_username:
            print("Нікнейм вже зайнятий")
            return templates.TemplateResponse("welcome.html", {
                "request": request,
                "show_register": True,
                "error": "Цей нікнейм вже зайнятий"
            })

        # Хешування паролю
        password_hash = hash_password(password)
        print(f"Хеш паролю створено для {username}")

        # Створення користувача
        new_user = User(
            username=username.strip(),
            email=email.strip().lower(),
            password_hash=password_hash
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        print(f"Користувач створений: ID={new_user.id}, username={new_user.username}")

        # Створення сесійного токена
        session_token = hash_password(f"{new_user.id}{new_user.email}{new_user.password_hash}")

        # Автоматичний вхід та перенаправлення
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key="user_id", value=str(new_user.id))
        response.set_cookie(key="session_token", value=session_token)

        print("Реєстрація успішна, перенаправляємо...")
        return response

    except Exception as e:
        print(f"Помилка при реєстрації: {e}")
        traceback.print_exc()
        return templates.TemplateResponse("welcome.html", {
            "request": request,
            "show_register": True,
            "error": f"Сталася помилка при реєстрації: {str(e)}"
        })


@app.post("/auth/login")
def login(
        request: Request,
        email: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db)
):
    """Вхід існуючого користувача"""
    try:
        print(f"Спроба входу: {email}")

        # Знаходимо користувача
        user = db.query(User).filter(User.email == email.strip().lower()).first()

        if not user:
            print("Користувача не знайдено")
            return templates.TemplateResponse("welcome.html", {
                "request": request,
                "show_register": False,
                "error": "Невірний email або пароль"
            })

        # Перевіряємо пароль
        if user.password_hash != hash_password(password):
            print("Невірний пароль")
            return templates.TemplateResponse("welcome.html", {
                "request": request,
                "show_register": False,
                "error": "Невірний email або пароль"
            })

        # Створюємо токен
        session_token = hash_password(f"{user.id}{user.email}{user.password_hash}")

        # Вхід успішний
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(key="user_id", value=str(user.id))
        response.set_cookie(key="session_token", value=session_token)

        print(f"Вхід успішний для {user.username}")
        return response

    except Exception as e:
        print(f"Помилка при вході: {e}")
        traceback.print_exc()
        return templates.TemplateResponse("welcome.html", {
            "request": request,
            "show_register": False,
            "error": f"Сталася помилка: {str(e)}"
        })


@app.get("/logout")
def logout():
    """Вихід з акаунту"""
    response = RedirectResponse(url="/")
    response.delete_cookie("user_id")
    response.delete_cookie("session_token")
    return response


@app.post("/games/add")
def add_game(
        request: Request,
        title: str = Form(...),
        genre: str = Form(None),
        year: int = Form(None),
        status: str = Form("В планах"),
        rating: int = Form(0),
        db: Session = Depends(get_db)
):
    """Додавання нової гри"""
    try:
        user = get_current_user(request, db)
        if not user:
            return RedirectResponse(url="/")

        # Валідація рейтингу
        if rating:
            rating = max(0, min(10, int(rating)))

        # Створення гри
        new_game = Game(
            title=title.strip(),
            genre=genre.strip() if genre else None,
            year=year if year and year > 1900 else None,
            status=status,
            rating=rating,
            user_id=user.id
        )

        db.add(new_game)
        db.commit()

        return RedirectResponse(url="/", status_code=303)

    except Exception as e:
        print(f"Помилка при додаванні гри: {e}")
        traceback.print_exc()
        return RedirectResponse(url="/", status_code=303)


@app.get("/games/delete/{game_id}")
def delete_game(
        request: Request,
        game_id: int,
        db: Session = Depends(get_db)
):
    """Видалення гри"""
    try:
        user = get_current_user(request, db)
        if not user:
            return RedirectResponse(url="/")

        game = db.query(Game).filter(Game.id == game_id, Game.user_id == user.id).first()
        if game:
            db.delete(game)
            db.commit()

        return RedirectResponse(url="/", status_code=303)

    except Exception as e:
        print(f"Помилка при видаленні гри: {e}")
        return RedirectResponse(url="/", status_code=303)


@app.get("/dashboard")
def dashboard(request: Request, db: Session = Depends(get_db)):
    """Сторінка статистики"""
    try:
        user = get_current_user(request, db)
        if not user:
            return RedirectResponse(url="/")

        games = db.query(Game).filter(Game.user_id == user.id).all()

        # Статистика
        stats = {
            "total": len(games),
            "completed": len([g for g in games if g.status == "Завершено"]),
            "playing": len([g for g in games if g.status == "Граю"]),
            "planned": len([g for g in games if g.status == "В планах"]),
            "avg_rating": 0
        }

        # Середній рейтинг
        rated_games = [g.rating for g in games if g.rating > 0]
        if rated_games:
            stats["avg_rating"] = round(sum(rated_games) / len(rated_games), 1)

        return templates.TemplateResponse("dashboard.html", {
            "request": request,
            "user": user,
            "games": games[:5],
            "stats": stats
        })

    except Exception as e:
        print(f"Помилка в dashboard: {e}")
        return RedirectResponse(url="/", status_code=303)


# Додаємо сторінку помилки
@app.get("/error")
def error_page(request: Request):
    return templates.TemplateResponse("error.html", {"request": request})