from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class Database:
    client: AsyncIOMotorClient = None
    db = None


db_instance = Database()


async def connect_to_mongo():
    try:
        db_instance.client = AsyncIOMotorClient(settings.MONGO_URI)
        db_instance.db = db_instance.client[settings.MONGO_DB_NAME]

        await init_beanie(
            database=db_instance.db,
            document_models=[
                "app.models.user.User"
            ]
        )

        await db_instance.client.admin.command("ping")

        logger.info(
            "Successfully connected to MongoDB at %s and initialized Beanie",
            settings.MONGO_URI,
        )

    except Exception as e:
        logger.error("Failed to connect to MongoDB: %s", e)
        raise


async def close_mongo_connection():
    if db_instance.client:
        db_instance.client.close()
        logger.info("MongoDB connection closed.")


def get_db():
    return db_instance.db