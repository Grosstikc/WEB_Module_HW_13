import sys
import os
sys.path.append(os.getcwd())  # Додає поточну директорію до sys.path

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context
from my_fastapi_project.app.database import Base  # Імпорт базового класу для моделей
from my_fastapi_project.app.models import *  # Імпорт всіх моделей

# це рядок зв'язку з вашою базою даних, отриманий з alembic.ini
config = context.config
config.set_main_option('sqlalchemy.url', 'postgresql://username:password@localhost/dbname')  # Переконайтеся, що цей рядок відповідає вашому рядку підключення

# Підключення до бази даних
connectable = engine_from_config(
    config.get_section(config.config_ini_section),
    prefix='sqlalchemy.',
    poolclass=pool.NullPool)

def run_migrations_online():
    """Запуск міграцій у "онлайн" режимі."""
    with connectable.connect() as connection:
        context.configure(
                connection=connection,
                target_metadata=Base.metadata
            )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
