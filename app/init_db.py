
from app.database import Base, engine
from app import models


def initialize_database():
    Base.metadata.create_all(bind=engine)
    print("TrustVault database initialized successfully!")

    print("\nTables created:")
    for table_name in Base.metadata.tables:
        print(f"- {table_name}")


if __name__ == "__main__":
    initialize_database()
