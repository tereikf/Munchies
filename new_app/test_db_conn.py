import psycopg2

try:
    conn = psycopg2.connect(
        dbname="your_app_database",
        user="your_username",
        password="your_password",
        host="127.0.0.1",
        port="5555"
    )
    print("Connected to PostgreSQL successfully!")
    conn.close()
except Exception as e:
    print(f"Error: {e}")