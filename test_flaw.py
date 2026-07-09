import os

api_key = "sk-ant-1234567890abcdef"

def get_user(cursor, user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")