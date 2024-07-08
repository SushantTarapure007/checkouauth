from pymongo import MongoClient
from bson.objectid import ObjectId
from .models import UserDB
from .schemas import UserCreate, UserUpdate
from .auth import get_password_hash

client = MongoClient('mongodb://localhost:27017/')
db = client['authentication_example']
users_collection = db['users']


def get_user(username: str):
    return users_collection.find_one({"username": username})


def create_user(user_data: UserCreate):
    user_data.password = get_password_hash(user_data.password)
    user_id = users_collection.insert_one(user_data.dict()).inserted_id
    return user_id


def update_user(username: str, user_data: UserUpdate):
    user_data.password = get_password_hash(user_data.password)
    users_collection.update_one({"username": username}, {"$set": user_data.dict()})


def delete_user(username: str):
    users_collection.delete_one({"username": username})
