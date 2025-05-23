from uvicorn.middleware.wsgi import WSGIMiddleware
from app import app as flask_app

# Wrap the Flask app with the WSGI-to-ASGI adapter
app = WSGIMiddleware(flask_app) 