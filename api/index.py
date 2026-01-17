from app import app

def handler(request, context):
    return app(request.environ, lambda status, headers: None)
