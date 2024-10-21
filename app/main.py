from fastapi import FastAPI
from app.presentation.routes import router

app = FastAPI()

# Include the routes from the presentation layer
app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
