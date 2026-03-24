from pydantic import BaseModel

class RegisterRequest(BaseModel):
    ai_url: str
    secret: str

class PredictRequest(BaseModel):
    reactant: str
    reagent: str = ""
