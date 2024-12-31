import os
from datetime import timedelta

class Config:
    ENVIRONMENT = os.getenv('ENVIRONMENT', 'development')
    
    # Redis configuration
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    
    # Security settings
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', os.urandom(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Google Cloud settings
    GOOGLE_CLOUD_PROJECT = os.getenv('GOOGLE_CLOUD_PROJECT')
    
    @property
    def is_production(self):
        return self.ENVIRONMENT == 'production'
