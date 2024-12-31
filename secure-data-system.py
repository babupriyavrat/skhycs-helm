# Add to imports
from typing import Optional
import jwt
import uuid

class DeviceManager:
    def __init__(self):
        self.secret_key = os.urandom(32)
        self._device_cache = {}  # In production, use Redis or a database
        
    def register_device(self, user_id: str) -> str:
        """Register a new device and return device ID"""
        device_id = str(uuid.uuid4())
        token = jwt.encode({
            'user_id': user_id,
            'device_id': device_id,
            'created_at': datetime.utcnow().isoformat()
        }, self.secret_key, algorithm='HS256')
        
        self._device_cache[device_id] = {
            'token': token,
            'user_id': user_id,
            'created_at': datetime.utcnow()
        }
        return device_id
    
    def verify_device(self, device_id: str, user_id: str) -> bool:
        """Verify if device ID is valid for the user"""
        device_info = self._device_cache.get(device_id)
        if not device_info:
            return False
            
        try:
            payload = jwt.decode(
                device_info['token'], 
                self.secret_key, 
                algorithms=['HS256']
            )
            return payload['user_id'] == user_id and payload['device_id'] == device_id
        except jwt.InvalidTokenError:
            return False

class HoneyEncryption:
    def __init__(self, config: SystemConfig):
        self.config = config
        self.key = os.urandom(32)
        self.fake_generator = FakeDataGenerator()
        self.cipher_type = 'aes'
        self.device_manager = DeviceManager()
    
    def decrypt(self, 
                ciphertext: bytes, 
                password: str, 
                device_id: Optional[str] = None,
                user_id: Optional[str] = None) -> Union[str, Dict[str, str]]:
        """
        Decrypt data with password and device verification
        Returns decoy data if either password is wrong or device is unverified
        """
        seed = self._generate_seed(password)
        
        try:
            # First verify the password
            cipher = self._get_cipher(seed)
            plaintext = cipher.decrypt(ciphertext).decode()
            
            # If device verification is required
            if device_id and user_id:
                if not self.device_manager.verify_device(device_id, user_id):
                    # Return decoy data even though password was correct
                    return self._generate_decoy_data(seed, "unverified_device")
                    
            return plaintext
            
        except Exception:
            # Generate decoy data for wrong password
            return self._generate_decoy_data(seed, "wrong_password")
    
    def _generate_decoy_data(self, seed: bytes, reason: str) -> Dict[str, str]:
        """Generate decoy data based on seed and reason"""
        seed_int = int.from_bytes(seed[:8], byteorder='big')
        data_type = self._infer_data_type(seed)
        decoy = self.fake_generator.generate_decoy(seed_int, data_type)
        
        # Add subtle variations based on reason
        if reason == "unverified_device":
            # Add a subtle marker in the decoy data
            if 'metadata' in decoy:
                decoy['metadata']['last_updated'] = datetime.utcnow().isoformat()
        
        return decoy

# Update main system class
class SecureDataSystem:
    def __init__(self):
        self.config = SystemConfig()
        self.preprocessor = DataPreprocessor()
        self.pipeline = ProcessingPipeline(self.config)
        self.device_manager = DeviceManager()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def register_device(self, user_id: str) -> str:
        """Register a new device for a user"""
        return self.device_manager.register_device(user_id)
    
    def decrypt_data(self, 
                    ciphertext: bytes, 
                    password: str, 
                    device_id: Optional[str] = None,
                    user_id: Optional[str] = None) -> Union[str, Dict[str, str]]:
        try:
            result = self.pipeline.process_decryption(
                ciphertext, 
                password, 
                device_id, 
                user_id
            )
            self.logger.info("Decryption process completed")
            return result
            
        except Exception as e:
            self.logger.error(f"Decryption failed: {str(e)}")
            raise

# Usage example
if __name__ == "__main__":
    system = SecureDataSystem()
    
    # Register a device
    user_id = "user123"
    device_id = system.register_device(user_id)
    print(f"Registered device ID: {device_id}")
    
    # Test data
    test_data = SensitiveData(
        data_type="credit_card",
        value="4532015112830366",
        metadata={"issuer": "VISA", "expiry": "12/25"}
    )
    
    # Encrypt data
    password = "secure_password123"
    ciphertext = system.encrypt_data(test_data, password)
    
    # Test cases
    print("\nTest Case 1: Correct password, correct device")
    result1 = system.decrypt_data(ciphertext, password, device_id, user_id)
    print(f"Result: {result1}")
    
    print("\nTest Case 2: Correct password, wrong device")
    wrong_device = "wrong_device_id"
    result2 = system.decrypt_data(ciphertext, password, wrong_device, user_id)
    print(f"Result: {result2}")
    
    print("\nTest Case 3: Wrong password")
    result3 = system.decrypt_data(ciphertext, "wrong_password", device_id, user_id)
    print(f"Result: {result3}")
