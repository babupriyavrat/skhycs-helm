#  Skhy CS  Helm - Secure Data System with Honey Encryption


A secure data management system with device-based authentication, honey encryption, and multi-environment deployment support.

## 🔑 Features

- Device-based authentication and management
- Honey encryption with decoy data generation
- Multi-environment deployment support (Local, Gradle, Google Cloud)
- Redis integration for device cache
- Comprehensive testing suite
- Secure configuration management

## 📋 Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose (for local deployment)
- Gradle 7.x or higher (for Gradle deployment)
- Google Cloud SDK (for GCP deployment)
- Redis (for production device cache)

## 🛠️ Installation

### Local Development Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secure-data-system.git
cd secure-data-system
```

2. Create and activate virtual environment:
```bash
python -m venv venv
# For Unix/macOS:
source venv/bin/activate
# For Windows:
venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Docker Setup

1. Build and run using Docker Compose:
```bash
docker-compose up --build
```

2. For production builds:
```bash
docker build -t secure-data-system:latest .
docker run -p 8000:8000 secure-data-system:latest
```

### Gradle Setup

1. Build the project:
```bash
./gradlew build
```

2. Build and push container image:
```bash
./gradlew jib
```

## 🚀 Deployment

### Local Deployment

1. Run the application:
```bash
python secure-data-system-device.py
```

2. Run tests:
```bash
pytest
pytest --cov=secure_data_system tests/
```

### Google Cloud Deployment

1. Configure Google Cloud SDK:
```bash
gcloud auth login
gcloud config set project your-project-id
```

2. Deploy to App Engine:
```bash
gcloud app deploy app.yaml
```

3. View logs:
```bash
gcloud app logs tail
```

## 💻 Usage Example

```python
from secure_data_system import SecureDataSystem

# Initialize system
system = SecureDataSystem()

# Register a device
user_id = "user123"
device_id = system.register_device(user_id)

# Encrypt sensitive data
test_data = SensitiveData(
    data_type="credit_card",
    value="4532015112830366",
    metadata={"issuer": "VISA", "expiry": "12/25"}
)

# Encrypt and decrypt
password = "secure_password123"
ciphertext = system.encrypt_data(test_data, password)
result = system.decrypt_data(ciphertext, password, device_id, user_id)
```

## ⚙️ Configuration

The system can be configured through environment variables or a `.env` file:

```env
ENVIRONMENT=development
REDIS_HOST=localhost
REDIS_PORT=6379
JWT_SECRET_KEY=your-secret-key
GOOGLE_CLOUD_PROJECT=your-project-id
```

## 🔒 Security Considerations

1. **Secrets Management**:
   - Use environment variables for local development
   - Use Google Cloud Secret Manager for production
   - Never commit sensitive data to version control

2. **Device Authentication**:
   - Implement device rotation policies
   - Monitor failed authentication attempts
   - Regularly audit device registrations

3. **Data Protection**:
   - All sensitive data is encrypted at rest
   - Honey encryption provides protection against brute force attacks
   - Decoy data generation for security through obscurity

## 🧪 Testing

Run the test suite:
```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=secure_data_system tests/
```

## 📦 Project Structure

```
secure-data-system/
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── build.gradle
├── app.yaml
├── config.py
├── secure-data-system-device.py
├── tests/
│   └── test_device_manager.py
└── .gitignore
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- JWT for secure token management
- Redis for high-performance caching
- Google Cloud Platform for scalable deployment
- Faker for generating realistic decoy data

Your Name - [@babupriyavrat](https://linkedin.com/in/babupriyavrat)
Project Link: [https://github.com/babupriyavrat/skhycs-helm](https://github.com/babupriyavrat/skhycs-helm)

---
Made with ❤️ by Babu Priyavrat

