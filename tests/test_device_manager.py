import pytest
from secure_data_system.device_manager import DeviceManager

def test_register_device():
    manager = DeviceManager()
    user_id = "test_user"
    device_id = manager.register_device(user_id)
    
    assert device_id is not None
    assert isinstance(device_id, str)
    
def test_verify_device():
    manager = DeviceManager()
    user_id = "test_user"
    device_id = manager.register_device(user_id)
    
    assert manager.verify_device(device_id, user_id) is True
    assert manager.verify_device(device_id, "wrong_user") is False
    assert manager.verify_device("wrong_device", user_id) is False
