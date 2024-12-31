import gradio as gr
from secure_data_system import SecureDataSystem, SensitiveData

system = SecureDataSystem()

def process_data(data_type, value, metadata, password, operation):
    try:
        data = SensitiveData(
            data_type=data_type,
            value=value,
            metadata=eval(metadata)  # Convert string to dict
        )
        
        if operation == "encrypt":
            result = system.encrypt_data(data, password)
            return f"Encrypted: {result.hex()}"
        else:
            result = system.decrypt_data(bytes.fromhex(value), password)
            return f"Decrypted/Decoy: {result}"
    except Exception as e:
        return f"Error: {str(e)}"

# Create Gradio interface
iface = gr.Interface(
    fn=process_data,
    inputs=[
        gr.Dropdown(choices=["credit_card", "crypto_wallet", "digital_wallet"], label="Data Type"),
        gr.Textbox(label="Value"),
        gr.Textbox(label="Metadata (as dict)", value="{'issuer': 'VISA', 'expiry': '12/25'}"),
        gr.Textbox(label="Password"),
        gr.Radio(choices=["encrypt", "decrypt"], label="Operation")
    ],
    outputs=gr.Textbox(label="Result"),
    title="Secure Data System",
    description="Encrypt sensitive data with honey encryption and decoy generation"
)

if __name__ == "__main__":
    iface.launch(server_name="0.0.0.0", server_port=7860)
