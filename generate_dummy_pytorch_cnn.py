# generate_dummy_pytorch_cnn.py

import os
import torch
import torch.nn as nn
import torch.nn.functional as F

# Define the path where the dummy model will be saved
# This should match the CNN_MODEL_PATH in your config.py
# Let's assume it's in 'app/models/dummy_pytorch_cnn_model.pth'
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
MODEL_DIR = os.path.join(PROJECT_ROOT, 'app', 'models')
MODEL_FILENAME = 'dummy_pytorch_cnn_model.pth' # PyTorch models often use .pth or .pt
SAVE_PATH = os.path.join(MODEL_DIR, MODEL_FILENAME)

# Create the directory if it doesn't exist
os.makedirs(MODEL_DIR, exist_ok=True)

print(f"Attempting to save dummy PyTorch CNN model to: {SAVE_PATH}")

# Define a very simple dummy CNN model using PyTorch
class DummyCNN(nn.Module):
    def __init__(self):
        super(DummyCNN, self).__init__()
        # Input: 3 channels (RGB), 32x32 image
        # Output: 8 channels, (32-3+1)x(32-3+1) = 30x30
        self.conv1 = nn.Conv2d(in_channels=3, out_channels=8, kernel_size=3, padding=0)
        # After pooling: 8 channels, 15x15
        self.pool = nn.MaxPool2d(kernel_size=2, stride=2)
        # Flatten layer will take 8 * 15 * 15 = 1800 features
        self.fc1 = nn.Linear(in_features=8 * 15 * 15, out_features=1) # Output a single value

    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))
        x = torch.flatten(x, 1) # Flatten all dimensions except batch
        x = torch.sigmoid(self.fc1(x)) # Sigmoid for a single output (e.g., similarity)
        return x

try:
    model = DummyCNN()

    
    torch.save(model.state_dict(), SAVE_PATH)
    print(f"Dummy PyTorch CNN model '{MODEL_FILENAME}' created and saved successfully at {SAVE_PATH}")

except Exception as e:
    print(f"Error creating or saving dummy PyTorch CNN model: {e}")
    print("Please ensure PyTorch and TorchVision are installed correctly (`pip install torch torchvision`)")

