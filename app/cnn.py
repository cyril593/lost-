import os
import logging
import torch
import torch.nn as nn
import torch.nn.functional as F
from torchvision import transforms
from PIL import Image
import io
import numpy as np

log = logging.getLogger(__name__)

class DummyCNN(nn.Module):
    def __init__(self):
        super(DummyCNN, self).__init__()
        self.conv1 = nn.Conv2d(in_channels=3, out_channels=8, kernel_size=3, padding=0)
        self.pool = nn.MaxPool2d(kernel_size=2, stride=2)
        self.fc1 = nn.Linear(in_features=8 * 15 * 15, out_features=1)

    def forward(self, x):
        x = self.pool(F.relu(self.conv1(x)))
        x = torch.flatten(x, 1)
        x = torch.sigmoid(self.fc1(x))
        return x

class ItemClassifier:
    _instance = None
    _model = None
    _is_loaded = False
    _transform = None

    def __new__(cls, model_path=None):
        if cls._instance is None:
            cls._instance = super(ItemClassifier, cls).__new__(cls)
            cls._instance._load_model(model_path)
            cls._instance._transform = transforms.Compose([
                transforms.Resize((32, 32)),
                transforms.ToTensor(),
            ])
        return cls._instance

    def _load_model(self, model_path):
        if self._is_loaded:
            return

        if not model_path:
            log.error("CNN model path not provided.")
            return

        if not os.path.exists(model_path):
            log.error(f"CNN model path not found or invalid: {model_path}")
            return

        try:
            self._model = DummyCNN()
            self._model.load_state_dict(torch.load(model_path))
            self._model.eval()
            self._is_loaded = True
            log.info(f"PyTorch CNN model loaded successfully from {model_path}")
        except Exception as e:
            log.error(f"Failed to load PyTorch CNN classifier model from {model_path}: {e}")
            self._model = None
            self._is_loaded = False

    def predict(self, image_data):
        if not self._is_loaded or self._model is None:
            log.warning("Attempted to predict with an unloaded or invalid CNN model.")
            return None

        try:
            img = Image.open(io.BytesIO(image_data)).convert('RGB')

            img_tensor = self._transform(img)
            img_tensor = img_tensor.unsqueeze(0)

            with torch.no_grad():
                output = self._model(img_tensor)
            
            similarity_score = output.item()
            similarity_percentage = int(similarity_score * 100)

            return {
                "matches": [
                    {
                        "item_id": 101,
                        "item_name": "Dummy Item A (PyTorch)",
                        "description": f"This is a dummy item with a similarity of {similarity_percentage}%.",
                        "similarity": similarity_percentage,
                        "image_url": "/static/uploads/dummy_item_a.jpg"
                    },
                    {
                        "item_id": 102,
                        "item_name": "Dummy Item B (PyTorch)",
                        "description": "Another dummy item for testing purposes with PyTorch.",
                        "similarity": max(0, similarity_percentage - 10),
                        "image_url": "/static/uploads/dummy_item_b.jpg"
                    }
                ]
            }
        except Exception as e:
            log.error(f"Error during PyTorch prediction: {e}")
            return None

    @property
    def is_loaded(self):
        return self._is_loaded
