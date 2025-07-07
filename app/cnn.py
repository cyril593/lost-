import torchvision.models as models
from PIL import Image
import os
import logging
import torch
import numpy as np
import torchvision.transforms as transforms

class ItemClassifier:
    def __init__(self, model_path):
        try:
            # Load the PyTorch model
            # map_location='cpu' ensures it loads on CPU even if trained on GPU
            self.model = torch.load(model_path, map_location=torch.device('cpu'))
            self.model.eval() # Set the model to evaluation mode
            self.categories = ['electronics', 'documents', 'clothing', 'accessories', 'other']
            logging.info(f"CNN model loaded successfully from {model_path}")
            
            # Define transformations for inference
            # These are standard transformations for pre-trained ImageNet models
            self.transform = transforms.Compose([
                transforms.Resize((224, 224)), # Resize image to 224x224 pixels
                transforms.ToTensor(), # Convert PIL Image to PyTorch Tensor
                transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]), # Normalize with ImageNet stats
            ])
        except Exception as e:
            logging.error(f"Error loading model from {model_path}: {str(e)}")
            self.model = None
            self.transform = None # Ensure transform is None if model loading fails

    def preprocess_image(self, image):
        """
        Preprocess the image to feed into CNN using torchvision transforms.
        Expects a PIL Image object.
        """
        try:
            if self.transform is None:
                logging.error("Image transformation pipeline not initialized. Model might not have loaded correctly.")
                return None
            if image.mode != "RGB":
                image = image.convert("RGB")
            # Apply transformations and add a batch dimension (unsqueeze(0))
            return self.transform(image).unsqueeze(0)
        except Exception as e:
            logging.error(f"Error preprocessing image: {str(e)}")
            return None

    def predict(self, image):
        """
        Run prediction on an image.
        Returns the predicted class index and the raw predictions (probabilities).
        """
        if not self.model:
            logging.warning("Model not loaded, cannot perform prediction.")
            return None, None
            
        processed_image = self.preprocess_image(image)
        if processed_image is None:
            return None, None
            
        try:
            with torch.no_grad(): # Disable gradient calculation for inference
                outputs = self.model(processed_image)
                # Apply softmax to convert logits to probabilities
                predictions = torch.softmax(outputs, dim=1).cpu().numpy()
                predicted_class = np.argmax(predictions, axis=1)[0]
                return predicted_class, predictions[0]
        except Exception as e:
            logging.error(f"Prediction error: {str(e)}")
            return None, None
            
    def predict_category(self, image):
        """
        Get the category name from the prediction.
        """
        class_idx, _ = self.predict(image)
        if class_idx is not None and 0 <= class_idx < len(self.categories):
            return self.categories[class_idx]
        logging.warning(f"Could not determine category for image. Predicted class index: {class_idx}")
        return "other" 