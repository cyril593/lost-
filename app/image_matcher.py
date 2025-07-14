import numpy as np
import torch
import torchvision.models as models
import torchvision.transforms as transforms
from PIL import Image
import io
import logging
import json
import os

logger = logging.getLogger(__name__)


_feature_model = None
_preprocess_transform = None
_device = None

def get_feature_model():
    """Initializes and returns a pre-trained ResNet50 model for feature extraction using PyTorch."""
    global _feature_model, _preprocess_transform, _device
    if _feature_model is None:
        try:
            _device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            
            _feature_model = models.resnet50(weights=models.ResNet50_Weights.IMAGENET1K_V1)
            
            _feature_model = torch.nn.Sequential(*(list(_feature_model.children())[:-1]))
            
            _feature_model.eval()
            _feature_model.to(_device)

            
            _preprocess_transform = transforms.Compose([
                transforms.Resize(256),
                transforms.CenterCrop(224),
                transforms.ToTensor(),
                transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
            ])
            logger.info(f"Loaded PyTorch ResNet50 feature extraction model successfully on {_device}.")
        except Exception as e:
            logger.error(f"Error loading PyTorch ResNet50 model: {e}")
            _feature_model = None
            _preprocess_transform = None
            _device = None
    return _feature_model, _preprocess_transform, _device

def extract_features(image_path_or_pil_image):
    """
    Extracts CNN features from an image using a pre-trained PyTorch ResNet50 model.
    Args:
        image_path_or_pil_image: Path to the image file (string) or a PIL Image object.
    Returns:
        A list of floats representing the image features, or None if an error occurs.
    """
    model, preprocess, device = get_feature_model()
    if model is None or preprocess is None or device is None:
        return None

    try:
        if isinstance(image_path_or_pil_image, str):
            if not os.path.exists(image_path_or_pil_image):
                logger.error(f"Image file not found: {image_path_or_pil_image}")
                return None
            img = Image.open(image_path_or_pil_image).convert('RGB')
        elif isinstance(image_path_or_pil_image, Image.Image):
            img = image_path_or_pil_image.convert('RGB')
        else:
            logger.error(f"Invalid input type for extract_features: {type(image_path_or_pil_image)}")
            return None

        
        img_tensor = preprocess(img)
       
        img_tensor = img_tensor.unsqueeze(0)

        img_tensor = img_tensor.to(device)

       
        with torch.no_grad():
            features = model(img_tensor)

        
        return features.flatten().cpu().numpy().tolist()
    except Exception as e:
        logger.error(f"Error extracting features from image: {e}")
        return None

def cosine_similarity(vec1, vec2):
    """
    Calculates the cosine similarity between two feature vectors.
    Returns 0.0 if either vector is None or empty.
    """
    if vec1 is None or vec2 is None or len(vec1) == 0 or len(vec2) == 0:
        return 0.0
    
    v1 = np.array(vec1)
    v2 = np.array(vec2)

    norm_v1 = np.linalg.norm(v1)
    norm_v2 = np.linalg.norm(v2)

    if norm_v1 == 0 or norm_v2 == 0:
        return 0.0  

    return np.dot(v1, v2) / (norm_v1 * norm_v2)

def find_matches(lost_item_features, found_items, threshold=0.85):
    """
    Finds potential matching 'found' items for a newly reported 'lost' item based on image features.
    
    Args:
        lost_item_features (list): Features of the newly reported lost item.
        found_items (list): A list of Item model objects that are marked as 'found' and have image_features.
        threshold (float): The minimum cosine similarity score to consider a match.
        
    Returns:
        A list of tuples: (found_item_object, similarity_score).
    """
    matches = []
    if not lost_item_features:
        return matches

    for found_item in found_items:
        if not found_item.image_features:
            continue
            
        try:
            found_features = found_item.image_features
            if isinstance(found_features, str):
                found_features = json.loads(found_features)
            
            similarity = cosine_similarity(lost_item_features, found_features)
            
            if similarity >= threshold:
                matches.append((found_item, similarity))
        except json.JSONDecodeError as e:
            logger.error(f"JSON decoding error for found item {getattr(found_item, 'item_id', 'unknown')} features: {e}")
            continue
        except Exception as e:
            logger.error(f"Error comparing lost item features with found item {getattr(found_item, 'item_id', 'unknown')}: {e}")
            continue
            
    matches.sort(key=lambda x: x[1], reverse=True)
    return matches
