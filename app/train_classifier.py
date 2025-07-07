import os
import torch
import torch.nn as nn
import torch.optim as optim
from torchvision import datasets, transforms
from torch.utils.data import DataLoader
import numpy as np
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
IMAGE_SIZE = (128, 128)
BATCH_SIZE = 32
EPOCHS = 20
MODEL_PATH = 'app/static/model/item_classifier.pt' 
TRAIN_DATA_DIR = 'dataset/train' 

# 1. Define the PyTorch Model
class CNNClassifier(nn.Module):
    def __init__(self, num_classes):
        super(CNNClassifier, self).__init__()
        self.features = nn.Sequential(
            nn.Conv2d(3, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2),

            nn.Conv2d(32, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2),

            nn.Conv2d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(kernel_size=2, stride=2)
        )
       
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(128 * (IMAGE_SIZE[0] // 8) * (IMAGE_SIZE[1] // 8), 128),
            nn.ReLU(),
            nn.Linear(128, num_classes)
        )

    def forward(self, x):
        x = self.features(x)
        x = self.classifier(x)
        return x


data_transforms = {
    'train': transforms.Compose([
        transforms.Resize(IMAGE_SIZE),
        transforms.RandomRotation(20),
        transforms.RandomResizedCrop(IMAGE_SIZE, scale=(0.8, 1.0)),
        transforms.RandomHorizontalFlip(),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
    ]),
    'val': transforms.Compose([
        transforms.Resize(IMAGE_SIZE),
        transforms.CenterCrop(IMAGE_SIZE),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225])
    ]),
}


train_dataset = datasets.ImageFolder(
    TRAIN_DATA_DIR,
    data_transforms['train']
)


full_dataset = datasets.ImageFolder(
    TRAIN_DATA_DIR,
    transform=data_transforms['train'] # Apply train transforms initially
)


num_classes = len(full_dataset.classes)
logging.info(f"Detected {num_classes} classes: {full_dataset.classes}")


train_size = int(0.8 * len(full_dataset))
val_size = len(full_dataset) - train_size
train_dataset, val_dataset = torch.utils.data.random_split(full_dataset, [train_size, val_size])



if not os.path.exists(os.path.join(TRAIN_DATA_DIR, 'class_name')):
    logging.warning(f"'{TRAIN_DATA_DIR}' does not seem to contain class subdirectories directly. Ensure your data is structured as `TRAIN_DATA_DIR/class1/img.jpg` etc.")

try:
    train_data = datasets.ImageFolder(
        TRAIN_DATA_DIR,
        transform=data_transforms['train']
    )
    
    train_size = int(0.8 * len(train_data))
    val_size = len(train_data) - train_size
    train_dataset, val_dataset = torch.utils.data.random_split(train_data, [train_size, val_size])

    
    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, num_workers=os.cpu_count() // 2 or 1)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False, num_workers=os.cpu_count() // 2 or 1)

  
    num_classes = len(train_data.class_to_idx)
    class_names = train_data.classes
    logging.info(f"Classes for training: {class_names}")

except Exception as e:
    logging.error(f"Error loading data: {e}")
    logging.error("Please ensure your data is structured as `TRAIN_DATA_DIR/class1/img.jpg`, `TRAIN_DATA_DIR/class2/img.jpg`, etc.")
    exit()

# 3. Create and Train Model
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = CNNClassifier(num_classes=num_classes).to(device)

criterion = nn.CrossEntropyLoss() # For sparse_categorical_crossentropy equivalent
optimizer = optim.Adam(model.parameters())

# Callbacks: EarlyStopping and ModelCheckpoint
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
best_val_loss = float('inf')
patience_counter = 0
early_stopping_patience = 5

logging.info(f"Starting training on device: {device}")

for epoch in range(EPOCHS):
    model.train()
    running_loss = 0.0
    correct_train = 0
    total_train = 0

    for i, (inputs, labels) in enumerate(train_loader):
        inputs, labels = inputs.to(device), labels.to(device)

        optimizer.zero_grad()
        outputs = model(inputs)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

        running_loss += loss.item() * inputs.size(0)
        _, predicted = torch.max(outputs.data, 1)
        total_train += labels.size(0)
        correct_train += (predicted == labels).sum().item()

    epoch_train_loss = running_loss / len(train_dataset)
    epoch_train_accuracy = correct_train / total_train

    # Validation phase
    model.eval()
    val_loss = 0.0
    correct_val = 0
    total_val = 0
    with torch.no_grad():
        for inputs, labels in val_loader:
            inputs, labels = inputs.to(device), labels.to(device)
            outputs = model(inputs)
            loss = criterion(outputs, labels)

            val_loss += loss.item() * inputs.size(0)
            _, predicted = torch.max(outputs.data, 1)
            total_val += labels.size(0)
            correct_val += (predicted == labels).sum().item()

    epoch_val_loss = val_loss / len(val_dataset)
    epoch_val_accuracy = correct_val / total_val

    logging.info(f"Epoch {epoch+1}/{EPOCHS}: "
                 f"Train Loss: {epoch_train_loss:.4f}, Train Acc: {epoch_train_accuracy:.4f} | "
                 f"Val Loss: {epoch_val_loss:.4f}, Val Acc: {epoch_val_accuracy:.4f}")

    # ModelCheckpoint and EarlyStopping
    if epoch_val_loss < best_val_loss:
        best_val_loss = epoch_val_loss
        patience_counter = 0
        torch.save(model.state_dict(), MODEL_PATH) # Save only the state_dict
        logging.info(f"Model saved to {MODEL_PATH} (Validation loss improved)")
    else:
        patience_counter += 1
        logging.info(f"Validation loss did not improve. Patience: {patience_counter}/{early_stopping_patience}")
        if patience_counter >= early_stopping_patience:
            logging.info("Early stopping triggered. Restoring best weights...")
            # Load the best model weights if early stopping
            model.load_state_dict(torch.load(MODEL_PATH))
            break

logging.info("Training complete.")
logging.info(f"Final best model saved to {MODEL_PATH}")