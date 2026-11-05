import torch
import torch.nn as nn

class ResourceAnomalyDetector(nn.Module):
    def __init__(self, input_dim=5): # CPU, RAM, GPU, Disk, Network
        super(ResourceAnomalyDetector, self).__init__()
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 8),
            nn.ReLU(),
            nn.Linear(8, 3) # Compressed latent space
        )
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(3, 8),
            nn.ReLU(),
            nn.Linear(8, input_dim)
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

# Usage in your loop: 
# High Mean Squared Error (MSE) between input and decoded output = Anomaly Detected!