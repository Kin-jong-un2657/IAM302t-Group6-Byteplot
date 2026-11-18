import torch
from torch import nn
from torch.nn import functional as F

CHANNELS = {"C1": [0], "C2": [0, 1], "C3": [0, 2], "C4": [0, 1, 2]}


class ByteplotCNN(nn.Module):
    def __init__(self, channels):
        super().__init__()
        blocks = []
        for output in (16, 32, 64):
            blocks.extend([nn.Conv2d(channels, output, 3, padding=1),
                           nn.GroupNorm(4, output), nn.ReLU(), nn.MaxPool2d(2)])
            channels = output
        self.features = nn.Sequential(*blocks)
        self.head = nn.Linear(64, 2)

    def forward(self, x, mask):
        features = self.features(x)
        # Same valid-byte mask for every configuration; no extra input channel.
        weights = F.interpolate(mask, size=features.shape[-2:], mode="area")
        pooled = (features * weights).sum((2, 3)) / weights.sum((2, 3)).clamp_min(1e-6)
        return self.head(pooled)


class EntropyProbe(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(nn.Conv2d(1, 16, 5, padding=2), nn.ReLU(),
                                 nn.Conv2d(16, 32, 5, padding=2), nn.ReLU(),
                                 nn.Conv2d(32, 16, 5, padding=2), nn.ReLU(),
                                 nn.Conv2d(16, 1, 1), nn.Sigmoid())

    def forward(self, x):
        return self.net(x)


def masked_mse(pred, target, mask):
    return ((pred - target).square() * mask).sum() / mask.sum().clamp_min(1)
