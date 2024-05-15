from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Flatten, Conv2D, AveragePooling2D
import pandas as pd
from tensorflow.python.keras.utils.np_utils import to_categorical
from tensorflow.keras.datasets import mnist
from tensorflow.keras import layers, models
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow import keras


def get_model():

    X_train_shape = 12

    model = keras.Sequential([
        layers.Input(shape=(X_train_shape,)),
        layers.Dense(64, activation='relu'),
        layers.Dense(32, activation='relu'),
        layers.Dense(1, activation='sigmoid')  
    ])


    return model
