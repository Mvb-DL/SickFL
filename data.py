
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import codecs
import pickle

def prepare_data(data):

    #prepares the data for the model

    data['TotalBytes'] = data['BytesSent'] + data['BytesReceived']
    data['TotalPackets'] = data['PacketsSent'] + data['PacketsReceived']

    anomaly_data = data[data['IsAnomaly'] == 1]
    oversampled_data = pd.concat([data, anomaly_data], axis=0)

    X = oversampled_data.drop(columns=['IsAnomaly'])  # Features
    y = oversampled_data['IsAnomaly']  # Labels

    return X, y


def get_data():

    #calls data from folder
    data_path='./data/synthetic_network_traffic_short.csv'

    data = pd.read_csv(data_path)

    X, y = prepare_data(data)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, y_train, X_test, y_test



def decode(b64_str):
    return pickle.loads(codecs.decode(b64_str.encode(), "base64"))

def encode_layer(layer):
    return codecs.encode(pickle.dumps(layer), "base64").decode()
