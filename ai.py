import threading
import socket
import logging
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import tensorflow as tf

history = []

def create_model(input_shape):
    model = tf.keras.Sequential([
        tf.keras.layers.Conv1D(filters=32, kernel_size=3, activation='relu', input_shape=input_shape),
        tf.keras.layers.MaxPooling1D(pool_size=2),
        tf.keras.layers.Flatten(),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    return model

def handle_request(sock, ip_address, model):
    request = sock.recv(1024).decode()
    data = np.fromstring(request, dtype=np.uint8)
    prediction = model.predict(np.array([data]))
    if prediction < 0.5:
        logging.info('Received a normal request from {}'.format(ip_address))
        # Handle normal request
    else:
        logging.warning('Received an attack request from {}'.format(ip_address))
        # Handle attack request

def analyze_requests():
    global history

    # Load request history from database
    data = pd.read_csv('request_history.csv')

    # Standardize data
    scaler = StandardScaler()
    data = scaler.fit_transform(data)

    # Split data into inputs and labels
    X = data[:, :-1]
    y = data[:, -1]

    # Create and train model
    model = create_model(X.shape[1:])
    model.fit(X, y, epochs=10, batch_size=32)

    # Save model weights
    model.save_weights('model_weights.h5')

    # Clear request history
    history = []

def main():
    # Create database for request history
    with open('request_history.csv', 'w') as f:
        f.write('data,label\n')

    # Create socket and bind to port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', 8000))
    s.listen()

    # Create and compile model
    model = create_model((1024, 1))

    # Start analysis thread
    threading.Thread(target=analyze_requests, daemon=True).start()

    while True:
        # Accept incoming connection
        sock, addr = s.accept()
        ip_address = addr[0]
        logging.info('Accepted connection from {}'.format(ip_address))

        # Handle request
        threading.Thread(target=handle_request, args=(sock, ip_address, model)).start()

        # Save request to history
        data = sock.recv(1024).decode()
        with open('request_history.csv', 'a') as f:
            f.write('{},{}\n'.format(data, 1))

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
