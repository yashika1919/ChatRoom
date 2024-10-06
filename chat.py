import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QTextEdit, QPushButton, QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt, QSize
import mysql.connector
import socket
import threading

HOST = '103.92.103.198'  # Replace with the server's IP address
PORT = 57532 # Replace with the server's port

# Connect to MySQL database
connection = mysql.connector.connect(
    host="localhost",
    user="root",
    password="1234",
    database="chat_application"
)

# Create a table to store user credentials
cursor = connection.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (username VARCHAR(255) PRIMARY KEY, password VARCHAR(255))")
connection.commit()

class SignUpLoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Chat Application - Sign Up / Login')
        self.resize(300, 150)

        self.username_label = QLabel('Username:')
        self.username_input = QLineEdit()
        self.password_label = QLabel('Password:')
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.login_button = QPushButton('Login')
        self.signup_button = QPushButton('Sign Up')

        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.signup_button)
        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.login_button.clicked.connect(self.login)
        self.signup_button.clicked.connect(self.signup)

    def login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if authenticate_user(username, password):
            chat_window = ChatWindow(username)
            chat_window.show()
            self.close()
        else:
            QMessageBox.warning(self, 'Login Failed', 'Invalid username or password')

    def signup(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if signup_user(username, password):
            QMessageBox.information(self, 'Sign Up Successful', 'User created successfully. You can now log in.')
        else:
            QMessageBox.warning(self, 'Sign Up Failed', 'Failed to create user. Please try again.')

def authenticate_user(username, password):
    cursor = connection.cursor()
    cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()

    if result is None:
        return False

    stored_password = result[0]
    return password == stored_password

def signup_user(username, password):
    cursor = connection.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        connection.commit()
        return True
    except mysql.connector.Error as error:
        print(f"Failed to insert user into database: {error}")
        return False

class ChatWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.setWindowTitle('Chat Application - Chat')
        self.resize(600, 400)
        self.username = username

        self.message_label = QLabel('Message:')
        self.message_input = QTextEdit()
        self.send_button = QPushButton('Send')
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.browse_button = QPushButton('Browse Image')
        self.send_image_button = QPushButton('Send Image')

        layout = QVBoxLayout()
        layout.addWidget(self.message_label)
        layout.addWidget(self.message_input)
        layout.addWidget(self.send_button)
        layout.addWidget(self.image_label)
        layout.addWidget(self.browse_button)
        layout.addWidget(self.send_image_button)
        self.setLayout(layout)

        self.send_button.clicked.connect(self.send_message)
        self.browse_button.clicked.connect(self.browse_image)
        self.send_image_button.clicked.connect(self.send_image)

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.client_socket.connect((HOST, PORT))
        except ConnectionRefusedError:
            QMessageBox.critical(self, 'Connection Error', 'Failed to connect to the server')
            sys.exit()

        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

    def send_message(self):
        message = self.message_input.toPlainText()
        self.client_socket.sendall(f"MESSAGE {self.username} {message}".encode())
        self.message_input.clear()

    def receive_messages(self):
        while True:
            data = self.client_socket.recv(1024).decode()

            if data.startswith('MESSAGE'):
                _, sender, message = data.split(' ', 2)
                self.display_message(sender, message)
            else:
                QMessageBox.information(self, 'New Message', 'You have received a new message')

    def display_message(self, sender, message):
        self.message_input.append(f"{sender}: {message}")

    def browse_image(self):
        file_dialog = QFileDialog()
        image_path, _ = file_dialog.getOpenFileName(self, 'Select Image', '', 'Images (*.png *.xpm *.jpg *.bmp *.gif)')

        if image_path:
            pixmap = QPixmap(image_path).scaled(QSize(200, 200), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.image_label.setPixmap(pixmap)

    def send_image(self):
        image_path, _ = QFileDialog.getOpenFileName(self, 'Select Image', '', 'Images (*.png *.xpm *.jpg *.bmp *.gif)')

        if image_path:
            try:
                with open(image_path, 'rb') as file:
                    image_data = file.read()

                self.client_socket.sendall(f"IMAGE {self.username}".encode() + image_data)
                QMessageBox.information(self, 'Image Sent', 'Image sent successfully')
            except Exception as e:
                QMessageBox.critical(self, 'Error Sending Image', str(e))

app = QApplication(sys.argv)
signup_login_window = SignUpLoginWindow()
signup_login_window.show()
sys.exit(app.exec_())
