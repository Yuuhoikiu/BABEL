"""
a tool for text encrypt and decrypt
"""

import importlib.metadata
import sys
from PySide6 import QtWidgets
import base64
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QInputDialog, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QFileDialog, QMessageBox, QHBoxLayout
from PySide6.QtGui import QAction, QIcon, QPixmap
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class Babel(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Babel")
        self.setGeometry(100, 100, 720, 360)

        # 设置文本编辑区域
        self.text_area = QTextEdit(self)
        self.text_area.append('Welcome to using Babel software. Babel is a software that can encrypt and decrypt documents, protecting your documents securely. However, please note that the document is built with a fixed key, and people who use the same software can decrypt your document. Remember to set a custom key or generate a random key to protect the security of your documents. ——The author of Babel software')


        # 创建按钮和布局
        self.create_buttons()

        # 创建菜单
        self.create_menu()

        # 设置中心控件
        self.setCentralWidget(self.text_area)

        self.show()

    def create_buttons(self):
        # creation按钮
        new_button = QPushButton("creation", self)
        new_button.clicked.connect(self.new_note)

        # open按钮
        open_button = QPushButton("open", self)
        open_button.clicked.connect(self.open_note)

        # save按钮
        save_button = QPushButton("save", self)
        save_button.clicked.connect(self.save_note)
        

    

        # 布局
        button_layout = QVBoxLayout()
        button_layout.addWidget(new_button)
        button_layout.addWidget(open_button)
        button_layout.addWidget(save_button)
        # button_layout.addWidget(encrypt_button)  # 添加加密按钮

        # Widget to contain the buttons
        buttons_widget = QWidget()
        buttons_widget.setLayout(button_layout)

        # 主布局
        main_layout = QHBoxLayout()
        main_layout.addWidget(self.text_area)
        main_layout.addWidget(buttons_widget)

        # 主窗口的中心控件
        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def create_menu(self):
        # 创建菜单栏
        menu_bar = self.menuBar()
        
        # creation菜单
        new_menu = menu_bar.addMenu('creation')
        new_action = new_menu.addAction("creation")
        new_action.triggered.connect(self.new_note)

    
        # open菜单
        open_menu = menu_bar.addMenu('open')
        open_action = open_menu.addAction("open")
        open_action.triggered.connect(self.open_note)

        # save菜单
        save_menu = menu_bar.addMenu('save')
        save_action = save_menu.addAction("save")
        save_action.triggered.connect(self.save_note)

        # 加密菜单
        encrypt_menu = menu_bar.addMenu('encrypt')
        encrypt_action = encrypt_menu.addAction("encrypt")
        encrypt_action.triggered.connect(self.encrypt_note)

        # decrypt菜单
        decrypt_menu = menu_bar.addMenu('decrypt')
        decrypt_action = decrypt_menu.addAction("decrypt")
        decrypt_action.triggered.connect(self.decrypt_note)

        # exit菜单
        exit_menu = menu_bar.addMenu('exit')
        exit_action = exit_menu.addAction("exit")
        exit_action.triggered.connect(self.close)


        # 创建菜单栏
        menu_bar = self.menuBar()
        # 设置自定义密钥菜单
        set_key_menu = menu_bar.addMenu('set a custom key')
        set_key_action = set_key_menu.addAction("set a custom key")
        set_key_action.triggered.connect(self.set_custom_key)
        # generae random key菜单
        random_key_menu = menu_bar.addMenu('generae random key')
        random_key_action = random_key_menu.addAction("generae random key")
        random_key_action.triggered.connect(self.generate_random_key)  

        
        menu_bar = self.menuBar()
        # save background image菜单
        background_menu = menu_bar.addMenu('save background image')
        background_action = background_menu.addAction("save background image")
        background_action.triggered.connect(self.load_background_image)



    def set_custom_key(self):
        # 这里可以添加设置自定义密钥的逻辑
        text, ok = QInputDialog.getText(None, "set a custom key", "Please enter your custom key:")
        if ok and text:
            # 检查用户输入的密钥长度是否为32个字节
            if len(text) == 44:  # 44个字符对应32个字节的密钥，因为密钥是用 base64 编码的
                try:
                    # 尝试通过 base64 解码密钥
                    key = base64.b64decode(text)
                    if len(key) == 32:  # 检查解码后的密钥长度是否为32个字节
                        with open("key.key", "wb") as key_file:
                            key_file.write(key)
                        QMessageBox.information(None, "Key Setting", "Custom key has been successfully set and saved as 'Babel.key'.")
                    else:
                        QMessageBox.warning(None, "Invalid Key", "The custom key must be 32 bytes in length.")
                except Exception as e:
                    QMessageBox.warning(None, "Error", f"Failed to set key: {e}")
            else:
                QMessageBox.warning(None, "Invalid Key", "The custom key must be 32 bytes in length (44 characters in base64 encoding).")

    def generate_random_key(self):
        # 生成一个随机的字节序列
        random_bytes = os.urandom(32)
        
        # 将字节序列编码为base64字符串
        base64_encoded = base64.b64encode(random_bytes).decode('utf-8')
        
        # 写入文件
        with open("key.key", "wb") as key_file:
            key_file.write(random_bytes)
        
        # 显示密钥已成功生成的消息
        QMessageBox.information(None, "Key Generation", "Random key has been successfully generated and saved as 'Babel.key'.")


    def new_note(self):
        self.text_area.clear()

    def open_note(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self,"Open Note", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            with open(file_name, 'r') as file:
                note_text = file.read()
                self.text_area.setPlainText(note_text)

    def save_note(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Note", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            with open(file_name, 'w') as file:
                text = self.text_area.toPlainText()
                file.write(text)
            QMessageBox.information(self, "save", "Note has been saved to" + file_name)


            # 定义方法以加载并save background image
    def load_background_image(self):
        # 设置文件对话框的选项，目前为空
        options = QFileDialog.Options()

        # open一个文件对话框，让用户选择图片文件
        # 参数分别为：父窗口、对话框标题、默认open路径、文件过滤器、选项
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Background Image", "", "Image Files (*.png *.jpg *.bmp)", options=options)

        # 如果用户选择了文件
        if file_name:
            # 使用选中的文件路径创建一个QPixmap对象
            pixmap = QPixmap(file_name)

            # 将图片缩放到与文本编辑区相适应的大小，保持宽高比，使用平滑变换
            scaled_pixmap = pixmap.scaled(self.text_area.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)

            # 设置文本编辑区的背景为缩放后的图片
            self.text_area.setBackgroundPixmap(scaled_pixmap)



    def encrypt_note(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Note to Encrypt", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            with open(file_name, 'rb') as file:
                data = file.read()

            key = b'\x00'*32
            iv = os.urandom(16)  # 生成一个128位的初始化向量

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()

            encrypted_file_name = file_name + '.enc'
            with open(encrypted_file_name, 'wb') as file:
                file.write(iv + encrypted_data)  # 将初始化向量也save到文件中

            QMessageBox.information(self, "Encrypt", f"Note has been encrypted and saved as {encrypted_file_name}")

    def decrypt_note(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Note to Decrypt", "", "Encrypted Files (*.enc);;All Files (*)", options=options)
    
        if file_name:
            with open(file_name, 'rb') as file:
               iv = file.read(16)  # 读取前16字节作为初始化向量
               encrypted_data = file.read()  # 读取剩余的数据作为加密内容
               
               
               key = b'\x00'*32 


            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            decrypted_file_name = os.path.splitext(file_name)[0]  # 去掉.enc扩展名
            with open(decrypted_file_name, 'wb') as file:
                file.write(decrypted_data)

            QMessageBox.information(self, "Decrypt", f"Note has been decrypted and saved as {decrypted_file_name}")



# def main():
#     # Linux desktop environments use an app's .desktop file to integrate the app
#     # in to their application menus. The .desktop file of this app will include
#     # the StartupWMClass key, set to app's formal name. This helps associate the
#     # app's windows to its menu item.
#     #
#     # For association to work, any windows of the app must have WMCLASS property
#     # set to match the value set in app's desktop file. For PySide6, this is set
#     # with setApplicationName().

#     # Find the name of the module that was used to start the app
#     app_module = sys.modules["__main__"].__package__
#     # Retrieve the app's metadata
#     metadata = importlib.metadata.metadata(app_module)

#     QtWidgets.QApplication.setApplicationName(metadata["Formal-Name"])

#     # app = QtWidgets.QApplication(sys.argv)
#     # main_window = Babel()
#     # main_window.show()
#     # sys.exit(app.exec())






def main():
    # Linux desktop environments use an app's .desktop file to integrate the app
    # in to their application menus. The .desktop file of this app will include
    # the StartupWMClass key, set to app's formal name. This helps associate the
    # app's windows to its menu item.
    #
    # For association to work, any windows of the app must have WMCLASS property
    # set to match the value set in app's desktop file. For PySide6, this is set
    # with setApplicationName().

    # Find the name of the module that was used to start the app
    app_module = sys.modules["__main__"].__package__
    # Retrieve the app's metadata
    metadata = importlib.metadata.metadata(app_module)

    QtWidgets.QApplication.setApplicationName(metadata["Formal-Name"])

    app = QtWidgets.QApplication(sys.argv)
    main_window = Babel()
    sys.exit(app.exec())

# if __name__ == "__main__":
#     app = QApplication(sys.argv)
#     window = Babel()
#     window.show()
#     sys.exit(app.exec())

