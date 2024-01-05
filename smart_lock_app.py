import json
import threading
import requests
import socket
from kivy.app import App
from kivy.clock import mainthread
from kivy.uix.label import Label
from kivy.uix.boxlayout import BoxLayout
from kivy.core.window import Window
from kivy.graphics import Color, Rectangle
import sqlite3


class CustomBoxLayout(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(1, 1, 1, 1)  # white background
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self._update_rect, pos=self._update_rect)

    def _update_rect(self, *args):
        self.rect.size = self.size
        self.rect.pos = self.pos

class MyApp(App):
    def build(self):
        # Fix the window size to a typical phone screen size
        Window.size = (360, 640)

        self.layout = CustomBoxLayout(orientation='vertical', padding=[10, 10, 10, 10], spacing=10)

        self.title_label = Label(text='Smart Lock', color=(0, 0, 0, 1), size_hint=(1, None), height=150)
        self.sigma_0_prime_label = Label(
            text='SigmaLprime: ',
            color=(0, 0, 0, 1),
            size_hint=(1, None),
            height=150,
            text_size=(Window.width - 20, None),
            halign='left',
            valign='middle'
        )
        self.sigma_0_double_prime_label = Label(
            text='SigmaLdoubleprime: ',
            color=(0, 0, 0, 1),
            size_hint=(1, None),
            height=200,
            text_size=(Window.width - 20, None),
            halign='left',
            valign='middle'
        )

        # Add the labels at the top of the layout
        self.layout.add_widget(self.title_label)
        self.layout.add_widget(self.sigma_0_prime_label)
        self.layout.add_widget(Label(size_hint_y=None, height=50))  # spacing
        self.layout.add_widget(self.sigma_0_double_prime_label)

        threading.Thread(target=self.fetch_data_from_server).start()
        threading.Thread(target=self.socket_communication).start()

        return self.layout

    def fetch_data_from_server(self):
        url = 'http://192.168.1.163:8000/register_smart_lock'
        response = requests.get(url)

        if response.status_code == 200:
            self.store_data_in_sqlite(response.text)
        else:
            print("Failed to fetch data from server")

    @mainthread
    def update_ui(self, sigma_0_prime, sigma_0_double_prime):
        self.sigma_0_prime_label.text = f'SigmaLprime: {sigma_0_prime}'
        self.sigma_0_double_prime_label.text = f'SigmaLdoubleprime: {sigma_0_double_prime}'

    def store_data_in_sqlite(self, response_data):
        try:
            data = json.loads(response_data)
            sigma_0_prime = data['sigma_0_prime']
            sigma_0_double_prime = data['sigma_0_double_prime']


            # Update UI
            self.update_ui(sigma_0_prime, sigma_0_double_prime)

            # SQLite database operations (simplified example)
            conn = sqlite3.connect('smartlock.db')
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS mytable 
                              (sigma_0_prime TEXT, sigma_0_double_prime TEXT)''')
            cursor.execute('''INSERT INTO mytable (sigma_0_prime, sigma_0_double_prime) 
                              VALUES (?, ?)''', (sigma_0_prime, sigma_0_double_prime))
            conn.commit()
            conn.close()
        except Exception as e:
            print("Error:", e)

    def get_sigma_values_from_db(self):
        try:
            conn = sqlite3.connect('smartlock.db')
            cursor = conn.cursor()
            cursor.execute('''SELECT sigma_0_prime, sigma_0_double_prime FROM mytable ORDER BY ROWID DESC LIMIT 1''')
            data = cursor.fetchone()
            conn.close()
            if data:
                return data[0], data[1]  # sigma_0_prime, sigma_0_double_prime
            else:
                return None, None
        except Exception as e:
            print("Database Error:", e)
            return None, None
    
    def store_logs_in_sqlite(self, log):
        try: 

            # SQLite database operations (simplified example)
            conn = sqlite3.connect('smartlock.db')
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS logtable 
                              (log TEXT)''')
            cursor.execute('''INSERT INTO mytable (log) 
                              VALUES (?)''', (log))
            conn.commit()
            conn.close()
        except Exception as e:
            print("Error:", e)

    def change_title_to_authentication_success(self):
      self.title_label.text = 'Authentification réussie'
    
    def socket_communication(self):
        host = '127.0.0.1'
        port = 12345

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f'Connected by {addr}')
                while True:
                    data = conn.recv(1024)
                    response = json.loads(data.decode())
                    if not data:
                        break  # Exit the loop if no data is received
                    else:
                        if response["req"] == "request":
                            # Proceed with fetching and sending sigma values
                            sigmaLprime, sigmaLdoubleprime = self.get_sigma_values_from_db()
                            if sigmaLprime is not None and sigmaLdoubleprime is not None:
                                data_to_send = {
                                    "sigmaLprime": sigmaLprime,
                                    "sigmaLdoubleprime": sigmaLdoubleprime
                                }
                                conn.sendall(json.dumps(data_to_send).encode())
                            else:
                                conn.sendall(json.dumps({"error": "No data"}).encode())
                        elif response["req"] == "1":
                             data_to_send = {
                                    "confi": "1"
                                }
                             conn.sendall(json.dumps(data_to_send).encode())
                        elif response["req"] == "2":
                            data_to_send = {
                                    "NT": "1"
                                }
                            conn.sendall(json.dumps(data_to_send).encode())
                        else:
                            self.change_title_to_authentication_success()
                            data_to_send = {
                                    "confi": "1"
                                }
                            conn.sendall(json.dumps(data_to_send).encode())
                             
if __name__ == '__main__':
    MyApp().run()
