import requests
import socket
import json
from threading import Thread
from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.clock import Clock
from kivy.core.window import Window
from Symetric import SymmetricCrypto  # Assuming this is your custom module for cryptography
import ast
import sqlite3
from kivy.uix.anchorlayout import AnchorLayout
from charm.toolbox.pairinggroup import PairingGroup, ZR
import base64
from hashlib import sha256


class RegisterScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        layout = BoxLayout(orientation='vertical', spacing=10, padding=20)
        self.add_widget(layout)

        # Adjusted the order to place ID and sigma_p at the top
        self.id_label = Label(text='ID: Waiting for response...', color=(0, 0, 0, 1), size_hint_y=None, height=250, text_size=(self.width, None), halign='left', valign='top')
        layout.add_widget(self.id_label)

        self.sigma_p_label = Label(text='Sigma P: Waiting for response...', color=(0, 0, 0, 1), size_hint_y=None, height=300, text_size=(self.width, None), halign='left', valign='top')
        layout.add_widget(self.sigma_p_label)


    def update_response(self, ID, sigma_p):
        self.id_label.text = f'ID: {ID}'
        self.sigma_p_label.text = f'Sigma P: {sigma_p}'
    
    def on_enter(self):
        # This method is automatically called when this screen is displayed
        app = App.get_running_app()
        app.retrieve_data_from_database()

class AuthenticationScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        layout = BoxLayout(orientation='vertical', padding=[10, 10, 10, 10], spacing=10)
        self.add_widget(layout)

        # Titre au sommet
        self.auth_status_label = Label(
            text='Smart lock key',
            color=(0, 0, 0, 1),
            size_hint=(1, None),
            height=150,
            halign='left',
            valign='middle'
        )
        layout.add_widget(self.auth_status_label)

        # Label pour cprims
        self.cprims_label = Label(
            text='Cprims: En attente...',
            color=(0, 0, 0, 1), size_hint_y=None, height=250, text_size=(self.width, None), halign='left', valign='top'
        )
        layout.add_widget(self.cprims_label)

        # Espacement
        layout.add_widget(Label(size_hint_y=None, height=50))

        # Label pour zs
        self.zs_label = Label(
            text='Zs: En attente...',
            color=(0, 0, 0, 1), size_hint_y=None, height=150, text_size=(self.width, None), halign='left', valign='top'
        )
        layout.add_widget(self.zs_label)

    def update_response(self, cprims, zs):
        self.auth_status_label = "Smart lock key"
        self.cprims_label.text = f'Cprims: {cprims}'
        self.zs_label.text = f'Zs: {zs}'


class MainScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Main layout that will contain all widgets
        main_layout = BoxLayout(orientation='vertical', spacing=10)
        self.add_widget(main_layout)

        # Title label at the top
        title_label = Label(text='Master App', font_size='24sp', color=(0, 0, 0, 1), size_hint=(1, 0.2))
        main_layout.add_widget(title_label)

        # AnchorLayout to center the buttons in the middle
        anchor_layout = AnchorLayout(anchor_x='center', anchor_y='center', size_hint=(1, 0.6))
        main_layout.add_widget(anchor_layout)

        # BoxLayout for the buttons
        button_layout = BoxLayout(orientation='vertical', spacing=10, size_hint=(None, None), size=(200, 120))
        anchor_layout.add_widget(button_layout)

        # Register button
        btn_register = Button(text="Register", size_hint=(None, None), size=(200, 50))
        btn_register.bind(on_press=self.register_action)
        button_layout.add_widget(btn_register)

        # Authenticate button
        btn_authenticate = Button(text="Authenticate", size_hint=(None, None), size=(200, 50))
        btn_authenticate.bind(on_press=self.authenticate_action)
        button_layout.add_widget(btn_authenticate)

    def register_action(self, instance):
        Thread(target=self.perform_registration).start()

    def authenticate_action(self, instance):
        self.manager.current = 'authentication'
        Thread(target=self.perform_authentication).start()

    def perform_registration(self):
        app = App.get_running_app()
        data_req = {
            "req" : "request"
        }
        fetch_sigma_values_from_server = app.send_socket_data(data_req)
        sigmaLprime = fetch_sigma_values_from_server.get('sigmaLprime')
        sigmaLdoubleprime = fetch_sigma_values_from_server.get('sigmaLdoubleprime')
        if sigmaLprime and sigmaLdoubleprime:
            response_text = app.send_to_register_master(sigmaLprime, sigmaLdoubleprime)
            confi = {
                "req" : "1"
            }
            send_confirm = app.send_socket_data(confi)
            Clock.schedule_once(lambda dt: self.update_ui(response_text))
    
    def update_ui(self, response_text):
        app = App.get_running_app()
        # Update this line as per your actual response structure
        ID, sigma_p = "Sample ID", "Sample Sigma P"
        app.register_screen.update_response(ID, sigma_p)
        app.screen_manager.current = 'register'
    
    def perform_authentication(self):
        app = App.get_running_app()
        q, ID, sigma_p, g = app.retrieve_data_from_database_for_auth()
        ms = app.get_ms()  # Replace with your actual master secret
        req = {
            "req" : "2"
        }
        auth_message=app.send_socket_data(req)
        NT = auth_message.get("NT")
        auth_values = app.generate_values(sigma_p, g, ID, ms, q, NT)
        response = app.send_to_authenticate_master(auth_values)
        cprims = response["cprims"]
        zs = response["zs"]
        app.auth_screen.update_response(cprims, zs)
        auth_data = { 
            "req": "6" 
        }
        auth_smart_lock = app.send_socket_data(auth_data)
        

class MyApp(App):
    def build(self):
        self.screen_manager = ScreenManager()
        self.main_screen = MainScreen(name='main')
        self.register_screen = RegisterScreen(name='register')
        self.screen_manager.add_widget(self.main_screen)
        self.screen_manager.add_widget(self.register_screen)
        self.auth_screen = AuthenticationScreen(name='authentication')
        self.screen_manager.add_widget(self.auth_screen)
        
        # Set the window size to mimic a typical smartphone screen
        Window.size = (360, 640)
        Window.clearcolor = (1, 1, 1, 1)  # White background

        self.socket_connection = None
        self.setup_socket_connection()
        return self.screen_manager
    
    def setup_socket_connection(self):
        host = '127.0.0.1'
        port = 12345
        try:
            self.socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket_connection.connect((host, port))
        except Exception as e:
            print("Erreur de connexion socket :", e)
    
    def send_socket_data(self, data):
        if self.socket_connection:
            try:
                self.socket_connection.sendall(json.dumps(data).encode())
                response = self.socket_connection.recv(1024)
                return json.loads(response.decode())
            except Exception as e:
                print("Erreur d'envoi/réception de données socket :", e)
                return None

    def on_stop(self):
        if self.socket_connection:
            self.socket_connection.close()
        
    def generate_values(self, sigma_p_str, g_str, IDp, ms, q, NT):
            group = PairingGroup('SS512')

            # Deserialize values
            g = group.deserialize(base64.b64decode(g_str))
            sigma_p = group.deserialize(base64.b64decode(sigma_p_str))
            IDp = group.init(ZR, IDp)
            ms = group.init(ZR, ms)

            # Generate random values in Z_q
            a_p = group.random(ZR)
            b_p = group.random(ZR)
            d_p = group.random(ZR)

            # Perform calculations
            sigma_p_prime = sigma_p ** a_p
            sigma_p_double_prime = (sigma_p_prime ** (-IDp)) * (g ** a_p)
            T_p = (sigma_p_prime ** d_p) * (g ** b_p)

            # Hash calculation
            sigma_p_double_prime_bytes = group.serialize(sigma_p_double_prime)
            T_p_bytes = group.serialize(T_p)
            ms_bytes = group.serialize(ms)

            hash_input = sigma_p_double_prime_bytes + T_p_bytes + ms_bytes
            c_p = int(sha256(hash_input).hexdigest(), 16) % int(q)  # Use q here

            # Further calculations with Python integers
            S_ap = (int(b_p) - c_p * int(a_p)) % int(q)   # Convert group elements to Python integers
            SIDp = (int(d_p) + c_p * int(IDp)) % int(q)   # Convert group elements to Python integers

            # Serialize and return the calculated values
            return {
                    'sigmapPrime': base64.b64encode(group.serialize(sigma_p_prime)).decode(),
                    'sigmapDoublePrime': base64.b64encode(sigma_p_double_prime_bytes).decode(),
                    'cp': str(c_p),
                    'Sap': str(S_ap),
                    'SIDp': str(SIDp),
                    'NT': str(NT)
            }

    def send_to_authenticate_master(self, auth_values):
            url = "http://192.168.1.163:8000/authentification_master"
            try:
                    response = requests.post(url, json=auth_values)
                    if response.status_code == 200:
                        return response.json()
                    else:
                        return "Authentication failed: " + str(response.text)
            except Exception as e:
                    print("HTTP request error:", e)
                    return "Authentication failed"

    def get_ms(self):
            url = "http://192.168.1.163:8000/ask_authentification_master"
            response = requests.get(url)
            if response.status_code == 200:
                ms_j = response.json()
                return ms_j['ms']
            else:
                print("Initialization failed.")
                print("Status Code:", response.status_code)
                print("Response:", response.text)
        
    def retrieve_data_from_database_for_auth(self):
            try:
                conn = sqlite3.connect('master.db')
                cursor = conn.cursor()
                cursor.execute("SELECT q, ID, sigma_p, g FROM mytable ORDER BY ROWID DESC LIMIT 1")
                data = cursor.fetchone()
                conn.close()

                if data:
                    q, ID, sigma_p, g = data
                    return q, ID, sigma_p, g
                else:
                    print("No data found in database for authentication")
                    return None, None, None, None
            except sqlite3.Error as e:
                print("Database error:", e)
                return None, None, None, None

    def send_to_register_master(self, sigmaLprime, sigmaLdoubleprime):
        url = "http://192.168.1.163:8000/register_master"
        data = {
            "sigma0Prime": sigmaLprime,
            "sigma0DoublePrime": sigmaLdoubleprime
        }
        try:
            response = requests.post(url, json=data)
            if response.status_code == 200:
                crypto = SymmetricCrypto()
                password = "5a88740AD4"
                key = crypto.generate_key(password)
                data = response.json()
                sessionID = data['session_ID']
                payload = ast.literal_eval(data['payload'])
                q = data['q']
                g = data['g']

                payload_data = crypto.decrypt(payload, key)
                decrypted_string = payload_data.decode('utf-8')
                data_list = decrypted_string.split('|')
                ID = data_list[0]
                sigma_p = data_list[1]
                # Insert data into SQLite database
                self.store_data_in_database(sessionID, ID, sigma_p, q, g)
                return "Registration successful"
            else:
                return "Registration failed: " + str(response.text)
        except Exception as e:
            print("HTTP request error:", e)
            return "Registration failed"
    
    

    def store_data_in_database(self, sessionID, ID, sigma_p, q, g):
        conn = sqlite3.connect('master.db')
        cursor = conn.cursor()

        # Create table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS mytable 
                        (sessionID TEXT, ID TEXT, sigma_p TEXT, q TEXT, g TEXT)''')

        # Insert data into table
        cursor.execute('''INSERT INTO mytable (sessionID, ID, sigma_p, q, g) 
                        VALUES (?, ?, ?, ?, ?)''', (sessionID, ID, sigma_p, q, g))

        conn.commit()
        conn.close()
    
    def retrieve_data_from_database(self):
        try:
            conn = sqlite3.connect('master.db')
            cursor = conn.cursor()
            cursor.execute("SELECT ID, sigma_p FROM mytable ORDER BY ROWID DESC LIMIT 1")
            data = cursor.fetchone()
            conn.close()

            if data:
                ID, sigma_p = data
                self.register_screen.update_response(ID, sigma_p)
            else:
                self.register_screen.update_response("No data", "No data")
        except sqlite3.Error as e:
            print("Database error:", e)
            self.register_screen.update_response("Database error", "Database error")

if __name__ == '__main__':
    MyApp().run()
