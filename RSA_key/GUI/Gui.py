import sys

import customtkinter as ctk
import tkinter as tk

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# set modes
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")


class Gui:
    window: ctk.CTk = None
    open_main_button: ctk.CTkButton = None

    sidebar_frame: ctk.CTkFrame = None
    logo_label: ctk.CTkLabel = None

    label_choose_key_size: ctk.CTkLabel = None
    key_size_menu: ctk.CTkOptionMenu = None
    key_size_menu_var: tk.StringVar = None

    label_type_pin: ctk.CTkLabel = None
    pin_entry: ctk.CTkEntry = None

    creating_keys: ctk.CTkLabel = None
    run_button: ctk.CTkButton = None
    exit_button: ctk.CTkButton = None

    generated_keys_frame: ctk.CTkFrame = None
    public_key_label: ctk.CTkLabel = None
    public_key_text: ctk.CTkTextbox = None
    private_key_label: ctk.CTkLabel = None
    private_key_text: ctk.CTkTextbox = None
    encrypted_private_key_label: ctk.CTkLabel = None
    encrypted_private_key_text: ctk.CTkTextbox = None

    gui_width: int = 1100
    gui_height: int = 580

    def __init__(self):
        self.window = ctk.CTk()
        self.show_app()
        self.add_sidebar()
        self.generated_keys_frame()
        self.window.mainloop()

    def show_app(self):
        self.window.title("RSA key generation")
        self.window.geometry(f"{self.gui_width}x{self.gui_height}")
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_rowconfigure(1, weight=4)

    def add_sidebar(self):
        # creating sidebar
        self.sidebar_frame = ctk.CTkFrame(self.window, height=self.gui_height - 40, width=200, corner_radius=10)
        self.sidebar_frame.grid(row=0, column=0, padx=(20, 20), pady=(20, 0), sticky="nsew")
        # adding sidebar content
        self.show_sidebar_labels()
        self.show_key_sizes_to_choose()
        self.show_pin_to_type()
        self.show_buttons()

    def show_sidebar_labels(self):
        # logo/title label
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="RSA key generation",
                                       font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(10, 5))

    def show_key_sizes_to_choose(self):
        self.label_choose_key_size = ctk.CTkLabel(self.sidebar_frame, text="Key Size:")
        self.label_choose_key_size.grid(row=1, column=0, padx=20, pady=(10, 5), sticky="w")
        self.key_size_menu_var = tk.StringVar(value="4096")
        self.key_size_menu = ctk.CTkOptionMenu(self.sidebar_frame, values=["2048", "4096"],
                                               variable=self.key_size_menu_var)
        self.key_size_menu.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="w")

    def show_pin_to_type(self):
        self.label_type_pin = ctk.CTkLabel(self.sidebar_frame, text="Enter PIN to encrypt the key:")
        self.label_type_pin.grid(row=3, column=0, padx=20, pady=(10, 5), sticky="w")
        self.pin_entry = ctk.CTkEntry(self.sidebar_frame, placeholder_text="1234")
        self.pin_entry.grid(row=4, column=0, padx=20, pady=(5, 230), sticky="w")
        self.pin_entry.focus()

    def show_buttons(self):
        self.run_button = ctk.CTkButton(self.sidebar_frame, text="Generate keys", command=self.generate_keys)
        self.run_button.grid(row=6, column=0, padx=(20, 20), pady=(10, 10), sticky="nsew")

        self.exit_button = ctk.CTkButton(self.sidebar_frame, text="Exit", command=self.exit_from_program)
        self.exit_button.grid(row=7, column=0, padx=(20, 20), pady=(10, 20), sticky="nsew")

    def generated_keys_frame(self):
        self.generated_keys_frame = ctk.CTkFrame(self.window, height=self.gui_height-40, width=self.gui_width-300,
                                                 corner_radius=10)
        self.generated_keys_frame.grid(row=0, column=1, rowspan=4, padx=(10, 10), pady=(20, 20), sticky="nsew")
        # adding sidebar content
        self.public_key_label = ctk.CTkLabel(self.generated_keys_frame, text="Public key:")
        self.public_key_label.grid(row=0, column=0, padx=20, pady=(10, 5), sticky="w")
        self.public_key_text = ctk.CTkTextbox(self.generated_keys_frame, height=100, width=750)
        self.public_key_text.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        self.private_key_label = ctk.CTkLabel(self.generated_keys_frame, text="Private key:")
        self.private_key_label.grid(row=2, column=0, padx=20, pady=(10, 5), sticky="w")
        self.private_key_text = ctk.CTkTextbox(self.generated_keys_frame, height=200, width=750)
        self.private_key_text.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="w")

        self.encrypted_private_key_label = ctk.CTkLabel(self.generated_keys_frame, text="Encrypted private key:")
        self.encrypted_private_key_label.grid(row=4, column=0, padx=20, pady=(10, 5), sticky="w")
        self.encrypted_private_key_text = ctk.CTkTextbox(self.generated_keys_frame, height=80, width=750)
        self.encrypted_private_key_text.grid(row=5, column=0, padx=20, pady=(0, 10), sticky="w")

    def generate_keys(self):
        if self.pin_entry.get() == "":
            pin = "1234"
        else:
            pin = self.pin_entry.get()
        key_size = int(self.key_size_menu_var.get())
        # Generowanie kluczy RSA
        key_pair = RSA.generate(key_size)
        # Wyświetlanie kluczy w textboxach
        private_key = key_pair.export_key()
        self.private_key_text.delete("1.0", "end")
        self.private_key_text.insert(tk.INSERT, private_key.decode())
        with open("private_key.txt", "wb") as writer:
            writer.write(private_key.decode())

        public_key = key_pair.publickey().export_key()
        self.public_key_text.delete("1.0", "end")
        self.public_key_text.insert(tk.INSERT, public_key.decode())
        with open("public_key.txt", "w") as writer:
            writer.write(public_key.decode())

        pin_key = pin.encode() * 16  # Pad PIN is 16 bytes (AES block size)
        aes_cipher = AES.new(pin_key[:16], AES.MODE_EAX)
        encrypted_private_key = aes_cipher.encrypt(private_key)
        self.encrypted_private_key_text.delete("1.0", "end")
        self.encrypted_private_key_text.insert(tk.INSERT, encrypted_private_key)
        with open("encrypted_private_key.txt", "wb") as writer:
            writer.write(encrypted_private_key)

        aes_nonce = aes_cipher.nonce

    @staticmethod
    def exit_from_program():
        sys.exit("Program ended successfully! \nBye :)")