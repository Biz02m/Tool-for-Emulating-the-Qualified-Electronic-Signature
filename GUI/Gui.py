import sys

import customtkinter as ctk
from customtkinter import filedialog
import tkinter as tk
import usbDetection as det
import signature as sign

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# set modes
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")


class Gui:
    window: ctk.CTk = None
    open_main_button: ctk.CTkButton = None

    left_frame: ctk.CTkFrame = None
    logo_label: ctk.CTkLabel = None
    detect_usb_button: ctk.CTkButton = None
    label_no_usb: ctk.CTkLabel = None

    label_upload_document: ctk.CTkLabel = None
    label_uploaded_pin: ctk.CTkLabel = None
    upload_pin_button: ctk.CTkButton = None
    upload_file_button1: ctk.CTkButton = None
    file_path = None
    label_file_path: ctk.CTkLabel = None
    sign_file_button: ctk.CTkButton = None

    file_path_to_verify = None
    label_file_path_to_verify: ctk.CTkLabel = None
    label_signed_file: ctk.CTkLabel = None

    label_type_pin: ctk.CTkLabel = None
    pin_entry: ctk.CTkEntry = None
    upload_file_to_verify_button: ctk.CTkButton = None

    exit_button: ctk.CTkButton = None

    right_frame: ctk.CTkFrame = None
    label_upload_file_to_verify: ctk.CTkLabel = None
    label_verification: ctk.CTkLabel = None
    label_signature: ctk.CTkLabel = None
    upload_signature_button: ctk.CTkButton = None
    signature_path = None
    label_signature_path: ctk.CTkLabel = None
    file_to_verify_uploaded: bool = False
    signature_uploaded: bool = False

    key = None
    aes_nonce = None
    deciphered_key = None
    gui_width: int = 600
    gui_height: int = 580

    def __init__(self):
        self.window = ctk.CTk()
        self.show_app()
        self.add_left()
        self.add_right()
        self.window.mainloop()

    def show_app(self):
        self.window.title("Document Signature")
        self.window.geometry(f"{self.gui_width}x{self.gui_height}")
        #self.window.grid_rowconfigure(0, weight=1)
        #self.window.grid_rowconfigure(1, weight=1)

    def add_left(self):
        # creating sidebar
        self.left_frame = ctk.CTkFrame(self.window, height=self.gui_height - 40, width=700, corner_radius=10)
        self.left_frame.grid(row=0, column=0, columnspan=1,  padx=(20, 20), pady=(20, 0), sticky="nsew")
        # adding sidebar content
        self.show_sidebar_labels()
        self.show_buttons()

    def show_sidebar_labels(self):
        # logo/title label
        self.logo_label = ctk.CTkLabel(self.left_frame, text="Document Signature",
                                       font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(10, 5))
        self.label_no_usb = ctk.CTkLabel(self.left_frame, text="No USB drive detected!",
                                         text_color="red")
        self.label_no_usb.grid(row=1, column=0, padx=20, pady=(10, 5), sticky="w")
        self.detect_usb_button = ctk.CTkButton(self.left_frame, text="Start Detecting USB Drive",
                                                  command=self.detect_usb)
        self.detect_usb_button.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="w")

    def detect_usb(self):
        drive = det.detect_new_drive()
        self.show_usb_conneted(drive)
        self.label_no_usb.destroy()
        self.detect_usb_button.destroy()

    def show_usb_conneted(self, drive):
        self.key, self.aes_nonce = det.get_key_nonce(drive)
        self.show_pin_to_type()
        self.upload_pin_button = ctk.CTkButton(self.left_frame, text="Upload Pin",
                                               command=self.decrypt_key)
        self.upload_pin_button.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="w")
        self.label_upload_document = ctk.CTkLabel(self.left_frame, text="Upload Document to sign:")
        self.label_upload_document.grid(row=4, column=0, padx=20, pady=(10, 5), sticky="w")
        self.upload_file_button1 = ctk.CTkButton(self.left_frame, text="Upload file",
                                                  command=self.choose_file_to_upload)
        self.upload_file_button1.grid(row=5, column=0, padx=20, pady=(0, 10), sticky="w")

    def decrypt_key(self):
        print(f"Key: {self.pin_entry.get()}")
        self.deciphered_key = det.decipher(self.key, self.aes_nonce, self.pin_entry.get())
        print(f"Deciphered key: {self.deciphered_key}")
        with open("private_key.txt", "wb") as writer:
            writer.write(self.deciphered_key)
        self.upload_pin_button.destroy()
        self.label_uploaded_pin = ctk.CTkLabel(self.left_frame, text="Uploaded Pin: " + self.pin_entry.get(),
                                               text_color="green")
        self.label_uploaded_pin.grid(row=3, column=0, padx=20, pady=(10, 5), sticky="w")

    def choose_file_to_upload(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            print(f"File path: {self.file_path}")
            self.upload_file_button1.destroy()
            self.label_file_path = ctk.CTkLabel(self.left_frame, text=self.file_path, wraplength=200,
                                                justify="left", text_color="green")
            self.label_file_path.grid(row=5, column=0, padx=20, pady=10, sticky="w")
            self.sign_file_button = ctk.CTkButton(self.left_frame, text="Sign uploaded file",
                                                  command=self.sign_file)
            self.sign_file_button.grid(row=6, column=0, padx=20, pady=(0, 10), sticky="w")

    def sign_file(self):
        sign.sign_file(self.file_path, "private_key.txt", {"name": "Joe Mama",
                                                             "email": "joemama@gmail.pg.edu.com.pl"}, "signature.xml")
        self.label_signed_file = ctk.CTkLabel(self.left_frame, text="File signed successfully! :)",
                                               text_color="green")
        self.label_signed_file.grid(row=7, column=0, padx=20, pady=(10, 5), sticky="w")

    def show_pin_to_type(self):
        self.label_type_pin = ctk.CTkLabel(self.left_frame, text="Enter PIN to encrypt the key:")
        self.label_type_pin.grid(row=1, column=0, padx=20, pady=10, sticky="w")
        self.pin_entry = ctk.CTkEntry(self.left_frame, placeholder_text="1234")
        self.pin_entry.grid(row=2, column=0, padx=20, pady=10, sticky="w")
        self.pin_entry.focus()

    def show_buttons(self):
        self.exit_button = ctk.CTkButton(self.left_frame, text="Exit", command=self.exit_from_program)
        self.exit_button.grid(row=8, column=0, padx=(20, 20), pady=(10, 20), sticky="nsew")

    def add_right(self):
        self.right_frame = ctk.CTkFrame(self.window, height=self.gui_height - 40, width=450,
                                        corner_radius=10)
        self.right_frame.grid(row=0, column=1, columnspan=1, padx=(10, 10), pady=(20, 20), sticky="nsew")
        # adding sidebar content
        self.label_verification = ctk.CTkLabel(self.right_frame, text="Signature Verification",
                                               font=ctk.CTkFont(size=20, weight="bold"))
        self.label_verification.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        self.label_upload_file_to_verify = ctk.CTkLabel(self.right_frame, text="Upload file to verify:")
        self.label_upload_file_to_verify.grid(row=1, column=0, padx=20, pady=10, sticky="w")

        self.upload_file_to_verify_button = ctk.CTkButton(self.right_frame, text="Upload file",
                                                          command=self.choose_file_to_upload_to_verify)
        self.upload_file_to_verify_button.grid(row=2, column=0, padx=(20, 20), pady=10, sticky="nsew")
        self.label_signature = ctk.CTkLabel(self.right_frame, text="Upload signature in xml format:")
        self.label_signature.grid(row=3, column=0, padx=20, pady=(10, 5), sticky="w")

        self.upload_signature_button = ctk.CTkButton(self.right_frame, text="Upload signature",
                                                          command=self.choose_signature_to_upload)
        self.upload_signature_button.grid(row=4, column=0, padx=(20, 20), pady=10, sticky="nsew")

    def check_if_ready_to_verify(self):
        if self.file_path_to_verify and self.signature_path:
            self.upload_signature_button = ctk.CTkButton(self.right_frame, text="Verify signature",
                                                         command=self.verify_signature)
            self.upload_signature_button.grid(row=5, column=0, padx=(20, 20), pady=10, sticky="nsew")

    def verify_signature(self):
        output_of_verification = sign.verify_signature(self.file_path_to_verify, "public_key.txt", self.signature_path)
        if output_of_verification:
            self.label_verification = ctk.CTkLabel(self.right_frame, text="The digital signature is correct! :)",
                                                   text_color="green")
            self.label_verification.grid(row=6, column=0, padx=20, pady=(10, 5), sticky="w")
        else:
            self.label_verification = ctk.CTkLabel(self.right_frame, text="The digital signature is incorrect! :(",
                                                   text_color="red")
            self.label_verification.grid(row=6, column=0, padx=20, pady=(10, 5), sticky="w")

    def choose_file_to_upload_to_verify(self):
        self.file_path_to_verify = filedialog.askopenfilename()
        if self.file_path_to_verify:
            print(f"File path: {self.file_path_to_verify}")
            self.upload_file_to_verify_button.destroy()
            self.file_to_verify_uploaded = True
            self.label_file_path_to_verify = ctk.CTkLabel(self.right_frame, text=self.file_path_to_verify, wraplength=200,
                                                justify="left", text_color="green")
            self.label_file_path_to_verify.grid(row=2, column=0, padx=20, pady=10, sticky="w")
            self.check_if_ready_to_verify()

    def choose_signature_to_upload(self):
        self.signature_path = filedialog.askopenfilename()
        if self.signature_path:
            print(f"File path: {self.signature_path}")
            self.upload_signature_button.destroy()
            self.signature_uploaded = True
            self.label_signature_path = ctk.CTkLabel(self.right_frame, text=self.signature_path, wraplength=200,
                                                justify="left", text_color="green")
            self.label_signature_path.grid(row=4, column=0, padx=20, pady=10, sticky="w")
            self.check_if_ready_to_verify()

    @staticmethod
    def exit_from_program():
        print("Program ended successfully! \nBye :)")
        sys.exit(0)