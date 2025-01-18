import matplotlib.pyplot as plt
from tkinter import *
from tkinter import messagebox, filedialog
import base64
import string


# Function to plot the frequency of alphabet characters
def plot_character_frequency(text):
    # Filter only alphabets (ignore spaces, punctuation, etc.)
    text = ''.join(filter(str.isalpha, text.lower()))

    frequency = {letter: text.count(letter) for letter in string.ascii_lowercase}

    fig, ax = plt.subplots()
    ax.bar(frequency.keys(), frequency.values(), color='blue')

    ax.set_xlabel('Alphabet')
    ax.set_ylabel('Frequency')
    ax.set_title('Alphabet Frequency in Text')

    plt.show()


# Decrypt window
def decrypt():
    password = code.get()

    if password == "1234":
        screen2 = Toplevel(screen)
        screen2.title("Decryption")
        screen2.geometry("400x300")
        screen2.configure(bg="#F7F7F7")

        message = text1.get(1.0, END).strip()
        try:
            decode_message = message.encode("ascii")
            base64_bytes = base64.b64decode(decode_message)
            decrypted = base64_bytes.decode("ascii")

            Label(screen2, text="DECRYPTED TEXT", font=("Helvetica", 16, "bold"), fg="black", bg="#F7F7F7").place(x=10,
                                                                                                                  y=10)
            text2 = Text(screen2, font=("Helvetica", 12), bg="#FFFFFF", relief=GROOVE, wrap=WORD, bd=2)
            text2.place(x=10, y=50, width=380, height=200)
            text2.insert(END, decrypted)

            # Plot the character frequency after decryption
            plot_character_frequency(decrypted)

        except Exception as e:
            messagebox.showerror("Decryption Error", f"Error: {str(e)}")

    elif password == "":
        messagebox.showerror("Decryption", "Input Password")

    elif password != "1234":
        messagebox.showerror("Decryption", "Invalid Password")


# Encrypt window
def encrypt():
    password = code.get()

    if password == "1234":
        screen1 = Toplevel(screen)
        screen1.title("Encryption")
        screen1.geometry("400x300")
        screen1.configure(bg="#F7F7F7")

        message = text1.get(1.0, END).strip()
        encode_message = message.encode("ascii")
        base64_bytes = base64.b64encode(encode_message)
        encrypted = base64_bytes.decode("ascii")

        Label(screen1, text="ENCRYPTED TEXT", font=("Helvetica", 16, "bold"), fg="black", bg="#F7F7F7").place(x=10,
                                                                                                              y=10)
        text2 = Text(screen1, font=("Helvetica", 12), bg="#FFFFFF", relief=GROOVE, wrap=WORD, bd=2)
        text2.place(x=10, y=50, width=380, height=200)
        text2.insert(END, encrypted)

        # Plot the character frequency after encryption
        plot_character_frequency(encrypted)

    elif password == "":
        messagebox.showerror("Encryption", "Input Password")

    elif password != "1234":
        messagebox.showerror("Encryption", "Invalid Password")


# Main encryption/decryption window
def main_screen():
    global screen
    global code
    global text1

    screen = Tk()
    screen.title("JASH")
    screen.state('zoomed')
    bg_image = PhotoImage(file="BG3.png")
    bg_label = Label(screen, image=bg_image)
    bg_label.place(relwidth=1, relheight=1)

    # icon
    image_icon = PhotoImage(file="logo.png")
    screen.iconphoto(False, image_icon)

    def reset():
        code.set("")
        text1.delete(1.0, END)

    shadow_title_label = Label(text="Enter text for encryption and decryption", fg="grey", font=("calibri", 17),
                               bg="#F0F0F0")
    shadow_title_label.place(relx=0.5, rely=0.097, anchor='center')

    title_label = Label(text="Enter text for encryption and decryption", fg="black", font=("calibri", 17, "bold"),
                        bg="#F0F0F0")
    title_label.place(relx=0.5, rely=0.1, anchor='center')
    text1_frame = Frame(screen, bg="#000000", bd=2)
    text1_frame.place(relx=0.5, rely=0.2, anchor='center', width=705, height=110)
    text1 = Text(text1_frame, font=("Helvetica", 14), bg="#f8f8ff", fg="#444444", relief=SOLID, wrap=WORD, bd=1,
                 padx=10, pady=5, insertbackground="black")
    text1.place(relwidth=1, relheight=1)

    key_label = Label(text="Enter secret key for encryption and decryption", fg="black", font=("calibri", 17, "bold"),
                      bg="#F0F0F0")
    key_label.place(relx=0.5, rely=0.35, anchor='center')

    code_frame = Frame(screen, bg="#000000", bd=2)
    code_frame.place(relx=0.5, rely=0.45, anchor='center')
    code = StringVar()
    secret_key_entry = Entry(code_frame, textvariable=code, bd=0, font=("arial", 25, "italic"), show="*", fg="#333333",
                             bg="#f8f8ff", insertbackground="black", width=30)
    secret_key_entry.pack(padx=5, pady=5)

    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, font=("Helvetica", 12, "bold"),
           command=encrypt).place(relx=0.3, rely=0.6, anchor='center')
    Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, font=("Helvetica", 12, "bold"),
           command=decrypt).place(relx=0.7, rely=0.6, anchor='center')
    Button(text="RESET", height="2", width=50, bg="#1089ff", fg="white", bd=0, font=("Helvetica", 12, "bold"),
           command=reset).place(relx=0.5, rely=0.75, anchor='center')
    Button(screen, text="BACK", height="2", width=10, bg="#AAAAAA", fg="white", bd=0, font=("Helvetica", 12, "bold"),
           command=lambda: [screen.destroy(), option_screen()]).place(relx=0.05, rely=0.05)

    screen.mainloop()





# File Selection Window
def file_encryption_screen():
    screen = Tk()
    screen.title("File Encryption/Decryption")
    screen.state('zoomed')
    screen.configure(bg="#F7F7F7")

    def select_file():
        file_path = filedialog.askopenfilename(title="Select a file", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
        if file_path:
            messagebox.showinfo("File Selected", f"Selected: {file_path}")

    Label(screen, text="File Encryption/Decryption", font=("Helvetica", 16, "bold"), fg="black", bg="#F7F7F7").pack(pady=20)
    Button(screen, text="Select File", height="2", width=23, bg="#1089ff", fg="white", bd=0, font=("Helvetica", 12, "bold"), command=select_file).pack(pady=20)
    Button(screen, text="BACK", height="2", width=10, bg="#AAAAAA", fg="white", bd=0, font=("Helvetica", 12, "bold"), command=lambda: [screen.destroy(), option_screen()]).pack(pady=10)

    screen.mainloop()

    def file_encrypt(file_path):
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
                encoded_data = base64.b64encode(file_data)

            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encoded_data)

            messagebox.showinfo("Success", f"File encrypted successfully!\nEncrypted File: {encrypted_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt file.\nError: {str(e)}")

    def file_decrypt(file_path):
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
                decoded_data = base64.b64decode(file_data)

            if file_path.endswith(".enc"):
                decrypted_file_path = file_path[:-4]  # Remove the .enc extension
            else:
                decrypted_file_path = file_path + ".dec"

            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decoded_data)

            messagebox.showinfo("Success", f"File decrypted successfully!\nDecrypted File: {decrypted_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt file.\nError: {str(e)}")

    def file_encryption_screen():
        screen = Tk()
        screen.title("File Encryption/Decryption")
        screen.state('zoomed')
        screen.configure(bg="#F7F7F7")

        def select_file_for_encryption():
            file_path = filedialog.askopenfilename(title="Select a file for encryption",
                                                   filetypes=(("All files", "*.*"),))
            if file_path:
                file_encrypt(file_path)

        def select_file_for_decryption():
            file_path = filedialog.askopenfilename(title="Select a file for decryption",
                                                   filetypes=(("All files", "*.*"),))
            if file_path:
                file_decrypt(file_path)

        Label(screen, text="File Encryption/Decryption", font=("Helvetica", 20, "bold"), fg="black", bg="#F7F7F7").pack(
            pady=20)

        Button(screen, text="Encrypt File", height="2", width=23, bg="#1089ff", fg="white", bd=0,
               font=("Helvetica", 12, "bold"), command=select_file_for_encryption).pack(pady=20)

        Button(screen, text="Decrypt File", height="2", width=23, bg="#00bd56", fg="white", bd=0,
               font=("Helvetica", 12, "bold"), command=select_file_for_decryption).pack(pady=20)

        Button(screen, text="BACK", height="2", width=10, bg="#AAAAAA", fg="white", bd=0,
               font=("Helvetica", 12, "bold"), command=screen.destroy).pack(pady=10)

        screen.mainloop()

    # Testing the file encryption screen
    if __name__ == "__main__":
        file_encryption_screen()


  # Global dictionary to store user credentials
user_credentials = {"admin": "1234"}


def login_screen():
    def verify_login():
        username = username_var.get()
        password = password_var.get()

        if username in user_credentials and user_credentials[username] == password:
            login.destroy()
            option_screen()
        else:
            messagebox.showerror("Login Failed", "Invalid Username or Password")

    def register_user():
        new_username = reg_username_var.get()
        new_password = reg_password_var.get()

        if new_username and new_password:
            if new_username in user_credentials:
                messagebox.showerror("Registration Failed", "Username already exists!")
            else:
                user_credentials[new_username] = new_password
                messagebox.showinfo("Registration Successful", f"User '{new_username}' registered successfully!")
                reg_username_var.set("")
                reg_password_var.set("")
        else:
            messagebox.showerror("Registration Failed", "Please fill out all fields!")

    login = Tk()
    login.title("Login and Register")
    screen_width = login.winfo_screenwidth()
    screen_height = login.winfo_screenheight()
    window_width = 900
    window_height = 600

    position_top = int(screen_height / 2 - window_height / 2)
    position_right = int(screen_width / 2 - window_width / 2)

    login.geometry(f"{window_width}x{window_height}+{position_right}+{position_top}")
    login.configure(bg="#F7F7F7")

    # Frames for Login and Register sections
    login_frame = Frame(login, bg="#F7F7F7", width=450, height=600)
    login_frame.place(x=0, y=0, relheight=1, width=window_width // 2)

    register_frame = Frame(login, bg="#FFFFFF", width=450, height=600)
    register_frame.place(x=window_width // 2, y=0, relheight=1, width=window_width // 2)

    # Login Section
    Label(login_frame, text="Login", font=("Helvetica", 24, "bold"), bg="#F7F7F7").pack(pady=40)
    Label(login_frame, text="Username", font=("Helvetica", 16), bg="#F7F7F7").pack(pady=10)
    username_var = StringVar()
    Entry(login_frame, textvariable=username_var, font=("Helvetica", 14), bg="#f8f8ff", relief=SOLID).pack(pady=5,
                                                                                                           ipadx=5,
                                                                                                           ipady=5)

    Label(login_frame, text="Password", font=("Helvetica", 16), bg="#F7F7F7").pack(pady=10)
    password_var = StringVar()
    Entry(login_frame, textvariable=password_var, font=("Helvetica", 14), show="*", bg="#f8f8ff", relief=SOLID).pack(
        pady=5, ipadx=5, ipady=5)

    Button(login_frame, text="Login", height=2, width=15, bg="#00bd56", fg="white", font=("Helvetica", 14, "bold"),
           command=verify_login).pack(pady=40)

    # Register Section
    Label(register_frame, text="Register", font=("Helvetica", 24, "bold"), bg="#FFFFFF").pack(pady=40)
    Label(register_frame, text="Username", font=("Helvetica", 16), bg="#FFFFFF").pack(pady=10)
    reg_username_var = StringVar()
    Entry(register_frame, textvariable=reg_username_var, font=("Helvetica", 14), bg="#f8f8ff", relief=SOLID).pack(
        pady=5, ipadx=5, ipady=5)

    Label(register_frame, text="Password", font=("Helvetica", 16), bg="#FFFFFF").pack(pady=10)
    reg_password_var = StringVar()
    Entry(register_frame, textvariable=reg_password_var, font=("Helvetica", 14), show="*", bg="#f8f8ff",
          relief=SOLID).pack(pady=5, ipadx=5, ipady=5)

    Button(register_frame, text="Register", height=2, width=15, bg="#1089ff", fg="white",
           font=("Helvetica", 14, "bold"), command=register_user).pack(pady=40)

    login.mainloop()


# Intermediate window
def option_screen():
    option_window = Tk()
    option_window.title("Choose Option")
    option_window.state('zoomed')

    bg_image = PhotoImage(file="BG.png")
    bg_label = Label(option_window, image=bg_image)
    bg_label.place(relwidth=1, relheight=1)

    # Welcome Label
    Label(option_window, text="Welcome to JASH", font=("Helvetica", 30, "bold italic"), fg="#2C3E50", bg="#F0F0F0").pack(pady=40)

    button_frame = Frame(option_window, bg="#F0F0F0")
    button_frame.pack(pady=20)

    encrypt_decrypt_image = PhotoImage(file="med.png")
    file_encrypt_decrypt_image = PhotoImage(file="fed.png")

    button1 = Button(button_frame, image=encrypt_decrypt_image, bg="#F0F0F0", bd=0, command=lambda: [option_window.destroy(), main_screen()])
    button1.grid(row=0, column=0, padx=50, pady=20)

    button2 = Button(button_frame, image=file_encrypt_decrypt_image, bg="#F0F0F0", bd=0, command=lambda: [option_window.destroy(), file_encryption_screen()])
    button2.grid(row=0, column=1, padx=50, pady=20)

    label1 = Label(button_frame, text="Message E/D", font=("Helvetica", 14), bg="#F0F0F0", fg="#2C3E50")
    label1.grid(row=1, column=0, pady=5)

    label2 = Label(button_frame, text="File E/D", font=("Helvetica", 14), bg="#F0F0F0", fg="#2C3E50")
    label2.grid(row=1, column=1, pady=5)

    button1.image = encrypt_decrypt_image
    button2.image = file_encrypt_decrypt_image

    option_window.mainloop()


 # Intro window
def show_intro():
    intro_screen = Tk()
    screen_width = intro_screen.winfo_screenwidth()
    screen_height = intro_screen.winfo_screenheight()
    window_width = 900
    window_height = 600

    position_top = int(screen_height / 2 - window_height / 2)
    position_right = int(screen_width / 2 - window_width / 2)

    intro_screen.geometry(f"{window_width}x{window_height}+{position_right}+{position_top}")
    intro_screen.configure(bg="black")

    png_image = PhotoImage(file="image.png")
    png_label = Label(intro_screen, image=png_image)
    png_label.pack(expand=True)
    intro_screen.after(3000, lambda: [intro_screen.destroy(), login_screen()])

    intro_screen.mainloop()

show_intro()