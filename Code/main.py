import tkinter
from crypto import Cryptinaitor
from database import Database
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
import os
import pygame


class MainProgram:
    def __init__(self, admin_key):
        # var creation for all the layouts
        self.init_wnd = Tk()
        # var for login window layout
        self.login_wnd = None
        # var for register window layout
        self.register_wnd = None
        # var for main user window layout
        self.user_wnd = None
        self.msg_wnd = None
        # var for table of user storage layout
        self.grid_storage = None
        # var for shop items table layout
        self.grid_items = None
        # we create objects instead of inherit them for educative purposes
        self.db = Database()
        self.crypt = Cryptinaitor(admin_key)
        # main function, activates the main layout
        self.menu_wnd()
        # nya!!
        self.music = False

    def menu_wnd(self):
        self.init_wnd.title("Shop simulator")
        self.init_wnd.geometry("500x500+500+200")
        self.init_wnd.iconbitmap("../images/favicon.ico")
        # Nya background image
        bg = PhotoImage(file="../images/icon.png")
        label1 = Label(self.init_wnd, image=bg)
        label1.place(x=0, y=0)
        # nya nya naan!!
        pygame.mixer.init()
        # Main label
        Label(text="Shop simulator", bg="navy", fg="white", width="300", height="3", font=("Calibri", 15)).pack()
        Label(text="").pack()
        # blanc space for aesthetic purposes
        # If login clicked open login window
        Button(text="Login", width="30", height="3", command=lambda: self.login()).pack()
        # If register clicked open register window
        Button(text="Register", width="30", height="3", command=lambda: self.register()).pack(pady="5")
        # If nya clicked let's start the party baby
        Button(text="Nya me", width="10", height="3", bg="pink", command=lambda: self.play()).pack(pady="40")
        self.init_wnd.mainloop()

    def login(self):
        # create window with top level init
        self.login_wnd = Toplevel(self.init_wnd)
        # when open login wnd close init wnd
        self.init_wnd.withdraw()
        self.login_wnd.geometry(f"500x500+{self.init_wnd.winfo_x()}+{self.init_wnd.winfo_y()}")
        self.login_wnd.title("Shop simulator-Login")
        self.login_wnd.iconbitmap("../images/favicon.ico")
        # text for insert purposes
        Label(self.login_wnd, text="Insert user and password",
              bg="navy", fg="white", width="300", height="3", font=("Calibri", 15)).pack()
        Label(self.login_wnd, text="").pack()
        # user label for insert purposes
        Label(self.login_wnd, text="user", width="25", bg="navy", fg="white", font=("Calibri", 12)).pack()
        # input for user str data type
        user_entry = Entry(self.login_wnd, width="25", font=("Calibri", 12))
        user_entry.pack()
        # password label for insert purposes
        Label(self.login_wnd, text="password", width="25", bg="navy", fg="white", font=("Calibri", 12)).pack()
        # input for password str data type
        password_entry = Entry(self.login_wnd, width="25", font=("Calibri", 12), show="*")
        password_entry.pack()
        # if clicked, take both entries and activate verify log protocol
        Button(self.login_wnd, text="Login", width="25", bg="navy", fg="white", font=("Calibri", 12),
               command=lambda: self.verify_log(user_entry, password_entry)).pack(padx="10", pady="10")
        user_entry.delete(0, "end")
        password_entry.delete(0, "end")
        # when home clicked, turn of main layout and reload init layout
        Button(self.login_wnd, text="Home", width="25", bg="navy", fg="white", font=("Calibri", 12),
               command=lambda: self.swapplaces(self.init_wnd, self.login_wnd)).pack(padx="10", pady="10")

    def register(self):
        # create window with top level init
        self.register_wnd = Toplevel(self.init_wnd)
        # when open register wnd close init wnd
        self.init_wnd.withdraw()
        self.register_wnd.title("Shop simulator-Register")
        self.register_wnd.geometry(f"500x500+{self.init_wnd.winfo_x()}+{self.init_wnd.winfo_y()}")
        self.register_wnd.iconbitmap("../images/favicon.ico")
        # label for entry purposes
        Label(self.register_wnd, text="Insert user and password for register",
              bg="navy", fg="white", width="300", height="3", font=("Calibri", 15)).pack()
        Label(self.register_wnd, text="").pack()
        # blanc space for aesthetic purposes
        # user label for insert purposes
        Label(self.register_wnd, text="User", width="25", bg="navy", fg="white", font=("Calibri", 12)).pack()
        # input for user str data type
        user_entry2 = Entry(self.register_wnd, width="25", font=("Calibri", 12))
        user_entry2.pack()
        # password label for insert purposes
        Label(self.register_wnd, text="Password", width="25", bg="navy", fg="white", font=("Calibri", 12)).pack()
        # input for password str data type
        password_entry2 = Entry(self.register_wnd, width="25", font=("Calibri", 12))
        password_entry2.pack()
        # if clicked, take both entries and activate verify reg protocol
        Button(self.register_wnd, text="Register", width="25", bg="navy", fg="white", font=("Calibri", 12),
               command=lambda: self.verify_reg(user_entry2, password_entry2)).pack()
        # when home clicked, turn of main layout and reload init layout
        Button(self.register_wnd, text="Home", width="25", bg="navy", fg="white", font=("Calibri", 12),
               command=lambda: self.swapplaces(self.init_wnd, self.register_wnd)).pack(padx="10", pady="10")

    def verify_log(self, user, password):
        # select from users table the matched user
        pwd = password.get()
        user_data = self.db.select_from_users([user.get()])
        if len(user_data) == 1:
            # if tuple found means user exists, now let's check password
            # we take the pwd salt[0][4] to do the super hash
            # if data1 and super hash of password equal then access granted
            if user_data[0][1] == self.crypt.scrypt(password.get(), self.crypt.encodec_binary(user_data[0][4])):
                # close main wnd
                self.login_wnd.withdraw()
                # open user main wnd
                self.main_window(user.get())
                self.crypt.password = pwd.encode("latin-1")
                # declaration of user key with the hash method and the user salt[0][2]
                self.crypt.user_key = self.crypt.pbkdf2(password.get(), self.crypt.encodec_binary(user_data[0][2]))
                # super mega user encrypt-hash for storage authentication purposes
                self.crypt.user_crypt_hashed = self.crypt.encrypt_user(user_data[0])
                # user_key salt and encryption rotation
                self.rotate_user_key_data(password.get(), list(user_data[0]))
                # tkinter thingy things
                tkinter.messagebox.showinfo(title="access granted", message="Welcome back " + user.get())
            else:
                # if password authentication failed, activate swap protocol and error msg
                tkinter.messagebox.showinfo(title="login error", message="wrong password")
                self.swapplaces(self.init_wnd, self.login_wnd)
        else:
            # if user authentication failed, activate swap protocol and error msg
            tkinter.messagebox.showinfo(title="login error", message="wrong user")
            self.swapplaces(self.init_wnd, self.login_wnd)

    def verify_reg(self, user, password):
        user = user.get()
        users_tuple = self.db.select_from_users([user])
        # if user not in database means it can be created
        if len(users_tuple) == 0:
            # close register window
            self.register_wnd.withdraw()
            # we create a user nonce  and a user salt for the super mega encrypt-hash of the user
            user_nonce = os.urandom(12)
            user_salt = os.urandom(16)
            # to store the password we need first to create a pwd salt for it's hash
            pwd_salt = os.urandom(16)
            asymmetric_key_pair = self.crypt.RSA_create_key(password.get())
            # we store the user without encryption because it's not needed to
            self.db.register_user([user, self.crypt.scrypt(password.get(), pwd_salt), self.crypt.decodec_binary(user_salt),
                                   self.crypt.decodec_binary(user_nonce), self.crypt.decodec_binary(pwd_salt),
                                   self.crypt.decodec_binary(asymmetric_key_pair[0]), self.crypt.decodec_binary(asymmetric_key_pair[1])])
            # we need to store the nonce and the two salts for later calc
            # init wnd opened again
            self.init_wnd.deiconify()
            # tkinter granted message box
            tkinter.messagebox.showinfo(title="register granted", message="Welcome to shop simulator " + user)
        else:
            # if user name already in database, choose other man idk
            answer = tkinter.messagebox.askquestion(title="Register error", message="name already exists,\n try again?")
            # tkinter question box
            if answer != "yes":
                self.register_wnd.withdraw()
                self.init_wnd.deiconify()

    def main_window(self, user):
        # create window with top level init
        self.user_wnd = Toplevel(self.init_wnd)
        self.user_wnd.title("Shop simulator-" + user)
        # geometry defined conditional to init geometry for aesthetic purposes
        self.user_wnd.geometry(f"500x500+{self.init_wnd.winfo_x()}+{self.init_wnd.winfo_y()}")
        self.user_wnd.iconbitmap("../images/favicon.ico")

        Label(self.user_wnd, text=user + "'s storage", bg="navy", fg="white", width="300", height="3",
              font=("Calibri", 15)).pack()
        Label(self.user_wnd, text="").pack()
        # if check button clicked then create users table layout
        Button(self.user_wnd, text="Check Items", width=25,
               command=lambda: self.create_users_table()).pack(pady=3, padx=3)
        # if check available button clicked then create items table layout
        Button(self.user_wnd, text="Check available Items", width=25,
               command=lambda: self.create_items_table()).pack(pady=3, padx=3)
        # if check message clicked then activate message box protocol
        Button(self.user_wnd, text="Message box", width=25,
               command=lambda: self.create_message_box(user)).pack(pady=3, padx=3)
        Label(self.user_wnd, text="").pack()
        # label just to create visual space between content
        Label(self.user_wnd, text="Insert object:",
              bg="navy", fg="white", width="25", font=("Calibri", 12)).pack()
        object_op = Entry(self.user_wnd, width="25", font=("Calibri", 12))
        object_op.pack()
        # insert amount text for input
        Label(self.user_wnd, text="Insert amount:",
              bg="navy", fg="white", width="25", font=("Calibri", 12)).pack()
        amount = Entry(self.user_wnd, width="25", font=("Calibri", 12))
        amount.pack()
        Label(self.user_wnd, text="").pack()
        # when buy clicked then activate buy protocol
        Button(self.user_wnd, text="Buy", width=25,
               command=lambda: self.buy_item(object_op.get(), amount.get())).pack(pady=3, padx=3)
        # when sell clicked then activate sell protocol
        Button(self.user_wnd, text="Sell", width=25,
               command=lambda: self.sell_item(object_op.get(), amount.get())).pack(pady=3, padx=3)
        # when delete clicked then activate delete protocol
        Button(self.user_wnd, text="Delete", width=25,
               command=lambda: self.delete_item(object_op.get(), amount.get())).pack(pady=3, padx=3)
        # when home clicked, turn of main layout and reload init layout
        Label(self.user_wnd, text="").pack()
        Button(self.user_wnd, text="Home", width="25", bg="navy", fg="white", font=("Calibri", 12),
               command=lambda: self.swapplaces(self.init_wnd, self.user_wnd)).pack(pady=3, padx=3)

    def buy_item(self, object_op, amount):
        # check for invalid or empty amounts, first the "" for python countermeasures
        if amount == "" or int(amount) <= 0:
            # if true then activate fail protocol
            tkinter.messagebox.showinfo(title="Buy action failed",
                                        message="amount invalid")
        else:
            # select from items the object selected for calc
            item = self.db.select_from_items([object_op])
            # if none (len == 0) found means object doesn't exist
            if len(item) == 0:
                # if true then activate fail protocol
                tkinter.messagebox.showinfo(title="Buy action failed",
                                            message="Object not found")
            else:
                # calc of the new amount in the data base
                new = int(item[0][1]) - int(amount)
                if new < 0:
                    # if true activate fail protocol
                    tkinter.messagebox.showinfo(title="Buy action failed",
                                                message="Amount requested exceeded\namount available")
                else:
                    # we update the items table with the new amount for the object selected
                    self.db.update_items([str(new), object_op])

                    # we need the user_crypt_hashed for authentication and access to the data
                    user_item = self.db.select_from_storage([self.crypt.user_crypt_hashed])
                    # all objects from user picked, we need to select only the one needed
                    user_item = self.pick_item(user_item, object_op)

                    # creation of the nonce's needed for the encrypt
                    # size 12 for AES_GCM compatibility

                    # if user None means the user doesn't have the object yet in the database
                    if user_item is None:
                        nonce1 = os.urandom(12)
                        nonce2 = os.urandom(12)
                        nonce3 = os.urandom(12)
                        # we access the database with the authentication system and encrypt the data
                        # use the nonce's given already for the encryption
                        # encrypt using the crypt function AES_GCM_encrypt(data, nonce)
                        self.db.insert_user_object([self.crypt.user_crypt_hashed,
                                                    self.crypt.AES_GCM_encrypt(object_op, nonce1),
                                                    self.crypt.AES_GCM_encrypt(amount, nonce2),
                                                    self.crypt.AES_GCM_encrypt(item[0][2], nonce3),
                                                    # price value is taken from the object tuple from items table
                                                    # nonce's are stored as b64 str data types
                                                    self.crypt.decodec_binary(nonce1),
                                                    self.crypt.decodec_binary(nonce2),
                                                    self.crypt.decodec_binary(nonce3)])
                    else:
                        # new amount is amount + old amount
                        # old amount is encrypted so we use the nonce and the AES for decrypt
                        user_item[2] = int(amount) + int(self.crypt.AES_GCM_decrypt(user_item[2], user_item[5]))
                        # the new data is encrypted and stored again in the data base but first we need to do the nonce rotation protocol
                        self.nonce_rotation(user_item)

                    # once calc finished and new data inserted we launch granted messagebox
                    tkinter.messagebox.showinfo(title="Buy action granted",
                                                message="Refresh user item list")

    def sell_item(self, object_op, amount):
        # check if amount is a valid value
        if amount == "" or int(amount) <= 0:
            # if true then activate fail protocol
            tkinter.messagebox.showinfo(title="Sell action failed",
                                        message="amount invalid")
        else:
            # select from items the object selected for calc
            item = self.db.select_from_items([object_op])
            # if none (len == 0) found means object doesn't exist
            if len(item) == 0:
                # if true then activate fail protocol
                tkinter.messagebox.showinfo(title="Sell action failed",
                                            message="Object not found")
            else:
                # first we need to get all the objects from user to check if it exists in its storage
                # we need the user_crypt_hashed for authentication and access to the data
                user_item = self.db.select_from_storage([self.crypt.user_crypt_hashed])
                # all objects from user picked, we need to select only the one needed
                user_item = self.pick_item(user_item, object_op)
                if user_item is None:
                    # if true means there is no item with this type of data
                    tkinter.messagebox.showinfo(title="Sell action failed",
                                                message="Object not found in user's storage")
                else:
                    # calc of the new user storage value
                    user_item[2] = int(self.crypt.AES_GCM_decrypt(user_item[2], user_item[5])) - int(amount)
                    if user_item[2] <= 0:
                        # if amount is below or equal to zero, we eliminate that object from user storage
                        self.db.delete_user_storage([user_item[0], user_item[1]])
                        # this way we guarantee that the amount given to the shop is the right one
                        self.db.update_items([int(item[0][1])+(int(amount)-user_item[2]), object_op])
                    else:
                        # update of item amount in database
                        self.db.update_items([int(item[0][1])+int(amount), object_op])
                        # once we have the new data we rotate all the nonce's for safety measures
                        self.nonce_rotation(user_item)
                    # message box for user extra info
                    tkinter.messagebox.showinfo(title="Sell action granted",
                                                message="Refresh main item list")

    def delete_item(self, object_op, amount):
        # check if amount is a valid value
        if amount == "" or int(amount) <= 0:
            # if true then activate fail protocol
            tkinter.messagebox.showinfo(title="Delete action failed",
                                        message="amount invalid")
        else:
            # first we need to get all the objects from user to check if it exists in its storage
            # we need the user_crypt_hashed for authentication and access to the data
            user_item = self.db.select_from_storage([self.crypt.user_crypt_hashed])
            # all objects from user picked, we need to select only the one needed
            user_item = self.pick_item(user_item, object_op)
            if user_item is None:
                # if true means there is no item with this type of data
                tkinter.messagebox.showinfo(title="Delete action failed",
                                            message="Object not found")
            else:
                user_item[2] = int(self.crypt.AES_GCM_decrypt(user_item[2], user_item[5])) - int(amount)
                if user_item[2] <= 0:
                    # if amount is below or equal to zero, we eliminate that object from user storage
                    self.db.delete_user_storage([user_item[0], user_item[1]])

                else:
                    # once we have the new data we rotate all the nonce's for safety measures
                    self.nonce_rotation(user_item)
                # message box for user extra info
                tkinter.messagebox.showinfo(title="Delete action granted",
                                            message="Refresh user item list")

    def pick_item(self, items_list, object_op):
        for i in range(len(items_list)):
            # we need to find the object, if found return the object, else None
            item_decrypt = self.crypt.AES_GCM_decrypt(items_list[i][1], items_list[i][4])
            if item_decrypt == object_op:
                # we change tuple to list for later modifications
                return list(items_list[i])
            else:
                # new nonce for object because of nonce rotation
                nonce = os.urandom(12)
                # because we have decrypted the object we now need to change its nonce and encrypt it again
                self.db.update_user_object([self.crypt.AES_GCM_encrypt(item_decrypt, nonce),
                                            self.crypt.decodec_binary(nonce),
                                            self.crypt.user_crypt_hashed, items_list[i][1]])

    def create_items_table(self):
        # not gonna explain how this works cause it's purely an aesthetic thing im doing cause i'm bored
        self.grid_items = Toplevel(self.init_wnd)
        self.grid_items.title("Items inventory")
        self.grid_items.geometry(f"600x500+{self.init_wnd.winfo_x() + 200}+{self.init_wnd.winfo_y() + 50}")
        self.grid_items.iconbitmap("../images/favicon.ico")
        items = self.db.select_from_items([])
        if len(items) == 0:
            Label(self.user_wnd, text="No objects available for purchase", font=("Calibri", 12)).pack(pady=40)
        else:
            style = ttk.Style()
            style.theme_use('clam')
            tree = ttk.Treeview(self.grid_items, column=("Object", "amount", "price"),
                                show='headings', height=len(items))
            self.table_inator(tree, items)

    def create_users_table(self):
        # we create a top level instance of init called grid_storage
        self.grid_storage = Toplevel(self.init_wnd)
        self.grid_storage.title("Shop simulator")
        self.grid_storage.geometry(f"600x500+{self.init_wnd.winfo_x() + 200}+{self.init_wnd.winfo_y() + 50}")
        self.grid_storage.iconbitmap("../images/favicon.ico")
        # we preload all the items belonging to the user (it's super hash equivalent in the database)
        user_items = self.db.select_from_storage([self.crypt.user_crypt_hashed])
        # we authenticate the data by using the super hash user
        if len(user_items) == 0:
            # if no objects found, means no objects yet purchased by the user
            Label(self.grid_storage, text="No objects purchased yet", font=("Calibri", 12)).pack(pady=40)
        else:
            self.db.delete_user_storage([self.crypt.user_crypt_hashed])
            # we delete all rows from user because we are about to decrypt them and nonce rotation forbids it
            # tkinter thingy things
            style = ttk.Style()
            style.theme_use('clam')
            tree = ttk.Treeview(self.grid_storage, column=("Object", "amount", "price"),
                                show='headings', height=len(user_items))
            # we decrypt the whole tuple of lists with encrypted data from the user
            user_items_decrypted = self.crypt.decrypt_list(user_items)
            # we now reinsert all the data but with new nonce's and new encryption for nonce rotations
            for i in range(len(user_items_decrypted)):
                nonce1 = os.urandom(12)
                nonce2 = os.urandom(12)
                nonce3 = os.urandom(12)
                # predefine the 3 new nonce's
                # encrypt the data using the nonce's and store the new nonce's as b64 str data
                self.db.insert_user_object([self.crypt.user_crypt_hashed,
                                            self.crypt.AES_GCM_encrypt(user_items_decrypted[i][1], nonce1),
                                            self.crypt.AES_GCM_encrypt(user_items_decrypted[i][2], nonce2),
                                            self.crypt.AES_GCM_encrypt(user_items_decrypted[i][3], nonce3),
                                            self.crypt.decodec_binary(nonce1),
                                            self.crypt.decodec_binary(nonce2),
                                            self.crypt.decodec_binary(nonce3)])
            # now we load the table creator with the non encrypted user's data as parameter
            self.table_inator(tree, user_items_decrypted)

    def create_message_box(self, user):
        # create window with top level init
        self.msg_wnd = Toplevel(self.init_wnd)
        self.msg_wnd.title("Message-" + user)
        # geometry defined conditional to init geometry for aesthetic purposes
        self.msg_wnd.geometry(f"420x320+{self.init_wnd.winfo_x() + 200}+{self.init_wnd.winfo_y() + 50}")
        self.msg_wnd.iconbitmap("../images/favicon.ico")
        # message box title using user's name
        Label(self.msg_wnd, text=user + "'s message box", bg="navy", fg="white", width="300", height="3",
              font=("Calibri", 15)).pack()
        Label(self.msg_wnd, text="").pack()
        # if clicked activate check message box protocol
        Button(self.msg_wnd, text="Check message box", width=25,
               command=lambda: self.check_message_box(user)).pack(pady=3, padx=3)
        Label(self.msg_wnd, text="").pack()
        # label for insert declaration
        Label(self.msg_wnd, text="Insert destination user:",
              bg="navy", fg="white", width="50", font=("Calibri", 12)).pack()
        # entry for user name
        user_receptor = Entry(self.msg_wnd, width="50", font=("Calibri", 12))
        user_receptor.pack()
        # entry for the message with label
        Label(self.msg_wnd, text="Insert message:",
              bg="navy", fg="white", width="50", font=("Calibri", 12)).pack()
        message = Entry(self.msg_wnd, width="50", font=("Calibri", 12))
        message.pack()
        Label(self.msg_wnd, text="").pack()
        # if clicked activate send message protocol
        Button(self.msg_wnd, text="Send message", width=25,
               command=lambda: self.send_message(user, user_receptor.get(), message.get())).pack(pady=3, padx=3)
        # when home clicked, turn of main layout and reload init layout
        Label(self.msg_wnd, text="").pack()

    def send_message(self, user, user_receptor, message):
        # select the user data to get the public key for encryption
        user_receptor_data = self.db.select_from_users([user_receptor])
        # if found, means it exists that user, else error protocol
        if len(user_receptor_data) == 1:
            # deserialize the public key to use it [0][6] = public key
            public_key = self.crypt.undo_serialization(user_receptor_data[0][6])
            # encrypt the message using RSA and the public key
            message_encrypted = self.crypt.RSA_encrypt(message, public_key)
            # we need to sign to forward validation of the message, but first need the user's private key
            user_data = self.db.select_from_users([user])
            # obtain private key ([0][5] using the undo serialization method
            private_key = self.crypt.undo_serialization(user_data[0][5], self.crypt.password)
            # using the private key and the message we now sign the message
            sign = self.crypt.RSA_sign(private_key, message)
            # add message encrypted to database
            self.db.insert_message([user, user_receptor, message_encrypted, sign])
            # successfully sent message info box
            tkinter.messagebox.showinfo(title="Message granted",
                                        message="message sent!")
        elif user_receptor == "all" and user == "admin":
            user_data = self.db.select_from_users([user])
            # obtain private key ([0][5] using the undo serialization method
            private_key = self.crypt.undo_serialization(user_data[0][5], self.crypt.password)
            sign = self.crypt.RSA_sign(private_key, message)
            self.db.insert_message([user, user_receptor, message, sign])
            tkinter.messagebox.showinfo(title="Message granted",
                                        message="message sent!")
        else:
            # user not found error protocol
            tkinter.messagebox.showinfo(title="Message error",
                                        message="message error\nreceptor user not found!")

    def check_message_box(self, user):
        # get all the messages meant for the user
        messages = self.db.select_from_message_log([user])
        # get the user data for decryption using the private key = [0][5]
        user_data = self.db.select_from_users([user])
        # if not found any, means user has no new messages
        if len(messages) > 0:
            # activate launch msg protocol with the msgs lists and the private key
            self.launch_msg(messages, user_data[0][5])
            # one the message has been seen, delete them from data base

        else:
            # if not found, activate box empty protocol
            tkinter.messagebox.showinfo(title="message box empty",
                                        message="message box empty\ncome back later!")

    def launch_msg(self, messages, private_key_encrypted):
        # for every message in list
        for i in range(len(messages)):
            # first we need the user's emitter public key
            user_emitter_data = self.db.select_from_users([messages[i][0]])
            # undo serialization of the public key [0][6]
            public_key = self.crypt.undo_serialization(user_emitter_data[0][6])
            if messages[i][0] == "admin" and messages[i][1] == "all":
                if self.crypt.RSA_check_sign(public_key, messages[i][2], messages[i][3]) is None:
                    # if sign verification is launch msg admin protocol
                    self.launch_msg_admin(messages[i])
                else:
                    tkinter.messagebox.showinfo(title="Illegal message",
                                                message="Illegal message detected\neliminating message for user's safety")
                    # one the message has been seen or blocked, delete it
                    # [i][1] = user receiver and [i][2] = plaintext
                    self.db.delete_message([messages[i][1], messages[i][2]])
            else:
                # deserialize the private key to use it with the user password
                private_key = self.crypt.undo_serialization(private_key_encrypted, self.crypt.password)
                # decrypt message using RSA with the private key
                decrypted_message = self.crypt.RSA_decrypt(messages[i][2], private_key)
                # verify using the user's public key and the decrypted message
                if self.crypt.RSA_check_sign(public_key, decrypted_message, messages[i][3]) is None:
                    # if sign verification is done print the message with the message box protocol
                    tkinter.messagebox.showinfo(title="Message #" + str(i + 1),
                                                message=str(messages[i][0] + ": " + decrypted_message))
                else:
                    tkinter.messagebox.showinfo(title="Illegal message",
                                                message="Illegal message detected\neliminating message for user's safety")
                # one the message has been seen or blocked, delete it
                # [i][1] = user receiver and [i][2] = plaintext
                self.db.delete_message([messages[i][1], messages[i][2]])

    def launch_msg_admin(self, message):
        # if sign verification is done print the message with the message box protocol
        var1 = self.crypt.create_certificate(open("../certificate_data/01.pem", "rb"))
        var2 = self.crypt.create_certificate(open("../certificate_data/ac1cert.pem", "rb"))
        check1 = self.crypt.check_certificate(var1, var2)
        check2 = self.crypt.check_certificate(var2, var2)
        # need to check
        if check1 and check2:
            tkinter.messagebox.showinfo(title="Admin message",
                                        message=str(message[0] + ": " + message[2]))
        else:
            tkinter.messagebox.showinfo(title="Illegal message",
                                        message="Illegal message detected\neliminating message for user's safety")
        # admin messages will not be deleted until admin does it

    def table_inator(self, tree, items):
        # table creator using tkinter not gonna explain it cause it's not interesting at all
        tree.column("# 1", anchor=CENTER)
        tree.heading("# 1", text="Object(" + str(len(items)) + ")")
        tree.column("# 2", anchor=CENTER)
        tree.heading("# 2", text="amount")
        tree.column("# 3", anchor=CENTER)
        tree.heading("# 3", text="price")

        if len(items[0]) == 3:
            for i in range(len(items)):
                tree.insert('', 'end', text="1", values=(items[i][0], str(items[i][1]), str(items[i][2])))
        else:
            for i in range(len(items)):
                tree.insert('', 'end', text="1", values=(items[i][1], str(items[i][2]), str(items[i][3])))
        tree.pack()

    def swapplaces(self, wnd1, wnd2):
        # swap wnd using tkinter withdraw and deiconify
        wnd2.withdraw()
        wnd1.deiconify()

    def nonce_rotation(self, item_data):
        # we delete the entire row for reinsert of the new encrypted data with the new nonce's
        self.db.delete_user_storage([self.crypt.user_crypt_hashed, item_data[1]])
        nonce1 = os.urandom(12)
        nonce2 = os.urandom(12)
        nonce3 = os.urandom(12)
        # since the amount is not encrypted we only encrypt it
        # the rest of the values need to be first decrypted and then encrypted again with the new nonce's
        self.db.insert_user_object([self.crypt.user_crypt_hashed,
                                    self.crypt.AES_GCM_encrypt(self.crypt.AES_GCM_decrypt(item_data[1], item_data[4]), nonce1),
                                    self.crypt.AES_GCM_encrypt(str(item_data[2]), nonce2),
                                    self.crypt.AES_GCM_encrypt(self.crypt.AES_GCM_decrypt(item_data[3], item_data[6]), nonce3),
                                    self.crypt.decodec_binary(nonce1),
                                    self.crypt.decodec_binary(nonce2),
                                    self.crypt.decodec_binary(nonce3)])

    def rotate_user_key_data(self, password, user_data):
        # select all items from user for the key rotation
        user_items = self.db.select_from_storage([self.crypt.user_crypt_hashed])
        # delete all of them for reinsertion later on
        self.db.delete_user_storage([self.crypt.user_crypt_hashed])
        # decrypt the data for encrypt with new key
        user_items_decrypted = self.crypt.decrypt_list(user_items)
        # create new user_salt for new user_key
        user_data[2] = self.crypt.decodec_binary(os.urandom(16))
        # change the user_key to the new one
        self.crypt.user_key = self.crypt.pbkdf2(password, self.crypt.encodec_binary(user_data[2]))
        # encrypt the data with the new user key and store the new user_key salt (user_salt)
        self.db.update_user_salt([user_data[2], user_data[0]])
        # update the user hash to use it
        # first update it's nonce value to the new one
        user_data[3] = self.crypt.decodec_binary(os.urandom(12))
        self.crypt.user_crypt_hashed = self.crypt.encrypt_user(user_data)
        # store the new nonce value in database
        self.db.update_user_nonce([user_data[3], user_data[0  ]])
        user_items_encrypted = self.crypt.encrypt_list(user_items_decrypted)
        # for every new array of encrypted data insert into database
        for i in range(len(user_items_encrypted)):
            user_items_encrypted[i][0] = self.crypt.user_crypt_hashed
            self.db.insert_user_object(user_items_encrypted[i])

    def play(self):
        # nya me, nya you, nya everyone!!
        pygame.mixer.music.load("../sound/nya.mp3")
        pygame.mixer.music.play(loops=0)


main_store_load = MainProgram(b'j7\x85\x1a9\xa0\x1b%\xe6\x08\x19\xeb:\xc3\xd2a')
# receives the admin key as parameter in binary state
