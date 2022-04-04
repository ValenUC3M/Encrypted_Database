import sqlite3 as sql


class Database:
    def __init__(self):
        self.conn = None

    # all this methods have a common use, they all need to create the connection and close it at the end
    # they all need to create a cursor for data management
    # they all need to select the instruction with it's parameters given in the data var

    def update_user_salt(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        instruccion = f"UPDATE users SET user_salt=? where name=?"
        cursor.execute(instruccion, data)
        self.conn.commit()
        self.conn.close()

    def update_user_nonce(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        instruccion = f"UPDATE users SET nonce=? where name=?"
        cursor.execute(instruccion, data)
        self.conn.commit()
        self.conn.close()

    def select_from_message_log(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()

        instruccion = f"SELECT * FROM message_log where receiver=? or receiver='all'"
        cursor.execute(instruccion, data)

        datos = cursor.fetchall()
        self.conn.commit()
        self.conn.close()
        return datos

    # funcion usada para registro y logueo en la bd
    def select_from_users(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()

        if len(data) == 2:
            instruccion = f"SELECT * FROM users where name=? AND password=?"
            cursor.execute(instruccion, data)
        else:
            instruccion = f"SELECT * FROM users where name=?"
            cursor.execute(instruccion, data)

        datos = cursor.fetchall()
        self.conn.commit()
        self.conn.close()
        return datos

    def update_user_object(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        instruccion = f"UPDATE storage SET item=?, item_nonce=? where user=? and item=?"
        cursor.execute(instruccion, data)
        self.conn.commit()
        self.conn.close()

    # si user es solo un nombre, cogemos toodo. Si no, cogemos el objeto pedido
    def select_from_storage(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()

        if len(data) == 2:
            instruccion = f"SELECT * FROM storage where user=? AND item=?"
            cursor.execute(instruccion, data)
        else:
            instruccion = f"SELECT * FROM storage where user=?"
            cursor.execute(instruccion, data)

        datos = cursor.fetchall()
        self.conn.commit()
        self.conn.close()
        return datos

    # funcion para insertar un nuevo usuario
    def register_user(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        instruccion = f"INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)"
        cursor.execute(instruccion, data)
        self.conn.commit()
        self.conn.close()

    def select_from_items(self, item):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()

        if len(item) == 0:
            instruccion = f"SELECT * FROM items ORDER BY name"
            cursor.execute(instruccion)
        else:
            instruccion = f"SELECT * FROM items where name=?"
            cursor.execute(instruccion, item)

        datos = cursor.fetchall()
        self.conn.commit()
        self.conn.close()
        return datos

    def update_items(self, item):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        instruccion = f"UPDATE items SET quantity=? where name=?"
        cursor.execute(instruccion, item)
        self.conn.commit()
        self.conn.close()

    def update_user_storage(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        instruccion = f"UPDATE storage SET amount=? where user=? and item=?"
        cursor.execute(instruccion, data)
        self.conn.commit()
        self.conn.close()

    def delete_user_storage(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        if len(data) == 1:
            instruccion = f"DELETE from storage where user=?"
            cursor.execute(instruccion, data)
        else:
            instruccion = f"DELETE from storage where user=? and item=?"
            cursor.execute(instruccion, data)
        self.conn.commit()
        self.conn.close()

    def insert_user_object(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        instruccion = f"INSERT INTO storage VALUES(?, ?, ?, ?, ?, ?, ?)"
        cursor.execute(instruccion, data)
        self.conn.commit()
        self.conn.close()

    def insert_message(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        instruccion = f"INSERT INTO message_log VALUES(?, ?, ?, ?)"
        cursor.execute(instruccion, data)
        self.conn.commit()
        self.conn.close()

    def delete_message(self, data):
        self.conn = sql.connect("database.db")
        cursor = self.conn.cursor()
        instruccion = f"DELETE from message_log where receiver=? and message=?"
        cursor.execute(instruccion, data)
        self.conn.commit()
        self.conn.close()
