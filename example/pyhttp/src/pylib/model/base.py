import peewee

db_name = "sge_file_manager"
db_user = "root"
db_pass = "12345"
db_host = "localhost"
db_port = 3306

db = peewee.MySQLDatabase(db_name, user=db_user, password=db_pass, host=db_host, port=db_port, charset="utf8mb4")
db.connect()

class BaseModel(peewee.Model):
    class Meta:
        database = db
