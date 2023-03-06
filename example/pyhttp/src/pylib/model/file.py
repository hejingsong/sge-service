import peewee
import model.base

class File(model.base.BaseModel):
    id = peewee.PrimaryKeyField()
    filename = peewee.CharField(128)
    path = peewee.CharField(512)
    parent_id = peewee.IntegerField()
    cover = peewee.CharField(512)
    file_type = peewee.CharField(64)

File.create_table()
