import sqlite3


def migrate(database_path):
    print "migrating to db version 6"
    conn = sqlite3.connect(database_path)
    conn.text_factory = str
    cursor = conn.cursor()

    cursor.execute('''ALTER TABLE sales ADD COLUMN "statusChanged" INTEGER''')
    cursor.execute('''ALTER TABLE purchases ADD COLUMN "statusChanged" INTEGER''')
    cursor.execute('''ALTER TABLE cases ADD COLUMN "statusChanged" INTEGER''')

    cursor.execute('''UPDATE purchases SET statusChanged = 0;''')
    cursor.execute('''UPDATE purchases SET statusChanged = 0;''')
    cursor.execute('''UPDATE purchases SET statusChanged = 0;''')

    # update version
    cursor.execute('''PRAGMA user_version = 6''')
    conn.commit()
    conn.close()
