import sqlite3


def migrate(database_path):
    print "migrating to db version 1"
    conn = sqlite3.connect(database_path)
    conn.text_factory = str
    cursor = conn.cursor()

    # read notifications from db
    cursor.execute('''SELECT * FROM notifications''')
    notifications = cursor.fetchall()

    # delete notifications table
    cursor.execute('''DROP TABLE notifications''')

    # create new table
    cursor.execute('''CREATE TABLE notifications(notifID TEXT UNIQUE, guid BLOB, handle TEXT, type TEXT,
    orderId TEXT, title TEXT, timestamp INTEGER, imageHash BLOB, read INTEGER)''')
    cursor.execute('''CREATE INDEX index_noftif_id ON notifications(notifID);''')

    # write notifications back into db
    for n in notifications:
        cursor.execute('''INSERT INTO notifications(notifID, guid, handle, type, orderId, title, timestamp,
    imageHash, read) VALUES (?,?,?,?,?,?,?,?,?)''', (n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7], n[8]))

    # update version
    cursor.execute('''PRAGMA user_version = 1''')
    conn.commit()
    conn.close()
