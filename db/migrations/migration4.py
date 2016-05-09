import sqlite3


def migrate(database_path):
    print "migrating to db version 4"
    conn = sqlite3.connect(database_path)
    conn.text_factory = str
    cursor = conn.cursor()

    # update settings table to include smtp server settings
    cursor.execute('''ALTER TABLE settings ADD COLUMN "smtpNotifications" INTEGER''')
    cursor.execute('''ALTER TABLE settings ADD COLUMN "smtpServer" TEXT''')
    cursor.execute('''ALTER TABLE settings ADD COLUMN "smtpSender" TEXT''')
    cursor.execute('''ALTER TABLE settings ADD COLUMN "smtpRecipient" TEXT''')
    cursor.execute('''ALTER TABLE settings ADD COLUMN "smtpUsername" TEXT''')
    cursor.execute('''ALTER TABLE settings ADD COLUMN "smtpPassword" TEXT''')

    # update version
    cursor.execute('''PRAGMA user_version = 4''')
    conn.commit()
    conn.close()
