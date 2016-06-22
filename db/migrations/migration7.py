import sqlite3


def migrate(database_path):
    print "migrating to db version 7"
    conn = sqlite3.connect(database_path)
    conn.text_factory = str
    cursor = conn.cursor()

    # create new table
    cursor.execute('''CREATE TABLE IF NOT EXISTS audit_shopping (
      audit_shopping_id integer PRIMARY KEY NOT NULL,
      shopper_guid text NOT NULL,
      contract_hash text,
      "timestamp" integer NOT NULL,
      action_id integer NOT NULL
    );''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS shopper_guid_index ON audit_shopping (audit_shopping_id ASC);''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS action_id_index ON audit_shopping (audit_shopping_id ASC);''')

    # update version
    cursor.execute('''PRAGMA user_version = 7''')
    conn.commit()
    conn.close()
