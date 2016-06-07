import sqlite3
from protos import objects


def migrate(database_path):
    print "migrating to db version 3"
    conn = sqlite3.connect(database_path)
    conn.text_factory = str
    cursor = conn.cursor()
    # read followers from db
    cursor.execute('''SELECT serializedFollowers FROM followers WHERE id=1''')
    followers = cursor.fetchone()

    # delete follower table
    cursor.execute('''DROP TABLE followers''')

    # create new table
    cursor.execute('''CREATE TABLE followers(guid TEXT UNIQUE, serializedFollower TEXT)''')
    cursor.execute('''CREATE INDEX index_followers ON followers(serializedFollower);''')

    # write followers back into db

    if followers is not None:
        f = objects.Followers()
        f.ParseFromString(followers[0])
        for follower in f.followers:
            cursor.execute('''INSERT INTO followers(guid, serializedFollower) VALUES (?,?)''',
                           (follower.guid.encode("hex"), follower.SerializeToString().encode("hex"),))

    # update version
    cursor.execute('''PRAGMA user_version = 3''')
    conn.commit()
    conn.close()
