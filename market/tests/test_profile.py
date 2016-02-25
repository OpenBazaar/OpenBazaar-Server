from twisted.trial import unittest
from protos import objects
import os

from db.datastore import Database
from market.profile import Profile

class MarketProfileTest(unittest.TestCase):
    PUBLIC_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFbGMvQBCADI9MkIEyVeyeAV+R4za8DuFEJbUviWmwTV+iCpt4utcsBNQa+/
MWxcQcZK76hY9l6/xvXNZifnMozfifFL4n+FR4hFYp8fwB6QjikACsd6CfO2coUk
p3aZSvP1ops2Z/LRNLf1QAqtltnMqkBcKPHp3JMcZUmOx1gOWfSrnc2b2Jk45sW2
pD0tk3v4UU/4WP20lzHnnCTQaVT7RkDivcZEVSfACtYWKBvL8iHtDJds0hsb5nSs
qUTnK7IPkAdL8iHTNtCRoReyPPbnTQQMdWGNxyBpgOd2tAUtWEMyUfLa9/Hl0dgA
TnI6c8SG8mugvucoeLujqJjlzfIVR8QejLd9ABEBAAG0HE9CIFRlc3QgPG9idGVz
dEBpbnZhbGlkLmNvbT6JATgEEwECACIFAlbGMvQCGwMGCwkIBwMCBhUIAgkKCwQW
AgMBAh4BAheAAAoJEIsTPki+1mH2NtsH/jprOKjdltcUS4eQ3PD555xYX++qpVkT
lv0MH+NP3eTD8v/LA1pAqjI1Lb58SxT7j5mAgJkJmMZylmHhptOBvtW8hpIAAdYM
4ywDVyZO9lz9tk4snU8cZiZqKi3Rp3FWwR3dR+Eyx1ciiYNN2nhQoLZUhynE2ShB
O6dk9VpWjdNhK1PU2umSopNJBb6bTes00HnHordml/StrxQPmyoJ8ZEV452Mztzx
WcryI42F7OsHPAg3hxD1QZ9cf9SIl9/p4x8Td/yms2y+rL8p7t4zBmgxAFDcBRsh
qllYKJpeVP4Jb6uOGiVyUUB+rr5/G8C9tpjPjYpbe0EHvTOdKqSZrMe5AQ0EVsYy
9AEIAJci80lDNCrpQaOIgXBouWhOwKMzteg/LvtwVbtLu8biJSNv1z7v/BBBhYuJ
OzbF60L4a/e25dsgEc/3kG2FzBAjq3ecR/2DxfF4e2dio+SUtOdf9ycK3VXmJMas
KpYmOdSAfMMSzDmCBbwXQ27gxBdu4+gSmsWh31MLACZ29C0L+p99x6uoFX5hgOC8
XelhWAa4dsCOXDIbkOTVl44XSoMyQtFZmEsyRp7/7h78osgssinFgY87/EXE3exC
fYNLZhotQWuqKn+2NvvED/UShVfzOCmkobVltAKRVC8vgQn3ALBgmtw7J9P0fr2z
IW0E9NR6I6JdbWLz+6hZ6sTSFZ0AEQEAAYkBHwQYAQIACQUCVsYy9AIbDAAKCRCL
Ez5IvtZh9jsJB/4z9sNqCiKo/FYIBG6mTlWTZ0fTnfTy81zUTVmfPhJtnjGDGk6l
r5jqi6itSx+qkRiV9W9IVUQLXboKIXFjugiWNTqbYtURiCigNis2SEkQ1uYp3y3H
o7IQG52dTqB5gopOx/jNDrcv0z7Vf71UOg9L0WU/5F4AZhxUMo0jCQudWbp0okEo
yOjZDvyBt/8ESAZCa/51doYeKBq+olS03AusUF6S1tyIOHaFWA/cCumc0QzdrHkD
gPJjjEdv9iS9Gyyc/G5p9xcIch3lw+pcRLqBAch4AGKJPudEN9P/fbbMCeCbJLif
FAfk98lyZjL/oXBb5qX9qcQguehRyuE4ccGD=F9sf
-----END PGP PUBLIC KEY BLOCK-----"""

    SIGNATURE = """-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA1

4c103483-3757-4ac6-85af-51e1f3193236
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iQEcBAEBAgAGBQJWxjoAAAoJEIsTPki+1mH2cGkH/0w+Q0V00oYtM86kifiH5iY7
//uMjCv0pAaupcanJMBi0lJPVa0uijz09fXThF+pWq85nDTx5FDklNexzzqUEaaR
Qggk3abEm9LjXYS9gq0AR5Va0qxBo4Xe8oMAheYIyC4/ikG627ew+x5VMPfKfbFq
zaX5wLzZGfrFtWetE1kFBbzlmdb8jARlkRB68nvzSH3vCoyLkRXa9/l7FXouIuNG
4i5iTMeM4T+bu6A5yS4Fz67+AGZnC2VZwzsz3RrpuAV65LoM3w2wfFrM6sni76Gu
/+VUFmAv+o3i0gbTCbaf3wc0SYrD5hrzjilqPVCmTxQYe4cOD8N6D1ZrTYyMdYU=
=FPwF
-----END PGP SIGNATURE-----"""
    VALID_GUID = '4c103483-3757-4ac6-85af-51e1f3193236'

    def setUp(self):
        self.db = Database(filepath="test.db")
        self.createTestUser()

    def createTestUser(self):
        u = objects.Profile()
        u.name = "test_name"
        u.location = 2
        u.about = "hello world"
        s = u.SocialAccount()
        s.username = "test_fb_username"
        s.type = s.SocialType.Value("FACEBOOK")
        u.social.extend([s])
        self.db.profile.set_proto(u.SerializeToString())
        self.db.profile.set_temp_handle("test_handle")

    def tearDown(self):
        os.remove("test.db")

    def test_MarketProfile_get_success(self):
        p = Profile(self.db).get()
        self.assertEqual('test_name', p.name)
        self.assertEqual(2, p.location)
        self.assertEqual('hello world', p.about)
        self.assertEqual(1, len(p.social))
        self.assertEqual(0, p.social[0].type)
        self.assertEqual('test_fb_username', p.social[0].username)

    def test_MarketProtocol_get_serialized_success(self):
        p = Profile(self.db).get(serialized=True)
        self.assertEqual("\n\ttest_name\x10\x02R\x0bhello worldr\x12\x12\x10test_fb_username", p)

    def test_MarketProfile_remove_field_success(self):
        p = Profile(self.db)
        p.remove_field("about")
        user = p.get()
        self.assertEqual('test_name', user.name)
        self.assertEqual('', user.about)

    def test_MarketProfile_remove_social(self):
        p = Profile(self.db)
        p.remove_social_account("FACEBOOK")
        u = p.get()
        self.assertEqual(0, len(u.social))

    def test_MarketProfile_remove_lowercase_social(self):
        p = Profile(self.db)
        p.remove_social_account("facebook")
        u = p.get()
        self.assertEqual(0, len(u.social))

    def test_MarketProfile_remove_social_invalid(self):
        p = Profile(self.db)
        p.remove_social_account("TEST")
        u = p.get()
        self.assertEqual(1, len(u.social))

    def test_MarketProfile_add_social_no_proof(self):
        p = Profile(self.db)
        p.add_social_account("TWITTER", "test_twitter_username")
        u = p.get()
        self.assertEqual(2, len(u.social))
        self.assertEqual(0, u.social[0].type)
        self.assertEqual('test_fb_username', u.social[0].username)
        self.assertEqual(1, u.social[1].type)
        self.assertEqual('test_twitter_username', u.social[1].username)

    def test_MarketProfile_replace_social_no_proof(self):
        p = Profile(self.db)
        p.add_social_account("FACEBOOK", "test_updated_username")
        u = p.get()
        self.assertEqual(1, len(u.social))
        self.assertEqual(0, u.social[0].type)
        self.assertEqual('test_updated_username', u.social[0].username)

    def test_MarketProfile_add_social_with_proof(self):
        p = Profile(self.db)
        p.add_social_account("TWITTER", "test_twitter_username", "http://test_url")
        u = p.get()
        self.assertEqual(2, len(u.social))
        self.assertEqual(0, u.social[0].type)
        self.assertEqual('test_fb_username', u.social[0].username)
        self.assertEqual('', u.social[0].proof_url)
        self.assertEqual(1, u.social[1].type)
        self.assertEqual('test_twitter_username', u.social[1].username)
        self.assertEqual('http://test_url', u.social[1].proof_url)

    def test_MarketProfile_replace_social_with_proof(self):
        p = Profile(self.db)
        p.add_social_account("FACEBOOK", "test_updated_username", "http://fb_url")
        u = p.get()
        self.assertEqual(1, len(u.social))
        self.assertEqual(0, u.social[0].type)
        self.assertEqual('test_updated_username', u.social[0].username)
        self.assertEqual('http://fb_url', u.social[0].proof_url)

    def test_MarketProfile_add_social_invalid(self):
        p = Profile(self.db)
        p.add_social_account("TEST", "test_twitter_username")
        u = p.get()
        self.assertEqual(1, len(u.social))
        self.assertEqual(0, u.social[0].type)
        self.assertEqual('test_fb_username', u.social[0].username)

    def test_MarketProfile_update_success(self):
        u = objects.Profile()
        u.about = "updated world"
        p = Profile(self.db)
        p.update(u)
        updated_user = p.get()
        self.assertEqual("updated world", updated_user.about)

    def test_MarketProfile_get_temp_handle(self):
        p = Profile(self.db)
        self.assertEqual("test_handle", p.get_temp_handle())

    def test_MarketProfile_add_pgp_key_success(self):
        p = Profile(self.db)
        self.assertTrue(p.add_pgp_key(self.PUBLIC_KEY, self.SIGNATURE, self.VALID_GUID))
        u = p.get()
        self.assertEqual(self.SIGNATURE, u.pgp_key.signature)
        self.assertEqual(self.PUBLIC_KEY, u.pgp_key.public_key)

    def test_MarketProfile_add_pgp_key_wrong_guid(self):
        p = Profile(self.db)
        wrong_guid = '5c2dedbd-5977-4326-b965-c9a2435c8e91'
        self.assertFalse(p.add_pgp_key(self.PUBLIC_KEY, self.SIGNATURE, wrong_guid))
