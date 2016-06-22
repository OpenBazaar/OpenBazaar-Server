__author__ = 'hoffmabc'

import smtplib
from smtplib import SMTPAuthenticationError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from log import Logger


class SMTPNotification(object):
    """
    A class for sending SMTP notifications
    """

    def __init__(self, db):
        self.db = db
        self.log = Logger(system=self)
        self.get_smtp_settings()

    def get_smtp_settings(self):
        settings = self.db.settings.get()
        self.server = settings[15]
        self.sender = settings[16]
        self.recipient = settings[17]
        self.username = settings[18]
        self.password = settings[19]

    def send(self, subject, body):

        settings = self.db.settings.get()
        is_enabled = True if settings[14] == 1 else False

        if is_enabled:
            # Construct MIME message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.sender
            msg['To'] = self.recipient

            html_body = MIMEText(body, 'html')
            msg.attach(html_body)

            try:
                server = smtplib.SMTP(self.server)
                server.starttls()

                # Authenticate if username/password set
                if self.username and self.password:
                    server.login(self.username, self.password)

                server.sendmail(self.sender, self.recipient, msg.as_string())
                server.quit()
            except SMTPAuthenticationError as e:
                self.log.error('Authentication Error: %s' % e)
            except Exception as e:
                self.log.error(e)
