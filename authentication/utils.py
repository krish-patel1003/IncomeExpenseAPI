from django.core.mail import EmailMessage
import smtplib
class Util:
    @staticmethod
    def send_email(data):

        email = EmailMessage(
            subject=data['email_subject'],
            body=data['email_body'],
            to=[data['to_email']]           
        )

        try:
            print("send mail called")
            email.send()
        except Exception as err:
            print(err)
