from rest_framework.test import APITestCase
from django.urls import reverse


class TestSetUp(APITestCase):
    register_url = reverse('register')
    register_url = reverse('login')

    def setUp(self):
        self.register_url = reverse('register')
        self.login_url = reverse('login')

        self.user_data = {
            'email':"email@email.com",
            'username':"email",
            'password':'email@email.com'
        }

        return super().setUp()

    def tearDown(self):
        return super().tearDown()