import secrets
import os
import bcrypt

class Random_generator:

    # generates a random token using the secrets library for true randomness
    def generate_token(self, length=32, alphabet=(
    '0123456789'
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    )):
        return ''.join(secrets.choice(alphabet) for i in range(length))

    # generates salt using the bcrypt library which is a safe implementation
    def generate_salt(self, rounds=22):
        return bcrypt.gensalt()
        # didn't supply the rounds variable to gensalt() because it takes way longer to run

class SHA256_hasher:

    # produces the password hash by combining password + salt because hashing
    def password_hash(self, password, salt):
        return bcrypt.hashpw(password.encode(), salt)

    # verifies that the hashed password reverses to the plain text version on verification
    def password_verification(self, password, password_hash):
        return bcrypt.checkpw(password.encode(), password_hash)

# a collection of sensitive secrets necessary for the software to operate
PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
PUBLIC_KEY = os.environ.get('PUBLIC_KEY')
SECRET_KEY = os.environ.get('SECRET_KEY')
PASSWORD_HASHER = 'SHA256_hasher'
