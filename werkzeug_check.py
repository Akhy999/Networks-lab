from werkzeug.security import generate_password_hash,check_password_hash


# def hashit(password):
#     hashed_pass = generate_password_hash(password)
#     print(hashed_pass)
#     return hashed_pass

# hashit('1234567890')
# hashit('1234567890')
# hashit('1234567890')

from flask_bcrypt import Bcrypt

# # Create the Hasher
bcrypt = Bcrypt()

# hashed_pass = bcrypt.generate_password_hash('mypassword')
# print(hashed_pass)
# wrong_check = bcrypt.check_password_hash(hashed_pass, 'wrongpass')
# print(wrong_check)
# right_check = bcrypt.check_password_hash(hashed_pass, 'mypassword')
# print(right_check)
# hashed_pass = generate_password_hash('mypassword')
# print(hashed_pass)
# wrong_check = check_password_hash(hashed_pass,'wrong')
# print(wrong_check)
# right_check = check_password_hash(hashed_pass,'mypassword')
# print(right_check)

c=b'$2b$12$Fl6AiVtNa.CornTjpNi1ZuNp.xWniNFC14lEcNNJZUH3M8t.WQIKe'
right_check = bcrypt.check_password_hash(c, 'mypassword')
print(right_check)
