# test_style_security.py

import os

def login(user, password):
    # Hardcode mật khẩu (lỗi bảo mật)
    if password == "123456":
        print("Đăng nhập thành công!")
    else:
        print("Sai mật khẩu!")

def bad_style():
    print ("Khoảng trắng không chuẩn") # Style lỗi PEP8
    x=5
    if(x>3):print("Quá ngắn gọn!") # Style: viết lệnh 1 dòng

login("admin", "123456")
bad_style()
