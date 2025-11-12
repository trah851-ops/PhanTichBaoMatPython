# test_code.py

def add_to_list(item, some_list=[]):
    """
    Hàm này có một lỗi tiềm ẩn nguy hiểm.
    Tham số some_list mặc định sẽ được tái sử dụng qua các lần gọi.
    """
    some_list.append(item)
    return some_list

# Gọi hàm lần đầu
first_call = add_to_list('apple')
print(f"Lần gọi 1: {first_call}")

# Gọi hàm lần hai mà không truyền list
second_call = add_to_list('banana')
print(f"Lần gọi 2: {second_call}")
