from analyzer.core import analyze_code
def test_mutable_default():
    src = "def f(a=[]):\n    a.append(1)\n"
    res = analyze_code(src, filename="test.py")
    types = [i["type"] for i in res["issues"]]
    assert "Lỗi Logic" in types

def test_eval_taint():
    src = "s = input()\nexec(s)\n"
    res = analyze_code(src, filename="test2.py")
    msgs = [i["msg"] for i in res["issues"]]
    assert any("exec" in m for m in msgs)
