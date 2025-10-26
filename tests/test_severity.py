import importlib

mod = importlib.import_module("severity")

def test_has_function():
    assert hasattr(mod, "cvss_to_severity")

def test_cvss_bands_examples():
    f = mod.cvss_to_severity
    assert f(0.0) == "None"
    assert f(3.9) == "Low"
    assert f(4.0) == "Medium"
    assert f(6.9) == "Medium"
    assert f(7.0) == "High"
    assert f(8.9) == "High"
    assert f(9.0) == "Critical"
    assert f(10.0) == "Critical"
