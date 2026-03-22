from shadowiot.doctor import run_doctor


def test_doctor_runs():
    findings = run_doctor()
    assert isinstance(findings, list)
    assert all(hasattr(f, "ok") for f in findings)
