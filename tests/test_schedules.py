from datetime import datetime
from zoneinfo import ZoneInfo

from servermanager.models import MaintenanceSchedule
from servermanager.schedules import compute_next_run, describe, validate_steps, required_level

TZ = ZoneInfo("Europe/Berlin")


def utc(*a):
    return datetime(*a)


def test_daily_summer_time():
    s = MaintenanceSchedule(recurrence="daily", time_of_day="03:00")
    # 2026-07-01 12:00 UTC -> next 03:00 CEST = 01:00 UTC next day
    assert compute_next_run(s, utc(2026, 7, 1, 12, 0), TZ) == utc(2026, 7, 2, 1, 0)
    # just before -> same night
    assert compute_next_run(s, utc(2026, 7, 1, 0, 30), TZ) == utc(2026, 7, 1, 1, 0)


def test_daily_winter_time():
    s = MaintenanceSchedule(recurrence="daily", time_of_day="03:00")
    assert compute_next_run(s, utc(2026, 1, 10, 12, 0), TZ) == utc(2026, 1, 11, 2, 0)


def test_weekly():
    s = MaintenanceSchedule(recurrence="weekly", time_of_day="02:30", weekdays=[6])  # sunday
    nxt = compute_next_run(s, utc(2026, 9, 23, 12, 0), TZ)  # wednesday
    assert nxt == utc(2026, 9, 27, 0, 30)
    assert "So" in describe(s)


def test_monthly_last_day():
    s = MaintenanceSchedule(recurrence="monthly", time_of_day="04:00", day_of_month=31)
    assert compute_next_run(s, utc(2026, 2, 1, 0, 0), TZ) == utc(2026, 2, 28, 3, 0)


def test_once():
    s = MaintenanceSchedule(recurrence="once", run_at=datetime(2026, 10, 1, 3, 0))
    assert compute_next_run(s, utc(2026, 9, 23), TZ) == utc(2026, 10, 1, 1, 0)
    assert compute_next_run(s, utc(2026, 10, 2), TZ) is None


def test_steps_validation_and_level():
    steps = validate_steps([{"module": "debian", "action": "upgrade", "params": {"autoremove": "1"}},
                            {"module": "command", "command": "  uptime "}])
    assert steps[0]["params"] == {"autoremove": "1"}
    assert steps[1] == {"module": "command", "action": "run", "command": "uptime"}
    assert required_level(steps) == "full"
    assert required_level(steps[:1]) == "operate"
