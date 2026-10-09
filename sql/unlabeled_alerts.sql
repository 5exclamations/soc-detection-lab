-- Alerts whose evidence touches no labeled event (baseline noise)
SELECT a.alert_id, a.rule_id FROM alerts a
WHERE NOT EXISTS (SELECT 1 FROM alert_events ae JOIN labels l ON l.event_id=ae.event_id WHERE ae.alert_id=a.alert_id);
