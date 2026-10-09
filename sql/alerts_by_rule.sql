SELECT rule_id, severity, COUNT(*) alerts FROM alerts GROUP BY rule_id, severity ORDER BY alerts DESC;
