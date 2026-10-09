-- Successful logins preceded by >=5 failures from the same IP in the previous 15 minutes
SELECT s.ts, s.user, s.src_ip,
  (SELECT COUNT(*) FROM events f WHERE f.category='authentication' AND f.outcome='failure'
     AND f.src_ip=s.src_ip AND f.epoch BETWEEN s.epoch-900 AND s.epoch) AS prior_failures
FROM events s WHERE s.category='authentication' AND s.outcome='success'
GROUP BY s.event_id HAVING prior_failures>=5 ORDER BY s.epoch;
