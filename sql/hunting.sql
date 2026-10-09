-- Run: python -m soclab sql sql/hunting.sql   (first statement only) or paste into sqlite3 data/soclab.db
-- Top failed-login sources
SELECT src_ip, COUNT(*) failures, COUNT(DISTINCT user) users, MIN(ts) first, MAX(ts) last
FROM events WHERE category='authentication' AND outcome='failure'
GROUP BY src_ip ORDER BY failures DESC LIMIT 10;
