-- Everything one external IP touched, across all sources (replace the literal)
SELECT ts, source, action, outcome, user, http_path, api_key_id, cloud_event
FROM events WHERE src_ip='203.0.113.50' ORDER BY epoch;
