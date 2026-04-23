-- Normalize usernames and emails by removing all whitespace
BEGIN;

UPDATE users SET username = regexp_replace(username, E'\\\\s', '', 'g') WHERE username != regexp_replace(username, E'\\\\s', '', 'g');
UPDATE user_emails SET email = regexp_replace(email, E'\\\\s', '', 'g') WHERE email != regexp_replace(email, E'\\\\s', '', 'g');

COMMIT;