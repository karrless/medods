CREATE TABLE IF NOT EXISTS public.users
(
  guid UUID NOT NULL PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS public.tokens
(
  jti UUID NOT NULL PRIMARY KEY,
  refresh_token TEXT NOT NULL UNIQUE,
  ip INET NOT NULL,
  user_agent TEXT NOT NULL,
  user_guid UUID REFERENCES users(guid) ON DELETE CASCADE NOT NULL
);

CREATE INDEX tokens_user_guid_idx ON public.tokens(user_guid);