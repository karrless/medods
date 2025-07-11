# Part of auth service API for medods

# Запуск

Запуск производится командой:

```bash
docker-compose -f docker-compose.yml up -d
```

При запуске поднимется два контейнера: с базой данных и с самим сервисом.

Миграция происходит в самом сервисе, во время миграции также создатся 5 записей в таблицу с пользователями

# Особенности

- Для связи access и refresh токенов был введен jti - id jwt тега, который не хранит секретных данных и может храниться в бд
-   Было принято решение оставить возмонжость создавать несколько access токена для одного guid, попдразумевая, что один пользователь может заходить с разных устройств.
-   При этом рефреш возможен только конкретной парой токенов.
-   Также реализована проверка ip и user-agent. Она распространяется в пределах одного access токена, т.е. у пользователя может быть несколько access токенов, но при этом при рефреше для конкретного токена проверяется ip и user-agent, и если в пределах одного токена разнятся ip или user-agent, то отправляется пост запрос на вебхук или происходит логаут соответственно.
-   Logout выполнен без особых проверок, лишь удаляется запись в бд. Это сделано по нескольким причинам:
    -   logout должен быть максимально простым
    -   если access токен невалиден, то можно считать, что пользователь итак деавторизирован
    -   если access валиден, то просто удаляется запись в бд, из-за чего доступ к защищенным ручкам api невозможен

## Формат отправки сообщения на webhook

```json
{
    "guid": "string",
    "old_ip": "string",
    "new_ip": "string",
    "timestamp": "string"
}
```
# База данных

1. Таблица `users` - таблица с пользователями:
    1. `guid` - соотвественно GUID пользователя
2. Таблица `tokens` - таблица с рефреш токенами:
    1. `jti` - JWT ID Access токена  PK
    2. `refresh_token` - bcrypt хэш refresh токен
    3. `ip` - IP пользователя, с которого была произведена аутентификация
    4. `user_agent` - User-Agent пользователя, с которого была произведена аутентификация
    5. `user_guid` - GUID пользователя для связи токена и пользоватлея


# Предложение по улушчению

1. Сделать TTL для Refresh и Access токенов (это не было реализовано в связи с тем, что не указано в ТЗ)
2. Корректировать поведение сервиса при нескольких access токенах на одном ip (у себя предположил, что с одного ip может быть несколько пользователей, и у самого пользователя может быть необходимость авторизации с помощью нескольких токенов с одного ip)
3. Для хранения токенов использовать Redis или аналог, если позволяет память, из-за большей производительности, а также наличия встроенного TTL
4. Добавить SHA512 ключ в более надежное хранилище, чем переменные окружения (например HashiCorp Vault или использовать Docker secrets)

# Примечание
Сама часть сервиса очень сырая, и использовать её, конечно, невозможно. Но были соблюдены все необходимые требования, все остальное же является конкретными доработками/улучшением безопасности/etc.
