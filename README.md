# SOCKS5 Proxy Server
Данная программа является SOCKS5-прокси сервером, предназначенным для переадресации запросов от клиента к конечному серверу и обратно:
```
Клиент -> Прокси-сервер -> Конечный сервер  
Клиент <- Прокси-сервер <- Конечный сервер
```
## Как использовать
### Запуск прокси-сервера
Для запуска SOCKS5-прокси сервера достаточно просто запустить исполняемый файл `socks5_proxy.exe`. После запуска откроется консольное окно, в котором будут отображаться логи — текущее состояние программы и подключений.

### Пример запроса от клиента
Для выполнения запроса от клиента через SOCKS5-прокси можно использовать утилиту `curl` из консоли. Пример команды:

```bash
curl --http0.9 --socks5-hostname <ip>:1080 http://ifconfig.me --output -
```
Где:
* `<ip>:1080` — IP-адрес и порт, на котором работает ваш прокси-сервер.
* `http://ifconfig.me` — URL, к которому осуществляется запрос (можно заменить на любой другой).

Пример с другим ресурсом:
```bash
curl --http0.9 --socks5-hostname <ip>:1080 http://example.com --output -
```

## Заметки
* Программа поддерживает SOCKS5 с разрешением доменных имен на стороне прокси (`-hostname`).
* Логи помогут отследить подключения и возможные ошибки.
* Убедитесь, что порт 1080 открыт и доступен для входящих подключений.
* HTTPS не поддерживается. Запросы по протоколу https:// не будут обработаны корректно.