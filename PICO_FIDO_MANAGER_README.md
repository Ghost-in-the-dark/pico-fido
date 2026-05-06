# Pico FIDO Key Manager

Программа для настройки и управления ключом безопасности **Pico FIDO** на базе микроконтроллера **RP2040** (Raspberry Pi Pico).

## Возможности

Поддерживает оба протокола FIDO:
- **FIDO U2F (CTAP1)** - классический протокол второго фактора
- **FIDO2 (CTAP2)** - современный протокол для беспарольной аутентификации

### Основные функции:

1. **Управление PIN-кодом**
   - Установка нового PIN-кода (4-63 символа)
   - Изменение существующего PIN-кода
   - Проверка количества оставшихся попыток ввода

2. **Управление учетными записями (Credential Management)**
   - Просмотр всех сохраненных Resident Keys
   - Регистрация новых учетных записей
   - Удаление учетных записей по ID или индексу
   - Экспорт списка учетных записей в JSON

3. **Информация об устройстве**
   - Версии поддерживаемых протоколов
   - Поддерживаемые алгоритмы шифрования
   - Возможности устройства (RK, UV, и т.д.)
   - AAGUID идентификатор

4. **Операции FIDO2**
   - Make Credential (регистрация)
   - Get Assertion (аутентификация)
   - Поддержка User Verification

5. **Сброс устройства**
   - Полное удаление всех данных
   - Возврат к заводским настройкам

## Требования

- Python 3.8+
- USB-ключ Pico FIDO на базе RP2040 с установленной прошивкой Pico FIDO
- Операционная система Linux, macOS или Windows

### Зависимости Python

```bash
pip install fido2 cryptography inputimeout
```

Для работы с NFC (опционально):
```bash
# Требуется установка PC/SC библиотеки в системе
# Debian/Ubuntu:
sudo apt-get install libpcsclite-dev pcscd
# macOS: встроенная поддержка
# Windows: встроенная поддержка

pip install pyscard
```

## Установка

1. Клонируйте репозиторий или скопируйте файл `pico_fido_manager.py`

2. Установите зависимости:
```bash
pip install fido2 cryptography inputimeout
```

3. Сделайте скрипт исполняемым (Linux/macOS):
```bash
chmod +x pico_fido_manager.py
```

## Использование

### Интерактивный режим (рекомендуется)

```bash
python3 pico_fido_manager.py --interactive
```

Или просто:
```bash
python3 pico_fido_manager.py
```

Интерактивное меню предоставляет удобный доступ ко всем функциям:
```
============================================================
  Pico FIDO Key Manager - Главное меню
============================================================
1. Информация об устройстве
2. Управление PIN-кодом
3. Просмотр учетных записей
4. Регистрация новой учетной записи
5. Аутентификация
6. Удаление учетной записи
7. Экспорт учетных записей
8. Сброс устройства
9. Выход
============================================================
```

### Командный режим

#### Получить информацию об устройстве
```bash
python3 pico_fido_manager.py --info
```

Пример вывода:
```json
{
  "versions": ["FIDO_2_0", "U2F_V2"],
  "extensions": ["hmac-secret", "credProtect", "minPinLength"],
  "aaguid": "d805a65442e28a01a9a5c64b3f5a5d12",
  "options": {
    "rk": true,
    "clientPin": true,
    "credMgmt": true,
    "up": true,
    "uv": true
  },
  ...
}
```

#### Список учетных записей
```bash
python3 pico_fido_manager.py --list
```

#### Установить PIN-код
```bash
python3 pico_fido_manager.py --set-pin
```

#### Изменить PIN-код
```bash
python3 pico_fido_manager.py --change-pin
```

#### Зарегистрировать новую учетную запись
```bash
# Базовая регистрация
python3 pico_fido_manager.py --register

# С указанием параметров
python3 pico_fido_manager.py --register \
  --rp-id example.com \
  --rp-name "Example Corp" \
  --user-name "john.doe" \
  --uv required
```

#### Аутентификация
```bash
python3 pico_fido_manager.py --authenticate --rp-id example.com
```

#### Удалить учетную запись
```bash
# По Credential ID (hex строка)
python3 pico_fido_manager.py --delete <credential_id_hex>

# Или через интерактивное меню по индексу
```

#### Экспорт учетных записей
```bash
# Автоматическое имя файла
python3 pico_fido_manager.py --export

# С указанием имени файла
python3 pico_fido_manager.py --export backup.json
```

#### Сброс устройства
```bash
# С подтверждением
python3 pico_fido_manager.py --reset

# Без подтверждения (осторожно!)
python3 pico_fido_manager.py --reset --force
```

### Все параметры командной строки

```
Основные режимы:
  -i, --info            Показать информацию об устройстве
  -l, --list            Список учетных записей
  --set-pin             Установить PIN-код
  --change-pin          Изменить PIN-код
  --register            Зарегистрировать новую учетную запись
  --authenticate        Аутентифицироваться
  --delete CRED_ID      Удалить учетную запись по Credential ID
  --reset               Сбросить устройство
  --export [FILE]       Экспортировать учетные записи в JSON
  --interactive         Интерактивный режим

Параметры:
  --rp-id RP_ID         Relying Party ID
  --rp-name RP_NAME     Relying Party Name
  --user-name USER_NAME Имя пользователя
  --origin ORIGIN       Origin для WebAuthn операций
  --pin PIN             PIN-код (не рекомендуется в CLI)
  --no-resident-key     Не создавать Resident Key
  --uv {required,preferred,discouraged}
                        Требование пользовательской верификации
  --force               Пропустить подтверждения
  --debug               Режим отладки
```

## Примеры использования

### Пример 1: Первоначальная настройка ключа

```bash
# 1. Проверяем информацию об устройстве
python3 pico_fido_manager.py --info

# 2. Устанавливаем PIN-код
python3 pico_fido_manager.py --set-pin

# 3. Регистрируем первую учетную запись для GitHub
python3 pico_fido_manager.py --register \
  --rp-id github.com \
  --rp-name GitHub \
  --user-name "myusername" \
  --uv preferred
```

### Пример 2: Управление существующими учетными записями

```bash
# Просмотреть все учетные записи
python3 pico_fido_manager.py --list

# Экспортировать резервную копию
python3 pico_fido_manager.py --export my_keys_backup.json

# Удалить старую учетную запись
python3 pico_fido_manager.py --delete abc123def456...
```

### Пример 3: Тестирование аутентификации

```bash
# Аутентификация для домена
python3 pico_fido_manager.py --authenticate \
  --rp-id example.com \
  --uv required
```

## Структура экспортируемого JSON файла

```json
{
  "metadata": {
    "existing_cred_count": 5,
    "max_remaining_count": 245
  },
  "credentials": [
    {
      "rp_id": "github.com",
      "rp_name": "GitHub",
      "user_id": "a1b2c3d4...",
      "user_name": "myusername",
      "user_display_name": "My Username",
      "credential_id": "abcdef123456...",
      "total_credentials": 1
    }
  ],
  "timestamp": "2024-01-15 10:30:45.123456"
}
```

## Безопасность

### Рекомендации по PIN-коду

- Используйте минимум 6 символов
- Избегайте простых комбинаций (1234, 0000, дата рождения)
- Не используйте один и тот же PIN для разных ключей
- Не передавайте PIN через командную строку (`--pin`)

### Важные предупреждения

⚠️ **Сброс устройства** (`--reset`) необратимо удаляет:
- Все сохраненные учетные записи
- PIN-код
- Все криптографические ключи

⚠️ **Экспорт учетных записей** содержит только метаданные:
- Приватные ключи НЕ экспортируются (они защищены аппаратно)
- Экспорт используется только для инвентаризации

## Поддерживаемые устройства

- Raspberry Pi Pico (RP2040) с прошивкой Pico FIDO
- Совместимые FIDO2 ключи безопасности, поддерживающие CTAP2

## Примечания по работе с RP2040

1. **Первое подключение**: При первом подключении ключа может потребоваться установка драйверов
2. **Режим загрузки**: Для перепрошивки удерживайте кнопку BOOTSEL при подключении USB
3. **Индикация**: Светодиод на плате показывает состояние операции

## Отладка

Включите режим отладки для подробной информации об ошибках:

```bash
python3 pico_fido_manager.py --info --debug
```

## Лицензия

AGPLv3 - см. файл LICENSE в репозитории Pico FIDO.

## Авторы

Инструмент разработан для работы с прошивкой Pico FIDO:
- Репозиторий: https://github.com/polhenarejos/pico-fido
- Документация: https://github.com/polhenarejos/pico-fido/wiki

## Поддержка

При возникновении проблем:
1. Убедитесь, что ключ правильно подключен
2. Проверьте, что установлена последняя версия прошивки
3. Запустите с флагом `--debug` для диагностики
4. Проверьте права доступа к USB устройству (Linux: добавьте пользователя в группу `plugdev`)

## См. также

- [WebAuthn спецификация](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance](https://fidoalliance.org/)
- [Pico FIDO прошивка](https://github.com/polhenarejos/pico-fido)
