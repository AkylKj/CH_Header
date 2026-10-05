# 🛡️ Security Header Checker

> Мощный CLI инструмент для анализа заголовков безопасности веб-сайтов

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/Version-0.0.3-orange.svg)]()

[English](Readme.md) | [Русский](README.ru.md)

## ✨ Возможности

- 🔒 **Анализ заголовков безопасности** - Проверка 15+ критических заголовков
- 🚀 **Массовая проверка** - Параллельная обработка множества сайтов
- 🔐 **SSL/TLS анализ** - Детальная проверка сертификатов и шифрования
- 📡 **Анализ ответов** - HTTP статус коды и информация о сервере
- 🎨 **Красивый вывод** - Цветной терминальный интерфейс
- 💾 **Экспорт результатов** - TXT, JSON, CSV форматы

## 🚀 Быстрый старт

```bash
# Установка
pip install -r requirements.txt

# Проверка одного сайта
python main.py https://example.com

# Массовая проверка
python main.py --file urls.txt --parallel 5

# Полный анализ
python main.py https://example.com --ssl-check --response-analysis
```

## v0.0.3: установка и поведение

Целевая поддержка: Python 3.10–3.14. Создайте отдельное окружение:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --version
```

На Linux: `.venv/bin/python -m pip install -r requirements.txt`.

`--ssl-only` и `--response-only` запускают только выбранный модуль и
взаимоисключают друг друга. `--batch-size` ограничивает число сайтов в пакете,
`--parallel` — число работников; timeout и числовые лимиты должны быть положительными.
Редиректы по умолчанию не выполняются; включите `--follow-redirects` при необходимости.
`--no-verify-ssl` отключает проверку сертификата только для HTTP-запросов;
TLS-анализ независимо проверяет доверие и hostname.

TXT показывает включённые проверки; JSON сохраняет составной отчёт целиком;
CSV содержит колонки URL, Module, Check, Value, Status, Score, Error.
Частичные результаты сохраняются даже при ошибке одного модуля.
Код завершения: 0 — все выбранные проверки и экспорт выполнены,
1 — ошибка проверки или экспорта, 2 — неверные аргументы CLI.

Оценка — собственная эвристика, а не отраслевой стандарт или полный аудит.
Проверка значений CSP/HSTS/cookies остаётся базовой. TLS UNKNOWN означает
невозможность достоверной проверки; анализируется только согласованный cipher suite.
Недоверенный сертификат может отображаться, но не получает статус verified.

Тесты и конфигурация CI уже добавлены. До прерывания 88 тестов прошли на
Windows / Python 3.14. После просьбы пользователя новые тесты не пишутся
и проверки не запускаются. Удалённый CI и полная матрица ОС/Python пока не проверены.

## 📋 Поддерживаемые заголовки

| Заголовок | Описание | Балл |
|-----------|----------|------|
| **Strict-Transport-Security** | Принудительное использование HTTPS | 10 |
| **Content-Security-Policy** | Защита от XSS и инъекций | 15 |
| **X-Frame-Options** | Защита от кликджекинга | 8 |
| **X-Content-Type-Options** | Предотвращение MIME-снифинга | 5 |
| **X-XSS-Protection** | Защита от XSS атак | 5 |
| **Referrer-Policy** | Контроль информации реферера | 3 |
| **Permissions-Policy** | Контроль доступа к функциям браузера | 4 |
| **Server** | Информация о веб-сервере | 2 |
| **X-Powered-By** | Технологии сайта | 2 |
| **Cache-Control** | Политика кэширования | 3 |
| **Set-Cookie** | Безопасность куки | 4 |
| **Clear-Site-Data** | Очистка данных | 3 |
| **Cross-Origin-Embedder-Policy** | Cross-origin embedder policy | 3 |
| **Cross-Origin-Opener-Policy** | Cross-origin opener policy | 3 |
| **Cross-Origin-Resource-Policy** | Cross-origin resource policy | 3 |

## 📖 Документация

- [План разработки](ROADMAP.md)

## 🤝 Участие в разработке

1. Форкните репозиторий
2. Создайте ветку для функции
3. Зафиксируйте изменения
4. Отправьте Pull Request


