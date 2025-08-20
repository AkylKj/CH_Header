# 🛡️ Security Header Checker

> Мощный CLI инструмент для анализа заголовков безопасности веб-сайтов

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.0.2-orange.svg)]()

[English](README.md) | [Русский](README.ru.md)

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


