# 🛡️ Security Header Checker

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version0.0.1-orange.svg)]()

**Мощный CLI инструмент для анализа заголовков безопасности веб-сайтов и предоставления детальной оценки безопасности**

[English](README.md) | [Русский](README.ru.md)

</div>

---

## 🚀 Возможности

- ✅ **Анализ заголовков безопасности** - Проверка 7+ критических заголовков
- ✅ **Цветной CLI вывод** - Красивый терминальный интерфейс с цветами
- ✅ **Множественные форматы экспорта** - Сохранение в TXT, JSON, CSV
- ✅ **Продвинутые CLI опции** - Настройка таймаута, User-Agent, проверка SSL
- ✅ **Подробный режим** - Детальная информация и рекомендации
- ✅ **Оценка безопасности** - Процентная оценка безопасности
- ✅ **Обработка ошибок** - Надёжная обработка ошибок и валидация

## 📋 Поддерживаемые заголовки безопасности

| Заголовок | Описание | Балл |
|-----------|----------|------|
| **Strict-Transport-Security** | Принудительное использование HTTPS | 10 |
| **Content-Security-Policy** | Защита от XSS и инъекций данных | 15 |
| **X-Frame-Options** | Защита от кликджекинга | 8 |
| **X-Content-Type-Options** | Предотвращение MIME-снифинга | 5 |
| **X-XSS-Protection** | Защита от XSS атак | 5 |
| **Referrer-Policy** | Контроль информации реферера | 3 |
| **Permissions-Policy** | Контроль доступа к функциям браузера | 4 |

## 🛠️ Установка

### Требования
- Python 3.8 или выше
- Менеджер пакетов pip

### Настройка
```bash
# Клонирование репозитория
git clone https://github.com/yourusername/security-header-checker.git
cd security-header-checker

# Создание виртуального окружения
python -m venv venv

# Активация виртуального окружения
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt
```

## 🎯 Использование

### Базовое использование
```bash
# Проверка веб-сайта
python main.py https://example.com

# Подробный вывод
python main.py https://example.com --verbose

# Сохранение результатов в файл
python main.py https://example.com --output report.txt
```

### Продвинутые опции
```bash
# Кастомный таймаут и User-Agent
python main.py https://example.com --timeout 30 --user-agent "MyBot/1.0"

# Отключение редиректов и проверки SSL
python main.py https://example.com --no-redirects --no-verify-ssl

# Экспорт в разные форматы
python main.py https://example.com --output report.json
python main.py https://example.com --output report.csv
```

### Все доступные опции
```bash
python main.py --help
```

## 📊 Пример вывода

```
🔍 Checking the security of the site: https://google.com

📊 Security Check Results:
URL: https://google.com
Total Score: 35/50
Security Percentage: 70.0%

📋 Detailed Report:
------------------------------------------------------------
Strict-Transport-Security:
  Value: max-age=31536000; includeSubDomains; preload
  Status: ✅ GOOD
  Description: ✅ Enforces the use of HTTPS
  Score: 10

Content-Security-Policy:
  Value: object-src 'none';base-uri 'self';script-src 'nonce-...
  Status: ✅ GOOD
  Description: ✅ Content security policy to prevent XSS and data injection attacks
  Score: 15

📈 Summary:
✅ Well configured: 5
❌ Issues: 2
ℹ️ Info: 0

⚠️ Average security
```

## 🔧 CLI опции

| Опция | Короткая | Описание | По умолчанию |
|-------|----------|----------|--------------|
| `--verbose` | `-v` | Подробный вывод | False |
| `--output` | `-o` | Путь к файлу вывода | None |
| `--timeout` | `-t` | Таймаут запроса (секунды) | 10 |
| `--user-agent` | `-u` | Кастомный User-Agent | Chrome 120.0.0.0 |
| `--follow-redirects` | `-f` | Следовать HTTP редиректам | True |
| `--no-redirects` | `-n` | Отключить редиректы | False |
| `--max-redirects` | | Максимум редиректов | 5 |
| `--verify-ssl` | | Проверять SSL сертификаты | True |
| `--no-verify-ssl` | | Отключить проверку SSL | False |
| `--version` | `-V` | Показать версию | - |

## 📁 Структура проекта

```
security-header-checker/
├── main.py                 # Основное CLI приложение
├── requirements.txt        # Python зависимости
├── README.md              # Английская документация
├── README.ru.md           # Этот файл (Русский)
├── ROADMAP.md             # План разработки
└── src/
    ├── __init__.py
    ├── header_checker.py  # Анализ заголовков безопасности
    └── exporter.py        # Функциональность экспорта
```

## 🎨 Форматы экспорта

### TXT формат
Читаемый текстовый отчёт с детальным анализом и рекомендациями.

### JSON формат
Структурированные данные для программной обработки и интеграции.

### CSV формат
Табличные данные для анализа в электронных таблицах.

## 🚀 План разработки

Смотрите [ROADMAP.md](ROADMAP.md) для детальных планов разработки.

### Предстоящие функции
- 🔄 Массовая проверка сайтов
- 📈 HTML отчёты с графиками
- 🔔 Мониторинг и уведомления
- 🌐 Веб-интерфейс
- 🔌 Система плагинов

## 🤝 Участие в разработке

1. Форкните репозиторий
2. Создайте ветку для функции (`git checkout -b feature/amazing-feature`)
3. Зафиксируйте изменения (`git commit -m 'Add amazing feature'`)
4. Отправьте в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

## 📄 Лицензия

Этот проект лицензирован под MIT License - смотрите файл [LICENSE](LICENSE) для деталей.

---

<div align="center">

**Создано с ❤️ для веб-безопасности**

</div>
