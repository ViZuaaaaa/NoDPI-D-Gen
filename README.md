# D-Gen — лаунчер  (Discord/YouTube)

**UPDATE:** This repository was refreshed to the latest D-Gen version (full replacement of the old contents).


**D-Gen** — простой лаунчер (GUI) для запуска набора стратегий из папки `strategies/` и управления запуском/остановкой.

> Это Windows‑утилита. Для работы нужны права администратора (UAC).

---

## Быстрый старт 

1) Распакуй/скопируй **всю папку**  (чтобы рядом были `D-Gen/`, `strategies/`, `utils/`, `lists/`).
2) Запусти **`oneclick-local.bat`**.
3) Если Windows попросит права администратора — **подтверди UAC**.
4) В окне **D-Gen Launcher** нажми **Start**.
5) Для корректной работы Discord cразу включайте галочку proxy 
Чтобы всё остановить — нажми **Stop**.

---

## Запустится ли на «чистом ПК»?

Обычно да, если это:
- **Windows 10/11 (x64)**
- есть **права администратора** (или можно подтвердить UAC)

Не запустится/будет нестабильно, если:
- PowerShell/скрипты запрещены политиками (часто на корпоративных ПК)
- Defender/антивирус/SmartScreen блокирует файлы/драйвер/процессы

---

## Что делает Start

- Запускает генератор `utils/ai_request_rewriter.ps1` (если включено/нужно) и затем
- перебирает стратегии `strategies/general*.bat`
- оставляет запущенной стратегию, которая проходит быстрые проверки доступности.

---

## Где смотреть логи

- Основной лог лаунчера: `D-Gen/logs/dgen-launch.log`
- Если GUI не открылся или сразу закрылся: `D-Gen/logs/launcher-startup.error.log`
- Логи генератора/стратегий: `D-Gen/logs/dgen-generator.*.log`, `D-Gen/logs/dgen-strategy.*.log`

---

## Если не запускается (прям чек-лист)

1) Запусти **`oneclick-local.bat`** ещё раз и **подтверди UAC**.
2) Открой `D-Gen/logs/launcher-startup.error.log` и посмотри **самую последнюю секцию** (по времени).
3) Если антивирус/Defender ругается — добавь папку в исключения или разреши запуск.
4) Проверь, что папка `strategies/` существует и в ней есть `general*.bat`.

---

## Структура папок (минимум)

- `oneclick-local.bat` — запуск GUI
- `D-Gen/launcher.ps1` — сам лаунчер
- `D-Gen/config.json` — конфиг
- `strategies/` — стратегии (`general*.bat`)
- `lists/` — списки
- `utils/` — утилиты

---

## Для разработчиков

Если нужно запускать без bat:
- `oneclick-local.ps1` стартует `D-Gen/launcher.ps1` в скрытом окне PowerShell.


