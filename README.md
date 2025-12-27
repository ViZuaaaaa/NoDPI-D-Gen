# D-gen | NoDPI (D‑Gen v4, local‑first)

**Язык:** Русский | **English:** `README.en.md`

Лицензия: **Apache-2.0** (см. `LICENSE`).

D‑Gen v4 — это **локальный HTTP/HTTPS прокси** (поддерживает CONNECT), который умеет **фрагментировать первый TLS ClientHello** по правилам (через SNI) и отдаёт **PAC-файл** для быстрой настройки браузера.

> Важно: это **не VPN**. Подробности, ограничения и риски см. в `DISCLAIMER.md`.

---

## Быстрый старт (Windows) — рекомендованный путь

Требования:
- Python **3.8+**
- На Windows обычно есть команда **`py`** (Windows Python Launcher).

### 1) Запуск «одной кнопкой»

```bat
cd dgen-nodpi4-main
run-dgen4.bat
```

`run-dgen4.bat` делает ровно это:
1) выполняет `enable-youtube` (записывает правила/параметры для YouTube в конфиг)
2) запускает прокси + PAC **в отдельном окне**: `py dgen_nodpi.py run`
3) запускает Chrome с PAC:
   - `--proxy-pac-url="http://127.0.0.1:8882/proxy.pac"`
   - `--disable-extensions --disable-quic --new-window`

Также он предупреждает, что **Chrome должен быть полностью закрыт** (иначе флаги PAC/прокси могут игнорироваться) и предлагает убить `chrome.exe`.

### 2) Проверка

Откройте YouTube. В консоли D‑Gen вы должны увидеть обновляющуюся строку статистики (если `console.mode=stats`).

Остановка: **Ctrl+C** в окне прокси.

---

## Альтернативный запуск

### Запуск прокси без автозапуска Chrome

```bat
cd dgen-nodpi4-main
run.bat
```

`run.bat` запускает `py dgen_nodpi.py` **без команды**, и скрипт покажет интерактивный выбор:

- `1` — **Старт** (запуск proxy + PAC)
- `2` — **Меню** (выбор действий без набора команд)
- `0` — **Выход**

---

## CLI: команды и режимы

### Команды

```bat
py dgen_nodpi.py --config dgen-nodpi4.json run
py dgen_nodpi.py doctor
py dgen_nodpi.py pac
py dgen_nodpi.py enable-youtube
py dgen_nodpi.py version

py dgen_nodpi.py status
py dgen_nodpi.py install
py dgen_nodpi.py uninstall
```

Примечания:
- `--config` (по умолчанию: `dgen-nodpi4.json`) — путь к JSON конфигу.
  - если путь **относительный**, он будет резолвиться относительно директории скрипта.
- `run` запускает **proxy + PAC server**.
- `doctor` делает самопроверку (Python, проверка, что порты можно занять) и печатает «Next steps».
- `pac` печатает PAC URL и содержимое `proxy.pac`.
- `enable-youtube` записывает рекомендованные правила YouTube в конфиг.
- `status/install/uninstall` — Windows‑автозапуск (см. ниже).

### Меню (интерактивный режим)

Если выбрать «Меню», вы увидите:

- `1` — Start proxy + PAC (run)
- `2` — Doctor (self-test)
- `3` — Show PAC URL and contents (pac)
- `4` — Enable YouTube preset (enable-youtube)
- `5` — Autostart status (Windows)
- `6` — Autostart install (Windows)
- `7` — Autostart uninstall (Windows)
- `0` — Exit

Интерфейс:
- экран очищается перед показом меню
- после некоторых действий будет пауза «нажмите Enter…»

---

## Статистика в консоли (console.mode)

Когда `verbose=false` и `console.mode=stats`, D‑Gen печатает одну обновляющуюся строку вида:

- `Conn: active=… total=…` — активные/всего подключения клиентов к прокси
- `HTTP=…` — количество HTTP запросов (absolute-form)
- `CONNECT=…` — количество CONNECT туннелей
- `TLS_hello=…` — сколько TLS ClientHello увидели
- `frag=… (..%)` — сколько из них фрагментировали (и процент)

Если строка мешает:
- поставьте в конфиге `"console": { "mode": "quiet" }`

---

## Конфиг: `dgen-nodpi4.json`

По умолчанию конфиг лежит рядом со скриптом и называется `dgen-nodpi4.json`.

Ключевые секции:

- `proxy.host`, `proxy.port` — где слушает прокси (по умолчанию `127.0.0.1:8881`)
- `pac.port` — порт PAC сервера (по умолчанию `8882`)
- `log.path` — путь к файлу лога (в файл пишется детальнее, чем в консоль)
- `verbose` — если `true`, то в консоль пойдёт больше логов (и stats‑строка не выводится)
- `console.mode` — `stats` или `quiet`
- `domains.matching` — `strict` или `loose` (как матчить доменные суффиксы)
- `net.prefer_ipv4` — предпочитать IPv4 при соединениях (полезно, если IPv6 ломает YouTube)
- `net.dial_timeout_s` — таймаут на соединение
- `upstream.*` — режим «remote-node baseline» (см. ниже)
- `fragment.*` — глобальные настройки фрагментации
- `rules[]` — правила по доменам

### Правила `rules[]`

Каждое правило:
- `suffix` — доменный суффикс (например, `.youtube.com` или `youtu.be`)
- `action` — `pass` или `fragment`
- опционально: `tls.fragment` — **переопределение** фрагментации только для этого правила

### Сопоставление доменов: `domains.matching`

- `strict` (по умолчанию): матчится **точно** или по границе через точку
  - `example.com` матчится на `example.com` и `www.example.com`
  - но **не** матчится на `notexample.com`
- `loose`: простой `endswith` (может задеть лишнее)

### Фрагментация TLS ClientHello

Глобальные параметры — в `fragment`.

Поддерживаемые стратегии (`fragment.strategy`):
- `random_parts` — N частей со случайными размерами
- `fixed_parts` — ровно `fixed_parts` частей
- `chunk_size` — фиксированные чанки по `chunk_size`
- `tiny_first` — очень маленький первый TLS record + остаток
- `sni_cut` — попытка разрезать внутри/рядом с байтами SNI (best‑effort), затем дробить хвост

Также есть джиттер между записями TLS рекордов:
- `jitter_ms_min` / `jitter_ms_max`

> Важно: фрагментация применяется только для CONNECT:443 и только к первому TLS record.

---

## Remote-node baseline (upstream CONNECT relay)

Режим `upstream` предназначен для ситуации «есть вторая машина вне DPI». Тогда локальный D‑Gen будет делать CONNECT **через upstream HTTP proxy**.

Как работает на практике:
1) На **remote** машине запустите D‑Gen (он поднимет HTTP proxy на `:8881`).
2) На **local** машине включите в конфиге:

```json
"upstream": {
  "enabled": true,
  "host": "REMOTE_IP_OR_DNS",
  "port": 8881
}
```

Примечание по реализации:
- upstream применяется **только к CONNECT** (HTTPS туннелям). Обычный HTTP (порт 80) ходит напрямую.

---

## Автозапуск Windows (install/status/uninstall)

Команды:

```bat
py dgen_nodpi.py status
py dgen_nodpi.py install
py dgen_nodpi.py uninstall
```

Что делает `install`:
- создаёт запись в **HKCU Run** (только для текущего пользователя)
- при входе в Windows запускает **только proxy + PAC**
- использует текущий интерпретатор Python (`sys.executable`) и сохраняет `--config` путь
- **не запускает браузер**

---

## Диагностика / типовые проблемы

1) Быстрый self-test:

```bat
cd dgen-nodpi4-main
py dgen_nodpi.py doctor
```

2) Порты заняты (`8881`/`8882`) — измените `proxy.port` / `pac.port` в конфиге.

3) Chrome игнорирует системный прокси / мешают расширения:
- используйте `run-dgen4.bat` (он запускает Chrome с PAC и отключает расширения + QUIC)

4) QUIC/HTTP3:
- рекомендуется отключить QUIC/HTTP3 в Chrome/Edge (`chrome://flags` → QUIC → Disabled)

5) Логи:
- детальные логи: файл из `log.path` (по умолчанию `dgen-nodpi4.log` в папке проекта)

---

## См. также

- `DISCLAIMER.md` — ограничения, риски, безопасность
- `LICENSE` — Apache-2.0
