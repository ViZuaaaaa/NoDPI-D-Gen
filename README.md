# D-Gen NODPI — автоматически настраивает подключение к недоступным сервисам (Discord • YouTube • Roblox)

> [!WARNING]
> **Официальный репозиторий:** https://github.com/ViZuaaaaa/NoDPI-D-Gen  
> Любые другие проекты/репаки/перезаливы — **фейк/неофициальные копии** (могут содержать вредоносные изменения). Используйте только официальный репозиторий.  
> Вопросы тут: https://t.me/DisappearGen

<p align="center">
  <img src="assets/screenshots/start.png" alt="D-Gen Launcher — стартовый экран" width="900">
</p>

<p align="center">
  <img alt="Windows 10/11" src="https://img.shields.io/badge/Windows-10%2F11-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
  <img alt="PowerShell" src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=for-the-badge&logo=powershell&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-Restricted-critical?style=for-the-badge" />
</p>

> [!IMPORTANT]
> Это Windows‑утилита. Для запуска и работы требуется **подтверждение UAC / права администратора**.

## Зачем я вообще взялся за этот проект

Если вы сталкивались с нестабильным доступом, то знаете типичный набор симптомов:

одна сеть работает идеально
другая сеть «почти», но с непонятными ошибками
третья сеть ломает ровно то, что нужно вам сейчас
Дальше начинается классика. Поиск советов. Подбор настроек. Перезапуски. «Вчера работало, сегодня нет».

D-Gen NoDPI вырос из желания убрать ручную возню и сделать продуктовую штуку, которой можно пользоваться каждый день. Не как «проект для настроек», а как «приложение для жизни».

## Что такое D-Gen NoDPI (если совсем коротко)

- Windows GUI с Start/Stop
- авто-подбор режима под вашу сеть
- запоминание того, что уже работало у вас
- приоритет на практичные кейсы: YouTube, Discord, Roblox
- простая диагностика, чтобы в случае проблем не гадать часами


Проект предназначен для ситуаций, когда доступ к сервисам ломается из‑за сетевых ограничений (DPI/фильтрация/прокси‑политики и т.п.).

## Скриншоты

| Start | Menu (Advanced) | Loading |
|---|---|---|
| <img src="assets/screenshots/start.png" width="300" alt="Start" /> | <img src="assets/screenshots/menu.png" width="300" alt="Menu" /> | <img src="assets/screenshots/load.png" width="300" alt="Loading" /> |

## Как запустить

1) Скачай и распакуй **всю папку проекта** так, чтобы рядом лежали:
- `D-Gen/`
- `strategies/`
- `lists/`
- `utils/`
- `bin/`

> [!IMPORTANT]
> Для работы нужен `bin/` (внутри `DGen.exe`, `WinDivert.dll`, `WinDivert64.sys`, `cygwin1.dll`, *.bin).

2) Запусти **`oneclick-local.bat`**.

3) Если Windows попросит права администратора — **подтверди UAC**.

4) В окне **D‑Gen Launcher** нажми **Start**.

Остановка: кнопка **Stop**.

> [!NOTE]
> На «чистом ПК» обычно всё заводится на Windows 10/11 x64 при наличии прав администратора. 
> На корпоративных/жёстко настроенных ПК запуск может быть ограничен политиками PowerShell или антивирусом.

## Установка

### Вариант A — просто скачать и запустить
- Скачать **Release ZIP**, распаковать.
- Запуск: `oneclick-local.bat`.


## Использование

### Основной сценарий
1) Нажми **Start**.
2) Открой Discord Desktop / Roblox / YouTube для проверки.
3) Если что‑то не работает — открой **Advanced**, попробуй включить Aggressive Mode или QUIC block и запусти заново.

### Advanced (что означает)
- **Smart Mode (Discord)** — включает дополнительные проверки/логику, связанную с Discord.
- **Aggressive Mode** — более «жёсткие» параметры стратегий.
- **Block QUIC (UDP 443)** — блокирует QUIC как один из частых источников проблем.
- **Disable Windows Proxy/PAC** — временно отключает системный proxy/PAC на время сессии (и восстанавливает на Stop).
- **Clear Discord cache** — очистка кеша Discord (иногда помогает при странных ошибках после изменения сети).

## Логи и диагностика

- Основной лог лаунчера: `D-Gen/logs/dgen-launch.log`
- Логи генератора: `D-Gen/logs/dgen-generator.stdout.log`, `D-Gen/logs/dgen-generator.stderr.log`
- Логи движка (DGen.exe): `D-Gen/logs/engine.stdout.log`, `D-Gen/logs/engine.log`
- Сводка (autopick/coreprobes): `D-Gen/logs/dgen-summary.json`
- Если GUI не открылся / сразу закрылся: `D-Gen/logs/launcher-startup.error.log`

## Troubleshooting

<details>
<summary><b>Окно не запускается / сразу закрывается</b></summary>

1) Запусти `oneclick-local.bat` ещё раз и **подтверди UAC**.
2) Открой `D-Gen/logs/launcher-startup.error.log` и смотри самый свежий кусок.
3) Проверь, что рядом есть `strategies/`, `lists/`, `utils/`.
4) Если Defender/антивирус блокирует файлы — добавь папку в исключения (если доверяешь исходникам).

</details>

<details>
<summary><b>Start прошёл, но сервисы не работают</b></summary>

1) Открой `D-Gen/logs/dgen-summary.json` (если есть) и `D-Gen/logs/engine.log`.
2) Посмотри:
   - что выбрал **autopick** (profile/score) и какие **coreprobes** падают;
   - нет ли ошибок драйвера/WinDivert/прав администратора.
3) Попробуй включить **Aggressive Mode** и/или **Block QUIC**, затем Start ещё раз.

</details>

## Структура проекта

- `oneclick-local.bat` — запуск GUI
- `D-Gen/launcher.ps1` — GUI + запуск/контроль стратегии, логи/диагностика
- `D-Gen/config.json` — конфиг
- `strategies/` — актуальные стратегии (`general*.bat`)
- `lists/` — домены/ipset
- `utils/` — утилиты

## Лицензия

Ограниченная лицензия  — см. `LICENSE`.
