# Пошаговая инструкция: стенд, запуск прототипа, оценка НФТ-2

Два варианта стенда: **Б — в Docker** (одна команда, ниже) и **А — GNS3 + MikroTik CHR** (этапы 0–5).

Документ закрывает невыполненные пункты ТЗ: стенд GNS3 (ФТ-1), запись нормального трафика и
сценариев атак, проверку Telegram и Grafana (ФТ-4, ФТ-5), оценку на стенде (НФТ-2) и запуск
на чистой машине (НФТ-4).

| Этап | Кто | Время | Результат |
|---|---|---|---|
| 0. Подготовка ПО | все | 1–2 ч | GNS3, GNS3 VM, Docker Desktop, Python |
| 1. Запуск прототипа и Telegram (НФТ-4) | Мирас | 1 ч | `docker compose up` работает, приходят оповещения в режиме REPLAY |
| 2. Стенд в GNS3 | Батыйхан | 3–4 ч | 7 узлов, OSPF, потоки доходят до коллектора |
| 3. Запись трафика | Батыйхан + Мирас | 3,5 ч | норма 1 ч, обучающие атаки, тестовый час, журналы |
| 4. Переобучение и оценка | Диас | 1 ч | `stand_train.json`, `stand_eval.json` |
| 5. Обновление диплома | — | — | прислать файлы из этапа 4 |

Все времена в журналах и командах — **UTC**. Казахстан (Алматы) — UTC+5: 15:00 по Алматы = 10:00 UTC.

---

## Вариант Б: стенд целиком в Docker (без GNS3) — рекомендуется для ноутбука

Та же топология и адресация, маршрутизаторы — контейнеры FRR (OSPF) + softflowd (NetFlow v9),
хосты — образ `nids-host`. Нужен только Docker Desktop (WSL 2).

```powershell
docker compose -p nidslab -f docker-compose.yml -f stand/lab/docker-compose.lab.yml up -d --build
docker exec nidslab-r-core-1 vtysh -c "show ip ospf neighbor"      # 2 соседа Full
docker exec nidslab-sub-1-1 curl -s -o NUL -w "%{http_code}" http://203.0.113.10/   # 200
```

Полный эксперимент (≈ 3 ч 45 мин: норма 1 ч, обучающие атаки, переобучение, тестовый час,
час фона, оценка) запускается одним скриптом:

```powershell
python scripts/run_stand_experiment.py
```

Результаты: `results/stand_train.json`, `results/stand_eval_test.json`,
`results/stand_eval_background.json`, журналы `stand/journals/*.csv`, ход эксперимента —
`results/stand_session.log`. Демонстрация атаки вручную:

```powershell
docker exec nidslab-attacker-1 timeout 60 hping3 -S -p 80 -i u500 100.64.10.20
```

Особенности (подробно — раздел 2.2 записки): OSPF в режиме NBMA (Docker не пересылает multicast),
сети без NAT вместо internal, softflowd собран с тайм-аутом захвата 100 мс, задержка записи 22–26 с
(допуск детектора `GRACE_S=30`), интенсивность атак ограничена 2000 пакетов/с.

---

## Этап 0. Подготовка ПО (на ноутбуке, где будет стенд)

Нужно: Windows 10/11, ≥ 16 ГБ ОЗУ, ≥ 40 ГБ свободного места, включённая виртуализация в BIOS.

1. **Docker Desktop** — https://www.docker.com/products/docker-desktop/ (бэкенд WSL 2).
   Проверка в PowerShell: `docker version` и `docker compose version`.
2. **Git** и **Python 3.12** (галочка «Add to PATH»).
3. **GNS3 2.2.x** (all-in-one) — https://www.gns3.com/software/download и **GNS3 VM для VirtualBox**
   той же версии (VirtualBox у вас уже установлен).
   - Импортировать `GNS3 VM.ova` в VirtualBox (File → Import Appliance), выделить 4–6 ГБ ОЗУ, 2–4 ядра.
   - GNS3 → Edit → Preferences → GNS3 VM → Enable, тип VirtualBox, VM name «GNS3 VM».
   - Важно: Docker Desktop (WSL 2/Hyper-V) и VirtualBox 7 могут работать одновременно; если GNS3 VM
     не стартует или работает очень медленно, обновите VirtualBox до 7.x.
4. **Образ MikroTik CHR**: https://mikrotik.com/download → Cloud Hosted Router → «Raw disk image»
   версии 7.x (`chr-7.x.img.zip`). В GNS3: File → New template → «Install an appliance from the GNS3
   server» → найти **MikroTik CHR** → выбрать скачанный образ.
5. Клонировать репозиторий:
   ```powershell
   git clone https://github.com/mapeke/anomaly-detection.git
   cd anomaly-detection
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```

---

## Этап 1. Запуск прототипа и Telegram (Мирас) — НФТ-4, ФТ-4, ФТ-5

### 1.1. Бот Telegram

1. В Telegram написать **@BotFather** → `/newbot` → имя, например `nids_batiy_bot` → получить **токен**
   вида `123456789:AA...`.
2. Написать своему боту любое сообщение (или добавить бота в общую группу команды и написать там).
3. Открыть в браузере `https://api.telegram.org/bot<ТОКЕН>/getUpdates` и найти `"chat":{"id":...}` —
   это **chat_id** (для группы число отрицательное).
4. В папке репозитория:
   ```powershell
   copy .env.example .env
   notepad .env
   ```
   заполнить `TELEGRAM_BOT_TOKEN=...` и `TELEGRAM_CHAT_ID=...`. Файл `.env` в git не попадает.

### 1.2. Проверка «на чистой машине» (НФТ-4)

Лучше на другом компьютере или в новой папке (свежий `git clone`), чтобы проверить README:

```powershell
$env:REPLAY="1"; docker compose up --build
```

Что должно произойти:
- поднимаются 5 сервисов: `db`, `collector`, `loader`, `detector`, `grafana`;
- в логах `loader` — `replay: ... flows`, в логах `detector` — `start: ... telegram=True` и строки `flows=... windows=...`;
- примерно через **2,5 мин** (первая атака в режиме воспроизведения начинается на 120-й секунде)
  в Telegram приходит оповещение «SYN-флуд», затем UDP-флуд, сканирование, подбор пароля
  с интервалом 5 мин;
- Grafana: http://localhost:3000 → Dashboards → NIDS → «NetFlow IDS — трафик и инциденты»
  (графики трафика и таблица инцидентов).

Сделайте **скриншоты** оповещения в Telegram и дашборда — они нужны в диплом (раздел 3).

Остановить и очистить БД перед работой со стендом (иначе данные воспроизведения смешаются с данными стенда):

```powershell
docker compose down -v
```

### 1.3. Открыть порт NetFlow в брандмауэре Windows

PowerShell **от имени администратора**:

```powershell
New-NetFirewallRule -DisplayName "NetFlow 2055" -Direction Inbound -Protocol UDP -LocalPort 2055 -Action Allow
```

---

## Этап 2. Стенд в GNS3 (Батыйхан)

### 2.1. Сеть между стендом и коллектором (host-only адаптер 10.0.0.100)

Коллектор (docker compose) работает на Windows. Чтобы маршрутизаторы стенда видели его по адресу
**10.0.0.100** (как в плане адресации), создаётся отдельный host-only адаптер VirtualBox:

1. VirtualBox → File → Tools → **Network Manager** → Host-only Networks → **Create**.
   IPv4: `10.0.0.100`, маска `255.255.255.0`, **DHCP Server — выключить**.
2. Выключить GNS3 VM → Settings → Network → **Adapter 3** → Enable → Attached to: Host-only Adapter →
   выбрать только что созданный адаптер. Запустить GNS3 VM снова.
3. Проверка в PowerShell: `ipconfig` — у адаптера «VirtualBox Host-Only Ethernet Adapter #2» адрес 10.0.0.100.
4. В консоли GNS3 VM (Shell, см. п. 2.2) поднять интерфейс без адреса: `sudo ip link set eth2 up`
   (повторять после каждой перезагрузки GNS3 VM).

### 2.2. Образ хостов

В GNS3 VM есть Docker. Подключиться к ней (адрес показан в окне GNS3 VM, логин/пароль `gns3`/`gns3`):

```bash
ssh gns3@<IP_GNS3_VM>
# в меню выбрать Shell
git clone https://github.com/mapeke/anomaly-detection.git
cd anomaly-detection
docker build -t nids-host -f stand/docker/Dockerfile stand
```

GNS3 → Edit → Preferences → Docker → Docker containers → **New** → «Run on GNS3 VM» →
Image: `nids-host` → Name: `nids-host` → Adapters: 1 → Start command: `/bin/bash` → Console: telnet.

### 2.3. Топология (7 узлов + коммутатор + облако)

Создать проект и узлы, соединить по схеме `stand/README.md`:

| Узел | Тип | Подключение |
|---|---|---|
| R-BORDER | MikroTik CHR | ether1 → R-CORE ether1; ether2 → EXT-SRV; ether3 → ATTACKER |
| R-CORE | MikroTik CHR | ether2 → R-BNG ether1; ether3 → коммутатор SW-DC |
| R-BNG | MikroTik CHR | ether2 → SUB-1; ether3 → SUB-2 |
| SW-DC | Ethernet switch | → ISP-SRV; → Cloud |
| Cloud | Cloud (на GNS3 VM) | интерфейс **eth2** (адаптер 3 из п. 2.1) |
| SUB-1, SUB-2, EXT-SRV, ISP-SRV, ATTACKER | nids-host | eth0 |

Для облака: правой кнопкой → Configure → вкладка Ethernet interfaces → отметить
«Show special Ethernet interfaces» → добавить **eth2**.

### 2.4. Адреса хостов

Для каждого контейнера (узел выключен): правой кнопкой → **Configure** → General settings →
Network configuration → **Edit** (файл `/etc/network/interfaces`):

```
# SUB-1 (SUB-2 — адрес 100.64.10.21)
auto eth0
iface eth0 inet static
    address 100.64.10.20
    netmask 255.255.255.0
    gateway 100.64.10.1
```

| Хост | address | gateway |
|---|---|---|
| SUB-1 | 100.64.10.20 | 100.64.10.1 |
| SUB-2 | 100.64.10.21 | 100.64.10.1 |
| EXT-SRV | 203.0.113.10 | 203.0.113.1 |
| ATTACKER | 198.51.100.66 | 198.51.100.1 |
| ISP-SRV | 10.0.0.53 | 10.0.0.1 |

### 2.5. Конфигурация маршрутизаторов

Запустить CHR, открыть консоль (логин `admin`, пароль пустой → задать новый), вставить
содержимое соответствующего файла построчно:

- R-BORDER — `stand/mikrotik/r-border.rsc`
- R-CORE — `stand/mikrotik/r-core.rsc`
- R-BNG — `stand/mikrotik/r-bng.rsc`

Проверки:

```
/routing ospf neighbor print      # на R-CORE должно быть 2 соседа в состоянии Full
/ip route print                   # маршруты 100.64.10.0/24, 203.0.113.0/24, 198.51.100.0/24
/ping 10.0.0.100 count=3          # с R-BORDER и R-BNG до коллектора (Windows)
/system clock print               # время UTC должно совпадать со временем Windows (±5 с)
```

Если часы расходятся больше чем на 5 с: `/system clock set time=HH:MM:SS date=YYYY-MM-DD`
(UTC) на каждом CHR **или** в `.env` указать `CLOCK=flows` (детектор будет ориентироваться на
время самих потоков).

Ограничение бесплатной лицензии CHR — 1 Мбит/с на интерфейс. Для экспорта потоков достаточно;
флуд будет ограничен ~2000 пакетов/с, этого хватает для обнаружения. При желании можно
активировать 60-дневную пробную лицензию (нужен аккаунт mikrotik.com и временный выход CHR в
Интернет), но **хост атакующего при этом к Интернету не подключать**.

### 2.6. Службы на хостах

В консоли каждого контейнера:

```bash
./start_services.sh sub     # на SUB-1 и SUB-2 (sshd — цель подбора пароля)
./start_services.sh ext     # на EXT-SRV (HTTP и iperf3)
./start_services.sh isp     # на ISP-SRV (DNS)
ping -c 3 203.0.113.10      # с SUB-1: связность через все маршрутизаторы
dig +short @10.0.0.53 host1.example.lab   # с SUB-1: ответ 203.0.113.10
```

### 2.7. Проверка, что потоки доходят до БД (ФТ-1)

На Windows в папке репозитория:

```powershell
docker compose up -d --build
docker compose logs -f loader
```

Через 10–30 с после пинга с SUB-1 в логах появятся строки `nfcapd.2026...: N flows`. Проверка в БД:

```powershell
docker compose exec db psql -U nids -c "select count(*), min(ts), max(ts) from flows;"
```

Если строк нет:
- `docker compose exec collector ls -R /data/nfcapd` — нет файлов → пакеты NetFlow не доходят:
  проверить брандмауэр (п. 1.3), `/ip traffic-flow print` на CHR, `/ping 10.0.0.100`;
- файлы есть, но `loader` пишет ошибки → выполнить
  `docker compose exec collector sh -c "nfdump -R /data/nfcapd -o csv | head -5"` и прислать вывод
  (формат CSV зависит от версии nfdump).

Сделайте **скриншот топологии GNS3** — он нужен в диплом.

---

## Этап 3. Запись трафика (Батыйхан + Мирас)

Все компоненты запущены (`docker compose up -d`). Записывайте время начала и конца каждого
интервала **в UTC** (`date -u` в консоли любого хоста).

### 3.1. Нормальный трафик — 1 ч (ТЗ, неделя 2)

На SUB-1 и SUB-2 одновременно:

```bash
DUR=3600 ./background.sh
```

Записать: `NORMAL_START`, `NORMAL_END`.

### 3.2. Обучающие атаки — ~40 мин

На SUB-1 и SUB-2 снова запустить фон (`DUR=3000 ./background.sh`), на ATTACKER:

```bash
DUR=120 PAUSE=180 JOURNAL=train_full.csv ./run_attacks.sh
MODE=low DUR=120 PAUSE=180 JOURNAL=train_low.csv ./run_attacks.sh
```

Записать: `TRAIN_START` (до первой атаки), `TRAIN_END` (после последней).
В конце скрипт печатает журнал — **скопировать текст** в файлы `stand/journals/train_full.csv`
и `stand/journals/train_low.csv` в репозитории на Windows.

### 3.3. Переобучение моделей (Диас)

```powershell
.venv\Scripts\activate
python scripts/train_stand.py --normal "NORMAL_START" "NORMAL_END" --attacks "TRAIN_START" "TRAIN_END" --journal stand/journals/train_full.csv stand/journals/train_low.csv
docker compose restart detector
```

(подставить время UTC в формате `2026-11-02 10:00:00`). Скрипт печатает число окон по классам и
сохраняет `models/window_models_stand.joblib` и `results/stand_train.json`. Если пишет «ни одно окно
не размечено» — проверьте, что в журнале адрес атакующего 198.51.100.66 и время в UTC.

### 3.4. Тестовый час (НФТ-2) — детектор работает онлайн

На SUB-1 и SUB-2: `DUR=3600 ./background.sh`; на ATTACKER (через ~3 мин после старта фона):

```bash
JOURNAL=test.csv ./run_attacks.sh
```

(4 атаки по 3 мин с паузами 9 мин ≈ 48 мин). Во время атак в Telegram должны приходить оповещения.
Записать `TEST_START`, `TEST_END`, скопировать журнал в `stand/journals/test.csv`.

### 3.5. Час чистого фона (ложные срабатывания)

На SUB-1 и SUB-2: `DUR=3600 ./background.sh`, атак нет. Записать `BG_START`, `BG_END`.
Создать пустой журнал `stand/journals/empty.csv` с одной строкой заголовка:
`kind,start,end,attacker,target`.

---

## Этап 4. Оценка (Диас)

```powershell
python scripts/eval_stand.py --period "TEST_START" "TEST_END" --journal stand/journals/test.csv
copy results\stand_eval.json results\stand_eval_test.json
python scripts/eval_stand.py --period "BG_START" "BG_END" --journal stand/journals/empty.csv
copy results\stand_eval.json results\stand_eval_background.json
```

Скрипт печатает по каждому сценарию: обнаружено/нет, задержку, тип, детекторы, и итог по
критериям НФТ-2 (≥ 3 из 4, ≤ 60 с, ≤ 2 ложных/ч). Если во время тестового часа детектор работал
со старыми моделями, добавьте `--offline` — записанные потоки будут повторно прогнаны через конвейер.

---

## Этап 5. Что прислать для обновления диплома

1. `results/stand_train.json`, `results/stand_eval_test.json`, `results/stand_eval_background.json`;
2. журналы `stand/journals/*.csv`;
3. скриншоты: топология GNS3, оповещение Telegram, дашборд Grafana;
4. вывод `docker compose exec db psql -U nids -c "select count(*) from flows;"`.

После этого в разделе 3 результаты имитационной модели дополняются результатами стенда, в
таблице выполнения требований статусы НФТ-2 и НФТ-4 меняются на «выполнено».

## Демонстрация на 10 минут (неделя 4)

1. Показать топологию GNS3 и дашборд Grafana (идёт фон с SUB-1/SUB-2).
2. На ATTACKER: `timeout 60 hping3 -S -p 80 --flood 100.64.10.20`.
3. Через ~30 с — оповещение «SYN-флуд» в Telegram (показать на телефоне) и новая строка в таблице
   инцидентов Grafana.
4. Повторить со сканированием: `nmap -sS -T4 -p 1-5000 -Pn 100.64.10.20`.
5. Запасной вариант без стенда: `REPLAY=1 docker compose up` (п. 1.2).

## Частые проблемы

| Симптом | Причина и решение |
|---|---|
| `docker compose up` падает на `collector` | порт 2055 занят — закрыть другие коллекторы; `netstat -ano | findstr 2055` |
| В Telegram ничего не приходит | в логах detector `telegram=False` → проверить `.env`, перезапустить `docker compose up -d` |
| Инциденты есть, но с опозданием в минуты или без них | часы CHR не совпадают с Windows → п. 2.5 или `CLOCK=flows` в `.env` |
| hping3: `Operation not permitted` | в шаблоне Docker GNS3 запускать контейнер от root (по умолчанию так и есть) |
| Много ложных срабатываний после переобучения | нормальный трафик записан слишком коротким или отличался от тестового — записать норму заново и повторить п. 3.3 |
