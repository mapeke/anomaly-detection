# NetFlow-IDS — обнаружение сетевых аномалий и атак в инфраструктуре интернет-провайдера

Прототип дипломного проекта (МУИТ). Система собирает записи потоков NetFlow v9/IPFIX с маршрутизаторов
модели сети провайдера, агрегирует их в окна по 10 с, применяет три детектора — пороговые правила,
Isolation Forest (без учителя) и XGBoost (классификатор типа атаки) — и отправляет оповещения
в Telegram; трафик и журнал инцидентов отображаются в Grafana.

Команда: Мухитұлы Батыйхан (сеть и стенд), Таубаев Диас (модели), Таубаев Мирас (конвейер и интерфейс).

```
 GNS3-стенд (MikroTik CHR) --NetFlow v9/IPFIX UDP 2055--> nfcapd --> loader --> PostgreSQL (flows)
                                                                                   |
               Telegram <-- detector: окна 10 с -> признаки -> правила | IForest | XGBoost
               Grafana  <-------------------------- PostgreSQL (windows, incidents)
```

## Структура

| Путь | Содержимое |
|---|---|
| `src/nids/features.py` | единая схема потока, оконная агрегация и признаки (ФТ-2) |
| `src/nids/detectors.py` | пороговые правила, Isolation Forest, XGBoost/Random Forest (ФТ-3) |
| `src/nids/engine.py` | онлайн-ядро: окна → детекторы → инциденты |
| `src/nids/pipeline.py` | сервис: PostgreSQL → ядро → инциденты, Telegram (ФТ-4) |
| `src/nids/loader.py` | загрузчик nfcapd/nfdump → PostgreSQL (ФТ-1), режим воспроизведения |
| `src/nids/simulator.py` | имитационная модель потоков стенда (фон + 4 сценария атак) |
| `scripts/download_data.py` | загрузка датасета NF-UNSW-NB15-v3 |
| `scripts/train_eval.py` | EDA, разбиение без утечки, обучение и оценка на датасете |
| `scripts/eval_scenarios.py` | оценка онлайн-конвейера: задержка, ложные срабатывания, производительность |
| `scripts/eval_latency.py` | распределение задержки при случайном начале атаки |
| `scripts/extra_experiments.py` | чувствительность к параметрам, абляция и важность оконных признаков |
| `scripts/make_diagrams.py` | схемы архитектуры, стенда, БД для пояснительной записки |
| `stand/` | топология, план адресации, конфигурации MikroTik, образ хостов GNS3, сценарии фона и атак |
| `scripts/train_stand.py`, `scripts/eval_stand.py` | переобучение на трафике стенда и оценка НФТ-2 по журналу атак |
| `docs/GUIDE_STAND.md` | пошаговая инструкция: стенд, запуск, запись трафика, оценка |
| `db/schema.sql`, `grafana/` | схема БД и дашборд (ФТ-5) |
| `results/` | метрики (`metrics.json`, `scenarios.json`) и рисунки |
| `notebooks/eda.ipynb` | разведочный анализ датасета |

## Воспроизведение экспериментов

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/download_data.py                   # ~105 МБ в data/raw/
python scripts/train_eval.py                      # ~5 мин, results/metrics.json
python scripts/eval_scenarios.py                  # ~5 мин, results/scenarios.json
python scripts/eval_latency.py                    # ~1 мин, results/latency.json
python scripts/extra_experiments.py               # ~3 мин, results/extra.json
```

## Основные результаты

| Эксперимент | Результат |
|---|---|
| Потоки, «норма/атака», XGBoost без IP и TTL (тест) | F1 = 0,9994 |
| Потоки, 10 классов, XGBoost | macro-F1 = 0,618 |
| Окна 10 с: правила / Isolation Forest / XGBoost (тест) | F1 = 0,011 / 0,899 / 0,991 |
| Имитационная модель стенда: 4 сценария, все детекторы | 4 из 4, задержка ≤ 30 с, 0 ложных за 1 ч |
| Пропускная способность онлайн-ядра | 22–48 тыс. записей потоков/с (i5-11300H) |

Подробности — `results/*.json`. Метрики на уровне отдельных потоков завышены артефактами набора
(минимальная длина пакета, TTL); см. раздел 3 пояснительной записки.

Фиксированный `random_state = 42` (модели) и фиксированные seed имитационной модели. Метрики считаются
только на отложенной тестовой части (временные блоки по 5 мин, не участвовавшие в обучении и подборе порогов).

## Запуск прототипа

```bash
cp .env.example .env            # при необходимости указать TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID
docker compose up --build       # db, collector (UDP 2055), loader, detector, grafana (http://localhost:3000)
```

Маршрутизаторы стенда экспортируют NetFlow v9 на `<хост>:2055` (см. `stand/README.md`).
Без стенда можно воспроизвести имитационный прогон с атаками: `REPLAY=1 docker compose up --build`.

## Этика

Атаки (hping3, nmap, hydra) запускаются только внутри изолированного стенда GNS3. Чужие сети не проверяются.
Датасет NF-UNSW-NB15-v3 (University of Queensland, doi:10.48610/6E0EDA1) в репозиторий не включён.
