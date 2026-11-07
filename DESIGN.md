# rosman — RouterOS Manager для небольшой организации

> Рабочее название `rosman` (RouterOS manager) — поменяем на вкус.
> Цель: один из лучших «managers» для парка MikroTik, собранный из лучших практик
> существующих продуктов, но лёгкий — работает на ноутбуке Atom (2 ядра / 2 ГБ RAM).

Стек (решено ранее): **Go, один статический бинарник, SQLite, без Redis/InfluxDB/nginx**,
веб-интерфейс и статика встроены в бинарник (`embed`), TLS внутри сервиса.
Бюджет памяти: цель **< 150 МБ RSS**, уверенный опрос десятков устройств.

---

## 1. Что берём у конкурентов (и что именно «выпиливаем»)

| Продукт | Что делает | Лучшая практика / фича, которую забираем |
|---|---|---|
| **RouterOS (WinBox/WebFig/CLI)** | Родное управление | **Safe-mode** (авто-откат при потере связи), `/export`, бинарный `/system backup`, CAPsMAN, RoMON |
| **The Dude** (MikroTik NMS) | Карта сети, SNMP-мониторинг | **Автодискавери + визуальная топология**, подсветка загрузки линков на карте, probes, нотификации |
| **MikroTik Manager (2GT)** | То, что у нас стоит | **CA/PKI-автоматизация** (api-ssl, выпуск сертификатов), снапшоты конфига, **TOFU-пиннинг host key**, fleet-деплой SSH-ключей, **CVE-проверки прошивок**, audit log, change-guard |
| **Unimus** | Бэкап/изменение конфигов, мультивендор | **Версионирование конфигов + diff**, расписание, **mass config push с шаблонами**, алерты на изменение конфига, NetFlow |
| **Oxidized / RANCID** | Бэкап конфигов в git | **Git-подобная история конфигов** с diff по коммитам |
| **LibreNMS / Zabbix / Observium** | SNMP-мониторинг, алерты, графики | Готовые **пороги/шаблоны алертов**, downsampling метрик, дашборды, автодискавери по SNMP |
| **NetBox** | IPAM/DCIM «источник правды» | Инвентарь, роли устройств, **IPAM** (позже) |
| **UISP (Ubiquiti)** | ISP-управление | **UX-идеи**: карта, статусы клиентов, лента инцидентов/outages, «одно окно» |
| **Oxidized+Gitea / Netbrain** | — | Offsite-копия бэкапов, подпись/целостность |

**Сквозные «лучшие практики», которые делаем ядром продукта:**

1. **Безопасные изменения.** Любой push/скрипт идёт через change-guard: перед применением
   ставится отложенный авто-откат (RouterOS scheduler / safe-mode), и если после применения
   устройство не подтвердило связь — конфиг откатывается сам. Это главное, чего боятся
   при массовых правках.
2. **Версионированные бэкапы.** И текстовый `/export` (для diff), и бинарный `.backup`
   (для полного восстановления). Хранить по content-hash, показывать diff между версиями,
   алерт на изменение конфига, offsite-копия.
3. **Доступ только по ключу + шифрование секретов.** API-SSL, SSH-ключи, пароли/ключи
   в БД зашифрованы (AES-256-GCM), host key пиннится (TOFU), есть audit log и RBAC.
4. **Мониторинг без тяжёлой TSDB.** Нужные метрики (CPU/RAM/disk/uptime, трафик интерфейсов,
   температура/вольтаж, клиенты Wi-Fi/DHCP) в SQLite с прореживанием (raw коротко →
   часовые/суточные агрегаты). Алерты: устройство down, высокий CPU, истекает сертификат,
   есть CVE для прошивки, скачок трафика.
5. **Карта сети.** Автодискавери по MNDP/LLDP/CDP + ручные связи, загрузка линков оверлеем.
6. **Прошивки.** Отслеживание актуальной версии и канала, маппинг на CVE, **поэтапный
   апгрейд с «канарейкой» и авто-откатом**.
7. **Одно окно.** Веб-терминал/WebFig-прокси к устройству, доступ к «недостижимым» через RoMON.

---

## 2. Набор фич по фазам

### P0 — MVP (то, ради чего продукт существует)
- Инвентарь: модель, серийник, версия RouterOS, уровень лицензии, uptime, сайт/группа.
- Добавление устройства: API-SSL (8729) с TOFU-пиннингом host key; авто-определение identity.
- **Бэкап конфига**: `/export` (текст) + бинарный `/system backup`; по расписанию, по кнопке,
  **по изменению**; версии + diff; offsite-копия (локальная папка/litestream).
- Базовый health-опрос: CPU/RAM/disk/uptime/интерфейсы; хранение с агрегацией.
- Алерты: down, истечение сертификата (минимальный набор каналов: Telegram + webhook).
- Веб-UI (server-rendered, лёгкий), локальная авторизация + RBAC, шифрование секретов.
- Поставка: один бинарник + `systemd`-юнит, первый запуск — self-signed TLS.

### P1
- SSH-ключи: управление + **CA/api-ssl автоматизация** (переиспользуем ваш внутренний
  корневой/подчинённый CA).
- Прошивки: версия/канал, CVE-маппинг, поэтапный апгрейд с канарейкой и авто-откатом.
- Change-guard + шаблоны конфигов + bulk push.
- Алерты: e-mail + дедуп + окна обслуживания (maintenance windows), audit log.

### P2
- Топология (MNDP/LLDP) + карта с загрузкой линков.
- Графики трафика (rollup в SQLite), CAPsMAN/Wi-Fi-клиенты, DHCP-лизы.
- Веб-терминал/WebFig-прокси, RoMON для недостижимых.
- Мульти-сайт/мульти-тенант, расширенный RBAC.
- IPAM-лайт (как в NetBox, но минимально).

**Явные non-goals:** не заменяем Zabbix как универсальный NMS, не делаем мультивендор
(фокус — MikroTik), не целимся в тысячи устройств. Цель — «идеальный manager для своего парка».

---

## 3. Архитектура на Go

```
┌──────────────────────────────────────────────────────────┐
│ rosman (один бинарник)                                     │
│                                                            │
│  HTTP/TLS (net/http) ── UI (templ+htmx, embed) ── REST/API │
│        │                                                   │
│  Auth/RBAC ─ Audit log                                     │
│        │                                                   │
│  ┌─ Scheduler (внутр. cron, горутина) ───────────────┐     │
│  │   worker pool + семафор (лимит параллелизма)       │     │
│  │   ├─ poller (health/metrics)                       │     │
│  │   ├─ backup (export + binary + diff)               │     │
│  │   ├─ firmware/CVE                                   │     │
│  │   └─ alert engine (дедуп, maintenance windows)      │    │
│  └────────────────────────────────────────────────────┘    │
│        │                                                    │
│  Device access layer                                        │
│   ├─ RouterOS API  (go-routeros, 8728/8729, TLS)            │
│   ├─ SSH/SFTP      (x/crypto/ssh: /export, .backup)         │
│   └─ SNMP          (gosnmp, опц.)                            │
│        │                                                    │
│  Storage: SQLite (modernc, pure-Go, WAL)                    │
│   ├─ inventory, configs(versioned), metrics(rollup)         │
│   ├─ secrets (AES-256-GCM), ssh/host-key pins               │
│   └─ users/rbac, audit, alerts                              │
│  Secrets key: файл 0600 (или OS keyring)                    │
└──────────────────────────────────────────────────────────┘
        └─ offsite backup: litestream → S3/папка (опц.)
```

### Ключевые технические решения
- **UI:** `templ` + **htmx** (server-rendered). Минимум JS в браузере — важно, т.к. UI
  открывают в т.ч. со слабых машин, и это резко упрощает сборку/встраивание. SPA можно
  добавить позже, но для MVP htmx достаточно и легче.
- **SQLite:** `modernc.org/sqlite` (чистый Go, без cgo → простая кросс-компиляция), режим
  **WAL**, один writer-пул + много readers. Для десятков устройств с запасом.
- **Метрики без TSDB:** таблица сырых точек с коротким TTL (напр. 24–48 ч) + джоб прореживания
  в часовые/суточные агрегаты. Так графики живут, а БД не пухнет.
- **Конфиги:** хранить `/export` как текст с `sha256`; новая версия только при изменении
  хэша; diff — по строкам. Опционально зеркалить в git-репозиторий.
- **Доступ:** основной путь — **API-SSL** (быстро, безопасно, не ломает SSH-ключи).
  SSH/SFTP — только там, где нужен файл (бинарный backup, `/export` на старых ROS).
  Выбор аутентификации: **ключ, если он проверен; иначе пароль** (как в нашем анализе sshExec).
- **Безопасность:** host key TOFU-пиннинг, секреты AES-256-GCM, ротация ключа шифрования,
  RBAC (admin/operator/viewer), токены API, полный audit log изменений.
- **Change-guard:** перед применением ставим на устройстве отложенный откат
  (`/system scheduler` с восстановлением из свежего backup или safe-mode), применяем,
  подтверждаем связь свежим логином — только тогда отменяем откат.

### Бюджет ресурсов (ориентир на Atom 2c/2GB)
- Бинарник idle: ~30–60 МБ RSS.
- Пул опроса: ограничить, напр., 8–16 одновременными сессиями (семафор), context-таймауты.
- SQLite WAL + агрегация метрик → БД в единицы-десятки МБ на небольшой парк.
- Итог: сервис целиком в ~100–150 МБ, остальное — ОС. Без Redis/Influx/Postgres/Node.

### Библиотеки (Go)
- `go-routeros/routeros` — бинарный API RouterOS (8728/8729, TLS).
- `golang.org/x/crypto/ssh` + `pkg/sftp` — SSH-команды и файлы.
- `gosnmp/gosnmp` — SNMP (опционально, для метрик/дискавери).
- `modernc.org/sqlite` — БД; `a-h/templ` + htmx — UI; `robfig/cron` или свой тикер — расписание.
- `benbjohnson/litestream` — offsite-реплика БД (опц.).

---

## 4. Эскиз модели данных (SQLite)

- `devices` (id, name, ip, site_id, model, serial, ros_version, license, api_port, api_tls,
  api_user, api_pw_enc, ssh_user, ssh_pw_enc, host_key_pin, last_seen)
- `device_ssh_keys` (device_id, key_type, public_key, private_key_enc, fingerprint, status)
- `configs` (id, device_id, taken_at, kind[export|binary], sha256, size, blob/path)
- `config_versions` view/diff по sha256
- `metrics_raw` (device_id, ts, cpu, mem, disk, …) + `metrics_hourly`/`metrics_daily`
- `iface_traffic` (device_id, iface, ts, rx, tx) + агрегаты
- `firmware` (device_id, current, channel, latest_known) ; `cve` (version_range, id, severity)
- `alerts` (rule, device_id, state, since, acked) ; `alert_rules` ; `maintenance_windows`
- `users`, `roles`, `api_tokens`, `audit_log`, `sites`

---

## 5. Дорожная карта реализации

1. **Каркас:** репозиторий, конфиг, SQLite-миграции, HTTP+TLS, auth/RBAC, audit, шифрование секретов.
2. **Устройства:** добавление (API-SSL + TOFU-пин), инвентарь, health-опрос, базовый дашборд.
3. **Бэкапы:** export+binary, расписание, версии+diff, offsite — это **ядро ценности**, делаем рано.
4. **Алерты:** движок + Telegram/webhook, окна обслуживания.
5. **PKI/ключи:** api-ssl автоматизация на вашем внутреннем CA, управление SSH-ключами.
6. **Прошивки + CVE + канареечный апгрейд с откатом.**
7. **Change-guard + шаблоны + bulk push.**
8. **Топология, графики трафика, веб-терминал, мульти-сайт.**

---

## 6. Чем будем лучше того, что стоит сейчас (2GT MikroTik Manager)
- Не 5 контейнеров (Node+Postgres+Redis+Influx+nginx), а **один бинарник + SQLite** — реально живёт на 2 ГБ.
- Те же сильные идеи (CA/PKI, TOFU, бэкапы, CVE, fleet-ключи), но без веса стека.
- Акцент на **change-guard** и **версионировании конфигов с diff** — то, чего в лёгком виде не хватает.

---

## 7. Идеи из существующего инструмента (48 устройств) и UI-решения

Из вашей текущей панели берём в бэклог как отдельные модули/вкладки:
- **Syslog** — приём и хранение syslog с устройств, поиск/фильтр.
- **Traffic / NetFlow** — сбор потоков, топ-talkers, графики по интерфейсам.
- **GeoTrack / GeoWIFI** — координаты (Lat/Lng) и карта устройств/точек.
- **QoS** — просмотр/настройка очередей.
- **HotSpot** — управление хотспотом и ваучерами.
- **Customer** — привязка клиентов (мини-биллинг/ISP).
- **Configurator** — массовые правки конфигов по шаблонам (ядро change-guard).
- **2FA** — двухфакторная аутентификация в саму панель.
- Поля карточки устройства: **Comment**, **Groups**, **Add time**, время последнего
  **успешного/неуспешного** подключения (у нас это покроют last_seen + алерт down + история).

### UI / брендинг
- Имя в интерфейсе: **ROSMan** (Router Operation System Manager).
- Стиль — близко к MikroTik (светлая гамма по умолчанию), тема **светлая/тёмная/системная**
  (переключатель в левом нижнем углу), там же **выбор языка** и **версия продукта**.
- Иконки — из набора под MIT (Tabler/Lucide), похожего на WinBox; **не** встраивать
  проприетарную графику/логотип/favicon MikroTik в распространяемый продукт (риск trademark).
- i18n: RU/EN (переключатель готов; подключение строк — ближайшая задача).

---

## 8. Паритет с MikroTik Manager — чек-лист (цель: всё то же, но на лёгком Go-стеке)

Легенда: ✅ есть в ROSMan · 🟡 частично · ⬜ впереди.

**Готово (v0.1–v0.9)**
- ✅ Инвентарь, добавление по API-SSL с TOFU-пином, health-опрос
- ✅ Бэкапы: export + полный (с паролем) + оба в zip; доставка в папку/Telegram/почту; версии + скачивание
- ✅ Алерты: down, cert-expiry, firmware-outdated; каналы webhook/Telegram/email
- ✅ Аудит-лог, RBAC (admin/operator/viewer), секреты AES-256-GCM, self-signed TLS
- ✅ Мониторинг прошивок (версия/канал/статус)
- ✅ PKI/api-ssl: ROSMan как CA (генерация/импорт), выпуск+раскатка серверных сертификатов
- ✅ Change-guard: шаблоны + применение с авто-откатом (одно/массово)
- ✅ Топология (MNDP/LLDP), графики трафика по интерфейсам
- ✅ Локации (сайты) + теги, фильтры; i18n RU/EN; темы светлая/тёмная/системная; стиль WAFISP

**Впереди — крупные блоки MTM**
- ⬜ Прошивки: выполнение обновления волнами (канарейка, pre-backup, reboot, health-check, halt-on-failure)
- ⬜ CAPsMAN: панель контроллера, радио, провижининг (read-only для начала)
- ⬜ Свитч-панель (faceplate), VLAN CRUD по портам, оптика, PoE power-cycle
- ⬜ Беспроводка: SSID CRUD, RF-health, сканы, rogue/evil-twin AP, гостевой Wi-Fi + ваучеры
- ⬜ Firewall-билдер (правила/NAT-визарды/address-lists/счётчики), Security Center, lockout-prediction
- ⬜ Сетевые сервисы: DHCP (сервера/пулы/лизы), DNS, NTP, WireGuard, Logging/syslog, SNMP/discovery
- ⬜ NetFlow-коллектор (v9/IPFIX, UDP 2055), top talkers, app-breakdown
- ⬜ Клиенты: трекинг, fingerprint по OUI, детальная карточка
- ⬜ CVE-сканер (NVD + CISA KEV + release-notes), security-posture
- ⬜ User-Manager (RADIUS, read-only), LTE/cellular (сигнал, CA-бэнды, SMS data-cap)
- ⬜ Config: side-by-side diff + rollback; config-health (L2-мисконфиги)
- ⬜ Доступ: 2FA (TOTP), OIDC/SSO, scoped API-токены, HMAC-вебхуки, плановые email-отчёты
- ⬜ Операции: adoption factory-default устройств, bulk-команды волнами, CSV-импорт, job-очередь
- ⬜ Дашборд (счётчики, доступность 30 дней, аномалии), maintenance windows, RoMON, per-device tools (ping/traceroute/pcap/WoL)

Принцип: один Go-бинарник + SQLite, без Redis/Influx/Postgres/nginx — та же функциональность кратно легче.
