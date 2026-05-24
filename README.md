# netscope-scan

> **RU** | [EN](#english)

---

## Русский

Быстрый портовый сканер на Rust с JSON-выводом. Форк RustScan — без nmap и скриптинга. Принимает цели (IP, CIDR, хосты), сканирует TCP/UDP-порты параллельными сокетами и печатает результат как JSON-массив в stdout.

Используется как бэкенд для [`netscope-py`](../netscope-py) — Python-обёртки над этим бинарником.

### Сборка

```bash
cargo build --release
# бинарник: target/release/netscope-scan
```

### Быстрый старт

```bash
# Конкретные порты
netscope-scan -a 192.168.1.0/24 -p 22,80,443

# Диапазон портов
netscope-scan -a 10.0.0.1 -r 1-1000

# Топ-1000 популярных портов
netscope-scan -a 10.0.0.0/24 --top

# UDP
netscope-scan -a 10.0.0.1 -p 53,161,500 --udp
```

### Вывод

JSON-массив в stdout. Только хосты с открытыми портами:

```json
[
  {"ip": "192.168.1.5", "ports": [22, 80]},
  {"ip": "192.168.1.10", "ports": [443]}
]
```

### Флаги

| Флаг | Короткий | По умолчанию | Описание |
|------|----------|-------------|---------|
| `--addresses` | `-a` | — | Цели: IP, CIDR или хосты, через запятую. Обязательный. |
| `--ports` | `-p` | — | Конкретные порты через запятую: `22,80,443`. |
| `--range` | `-r` | — | Диапазон: `1-1000`. Несовместим с `-p`. |
| `--top` | | | Топ-1000 популярных портов. |
| `--batch-size` | `-b` | `4500` | Число одновременных сокетов. |
| `--timeout` | `-t` | `1500` | Таймаут на порт, мс. |
| `--tries` | | `1` | Попыток на порт. |
| `--ulimit` | `-u` | | Установить лимит файловых дескрипторов (Unix). |
| `--scan-order` | | `serial` | `serial` или `random`. |
| `--exclude-ports` | `-e` | | Исключить порты через запятую. |
| `--exclude-addresses` | `-x` | | Исключить адреса/CIDR через запятую. |
| `--udp` | | | UDP-режим. |
| `--resolver` | | | Кастомные DNS-резолверы через запятую. |
| `--no-config` | `-n` | | Игнорировать конфиг-файл. |
| `--config-path` | `-c` | | Путь к конфиг-файлу. |

> **Приоритет портов:** `-p` > `-r` > `--top`. Использует первый заданный вариант.

### Конфигурационный файл

Опции можно зафиксировать в TOML-файле. Путь по умолчанию: `~/.config/.netscope-scan.toml` (или `~/.netscope-scan.toml` как запасной). Флаги командной строки перекрывают значения из файла.

```toml
batch_size = 8000
timeout = 800
scan_order = "Random"
exclude_ports = [135, 139, 445]
```

---

## English

<a name="english"></a>

Fast Rust port scanner with JSON output. A RustScan fork — nmap and scripting removed. Accepts targets (IPs, CIDRs, hostnames), scans TCP/UDP ports with parallel sockets, and prints results as a JSON array to stdout.

Used as the backend for [`netscope-py`](../netscope-py) — the Python wrapper around this binary.

### Build

```bash
cargo build --release
# binary: target/release/netscope-scan
```

### Quick start

```bash
# Explicit ports
netscope-scan -a 192.168.1.0/24 -p 22,80,443

# Port range
netscope-scan -a 10.0.0.1 -r 1-1000

# Top-1000 common ports
netscope-scan -a 10.0.0.0/24 --top

# UDP
netscope-scan -a 10.0.0.1 -p 53,161,500 --udp
```

### Output

JSON array to stdout. Only hosts with at least one open port are included:

```json
[
  {"ip": "192.168.1.5", "ports": [22, 80]},
  {"ip": "192.168.1.10", "ports": [443]}
]
```

### Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--addresses` | `-a` | — | Targets: IPs, CIDRs, or hostnames, comma-separated. Required. |
| `--ports` | `-p` | — | Explicit ports, comma-separated: `22,80,443`. |
| `--range` | `-r` | — | Port range: `1-1000`. Conflicts with `-p`. |
| `--top` | | | Scan top-1000 common ports. |
| `--batch-size` | `-b` | `4500` | Concurrent socket count. |
| `--timeout` | `-t` | `1500` | Per-port timeout in ms. |
| `--tries` | | `1` | Probe attempts per port. |
| `--ulimit` | `-u` | | Set the file-descriptor limit (Unix). |
| `--scan-order` | | `serial` | `serial` or `random`. |
| `--exclude-ports` | `-e` | | Ports to skip, comma-separated. |
| `--exclude-addresses` | `-x` | | Addresses/CIDRs to exclude, comma-separated. |
| `--udp` | | | UDP scanning mode. |
| `--resolver` | | | Custom DNS resolvers, comma-separated. |
| `--no-config` | `-n` | | Ignore the config file. |
| `--config-path` | `-c` | | Path to a custom config file. |

> **Port selection priority:** `-p` > `-r` > `--top`. First provided option wins.

### Config file

Defaults can be set in a TOML file. Lookup order: `~/.config/.netscope-scan.toml`, then `~/.netscope-scan.toml`. CLI flags override config values.

```toml
batch_size = 8000
timeout = 800
scan_order = "Random"
exclude_ports = [135, 139, 445]
```
