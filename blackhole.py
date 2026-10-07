#!/usr/bin/env python3
"""
Blackhole: учебный метод обнаружения DDoS-атак по журналу запросов.
Проект Aegis, IT 19-26 Corporation.

Запуск:
    python blackhole.py aegis-sample-log.csv
    python blackhole.py my-log.csv --out blocklist.txt

Нужен только Python 3.8+, дополнительные библиотеки не требуются.
Файл: CSV со столбцами времени (time, date, timestamp) и адреса (ip, src, client).
Метод учебный: пользуйтесь им только на своих данных и системах.
"""
import argparse
import math
import re
from datetime import datetime

# Параметры метода (те же, что на странице Aegis Monitor)
SPIKE_FACTOR = 2.5     # трафик выше нормы в 2,5 раза считается всплеском
MIN_HOT_TICKS = 2      # всплеск должен держаться хотя бы 2 отрезка подряд
CALM_TICKS = 3         # атака считается законченной после 3 спокойных отрезков
HEAVY_RATE = 50        # один адрес, шлющий больше 50 запросов в секунду, считается нарушителем
TARGET_BUCKETS = 150   # на сколько отрезков делим весь журнал


def to_time(value):
    """Превращает значение времени в секунды (число). Понимает дату и unix-время."""
    v = value.strip().strip('"')
    if re.fullmatch(r"\d+(\.\d+)?", v):
        n = float(v)
        return n / 1000 if n > 1e11 else n
    return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()


def read_log(path):
    """Шаг 0. Читает CSV и возвращает два списка: время и IP каждого запроса."""
    with open(path, encoding="utf-8-sig") as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    if len(lines) < 20:
        raise SystemExit("В файле слишком мало строк (нужно хотя бы 20).")
    head = lines[0]
    sep = ";" if (";" in head and "," not in head) else "\t" if "\t" in head else ","
    cols = [c.strip().strip('"') for c in head.split(sep)]
    t_col = next((i for i, c in enumerate(cols) if re.search(r"time|date|ts|stamp", c, re.I)), None)
    i_col = next((i for i, c in enumerate(cols) if re.search(r"^(ip|src|source|client|remote)|_ip|ip_", c, re.I)), None)
    if t_col is None:
        raise SystemExit("Не найден столбец времени. Назовите его time или timestamp.")
    if i_col is None or i_col == t_col:
        i_col = 1 if t_col == 0 else 0
    times, ips = [], []
    for ln in lines[1:]:
        parts = ln.split(sep)
        try:
            times.append(to_time(parts[t_col]))
            ips.append(parts[i_col].strip().strip('"'))
        except (ValueError, IndexError):
            continue  # пропускаем битые строки
    return times, ips


def blackhole(times, ips):
    """Главная функция: все шаги метода от подсчёта трафика до списка блокировки."""
    t_min, t_max = min(times), max(times)
    size = max(1, math.ceil((t_max - t_min + 1) / TARGET_BUCKETS))   # длина отрезка, секунд
    n_buckets = int((t_max - t_min) // size) + 1

    # Шаг 1. Считаем запросы в каждом отрезке времени
    counts = [0] * n_buckets
    bucket_of = []
    for t in times:
        b = int((t - t_min) // size)
        bucket_of.append(b)
        counts[b] += 1
    rate = [c / size for c in counts]                  # запросов в секунду

    # Шаг 2. Нормальный уровень: медиана, дальше он медленно подстраивается (EWMA)
    baseline = max(1.0, sorted(rate)[n_buckets // 2])

    # Шаг 3. Ищем всплески: выше нормы в 2,5 раза минимум 2 отрезка подряд
    incidents, current = [], None
    hot = calm = start = 0
    for b in range(n_buckets):
        if rate[b] > SPIKE_FACTOR * baseline:
            if hot == 0:
                start = b
            hot += 1
            calm = 0
            if current:
                current["end"] = b
            elif hot >= MIN_HOT_TICKS:
                current = {"start": start, "end": b}
        else:
            hot = 0
            calm += 1
            baseline = 0.9 * baseline + 0.1 * rate[b]     # норма обновляется только в спокойное время
            if current and calm >= CALM_TICKS:
                incidents.append(current)                 # Шаг 5. Атака закончилась
                current = None
    if current:
        incidents.append(current)

    in_incident = [-1] * n_buckets
    for k, inc in enumerate(incidents):
        for b in range(inc["start"], inc["end"] + 1):
            in_incident[b] = k

    # Шаг 4. Кто виноват: считаем запросы каждого адреса внутри атак
    per_bucket, per_ip, first_seen = {}, {}, {}
    for idx, (ip, b) in enumerate(zip(ips, bucket_of)):
        first_seen.setdefault(ip, b)
        if in_incident[b] >= 0:
            per_bucket[(ip, b)] = per_bucket.get((ip, b), 0) + 1
            per_ip[ip] = per_ip.get(ip, 0) + 1
    heavy = {ip for (ip, b), n in per_bucket.items() if n / size > HEAVY_RATE}

    # Определяем тип каждой атаки: мало адресов или много
    for inc in incidents:
        total = heavy_total = 0
        peak = 0.0
        for b in range(inc["start"], inc["end"] + 1):
            total += counts[b]
            peak = max(peak, rate[b])
        for (ip, b), n in per_bucket.items():
            if inc["start"] <= b <= inc["end"] and ip in heavy:
                heavy_total += n
        inc.update(total=total, peak=peak,
                   kind="few" if total and heavy_total / total > 0.5 else "dist")

    # Решение по каждому адресу: блокировать, проверить или всё в порядке
    first_start = incidents[0]["start"] if incidents else n_buckets
    verdicts = {}
    for ip, n in per_ip.items():
        if ip in heavy:
            verdicts[ip] = "block"
        elif first_seen[ip] >= first_start:
            verdicts[ip] = "check"       # новый адрес, появился во время атаки
        else:
            verdicts[ip] = "ok"          # обычный посетитель, был и до атаки
    return dict(t_min=t_min, size=size, incidents=incidents, per_ip=per_ip, verdicts=verdicts)


def fmt(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def main():
    ap = argparse.ArgumentParser(description="Blackhole: поиск DDoS-атак в журнале запросов")
    ap.add_argument("log", help="CSV-файл со столбцами времени и IP")
    ap.add_argument("--out", help="куда сохранить список IP для блокировки (текстовый файл)")
    args = ap.parse_args()

    times, ips = read_log(args.log)
    r = blackhole(times, ips)
    print(f"Запросов: {len(times)}, уникальных адресов: {len(set(ips))}")
    if not r["incidents"]:
        print("Атак не найдено.")
        return
    print(f"\nНайдено атак: {len(r['incidents'])}")
    for k, inc in enumerate(r["incidents"], 1):
        a = r["t_min"] + inc["start"] * r["size"]
        b = r["t_min"] + (inc["end"] + 1) * r["size"]
        kind = "с небольшого числа адресов" if inc["kind"] == "few" else "распределённая (много адресов)"
        print(f"  {k}. {fmt(a)} - {fmt(b)}, длительность {int(b - a)} с, "
              f"пик {inc['peak']:.0f} запросов/с, тип: {kind}")
    block = sorted((ip for ip, v in r["verdicts"].items() if v == "block"),
                   key=lambda ip: -r["per_ip"][ip])
    check = [ip for ip, v in r["verdicts"].items() if v == "check"]
    print(f"\nБлокировать ({len(block)}):")
    for ip in block:
        print(f"  {ip}  ({r['per_ip'][ip]} запросов за время атак)")
    print(f"\nПроверить дополнительно (новые адреса во время атаки): {len(check)}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write("\n".join(block) + "\n")
        print(f"\nСписок блокировки сохранён в {args.out}")


if __name__ == "__main__":
    main()
