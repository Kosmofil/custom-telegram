#!/usr/bin/env python3

import sys
import json
import requests
import re
import os

# === Bitrix24 Webhook ===
BITRIX_WEBHOOK = "https://{COMPANY_NAME}.bitrix24.ru/rest/{USER_ID}/{BITRIX_WEBHOOK_SECRET}/tasks.task.add"

BITRIX_FLOW_MAP = {
    "100110": "{FLOW_ID_BITRIX}",
    "100112": "{FLOW_ID_BITRIX}",
    "100150": "{FLOW_ID_BITRIX}",
    "60115": "{FLOW_ID_BITRIX}",  # Нужно для прохождения фильтра (задача не создаётся)
}
GROUP_ID = "GROUP_ID_BITRIX"

TASK_TITLE_MAP = {
    "100150": "Kaspersky Security Center",
    "100110": "Windows AD: Изменение группы 'Администраторы домена'",
    "100112": "Windows AD: Изменение группы 'Администраторы предприятия'",
    "60115": "Windows AD: Учётная запись заблокирована (брутфорс)",
}
  RESPONSIBLE_MAP = {
    "100150": "{USER_ID_BITRIX}",
    "100110": "{USER_ID_BITRIX}",
    "100112": "{USER_ID_BITRIX}",
    "60115": 1135,
}

KSC_PRODUCT_NAMES = {
    "1093": "Kaspersky Security Center",
    "1102": "Kaspersky Endpoint Security",
    "1106": "Kaspersky Security for Linux",
    "1112": "Kaspersky Small Office Security",
}

MAIN_CHAT_ID = "-{CHAT_ID_TELEGRAMM}"

def escape_markdown_basic(text):
    if not isinstance(text, str):
        return str(text)
    for char in r'_*[]()~`>#+-=|{}.!':
        text = text.replace(char, '\\' + char)
    return text

def parse_ksc_cef(cef_line):
    fields = {}
    if not cef_line or not isinstance(cef_line, str):
        return fields
    parts = cef_line.split('|', 6)
    if len(parts) < 7:
        return fields
    ext_part = parts[6]
    pairs = re.findall(r'(\w+)=([^=]+?)(?=\s+\w+=|$)', ext_part)
    for key, value in pairs:
        fields[key] = value.strip()
    return fields

def safe_get(d, *keys, default='N/A'):
    for key in keys:
        if isinstance(d, dict) and key in d:
            d = d[key]
        else:
            return default
    return d if d not in (None, '') else default

def build_bitrix_description(alert_json, rule_id, is_windows, data, event_id, host_for_check):
    lines = []

    descriptions = {
        "100110": "🚨 CRITICAL ALERT: Domain Admins group modified!",
        "100112": "🚨 CRITICAL ALERT: Enterprise Admins group modified!",
        "100150": "🚨 Событие Kaspersky Security Center",
        "60115": "🚨 Учётная запись заблокирована из-за множества неудачных попыток входа",
    }
    lines.append(descriptions.get(rule_id, "🚨 Событие безопасности Wazuh"))

    timestamp = alert_json.get('timestamp', 'N/A')
    if timestamp != 'N/A':
        lines.append(f"🕗 Время: {timestamp}")

    alert_level = safe_get(alert_json, 'rule', 'level')
    if alert_level != 'N/A':
        lines.append(f"🚨 Уровень: {alert_level}")

    description = safe_get(alert_json, 'rule', 'description')
    if description != 'N/A':
        lines.append(f"📝 Описание: {description}")

    agent_name = safe_get(alert_json, 'agent', 'name')
    if agent_name != 'N/A':
        lines.append(f"🖥️ Агент: {agent_name}")

    if is_windows:
        target_host = safe_get(data, 'win', 'system', 'computer')
        if target_host != 'N/A':
            lines.append(f"🎯 Целевой хост: {target_host}")

        workstation = safe_get(data, 'win', 'eventdata', 'workstationName')
        if workstation != 'N/A':
            lines.append(f"📍 Источник: {workstation}")

        src_ip = alert_json.get('srcip', 'N/A')
        if src_ip == 'N/A':
            src_ip = safe_get(data, 'win', 'eventdata', 'ipAddress')
        if src_ip != 'N/A':
            lines.append(f"🌐 IP источника: {src_ip}")

        if str(event_id).strip() in ('4728', '4729', '4732', '4733', '4737', '4738', '4746', '4747', '4757'):
            if str(event_id).strip() == "4737":
                lines.append("👤 Состав группы изменён (возможно, удаление участника)")
                subject_user = safe_get(data, 'win', 'eventdata', 'subjectUserName')
                subject_domain = safe_get(data, 'win', 'eventdata', 'subjectDomainName')
                if subject_user != 'N/A':
                    modifier = f"{subject_domain}\\{subject_user}" if subject_domain != 'N/A' else subject_user
                    lines.append(f"✏️ Изменил: {modifier}")
            else:
                member_name = safe_get(data, 'win', 'eventdata', 'memberName')
                affected_user = 'N/A'
                if member_name != 'N/A' and isinstance(member_name, str):
                    if member_name.startswith('CN='):
                        affected_user = member_name[3:].split(',')[0]
                    else:
                        affected_user = member_name
                if affected_user == 'N/A':
                    target_user_fallback = safe_get(data, 'win', 'eventdata', 'targetUserName')
                    if target_user_fallback != 'N/A':
                        affected_user = target_user_fallback
                if affected_user != 'N/A':
                    lines.append(f"👤 Добавлен/удалён: {affected_user}")

                subject_user = safe_get(data, 'win', 'eventdata', 'subjectUserName')
                subject_domain = safe_get(data, 'win', 'eventdata', 'subjectDomainName')
                if subject_user != 'N/A':
                    modifier = f"{subject_domain}\\{subject_user}" if subject_domain != 'N/A' else subject_user
                    lines.append(f"✏️ Изменил: {modifier}")
        else:
            # Обработка остальных событий (включая 4740)
            target_user = safe_get(data, 'win', 'eventdata', 'targetUserName')
            target_domain = safe_get(data, 'win', 'eventdata', 'targetDomainName')
            full_user = None
            if target_user != 'N/A' and target_domain != 'N/A':
                full_user = f"{target_domain}\\{target_user}"
            elif target_user != 'N/A':
                full_user = target_user
            elif target_domain != 'N/A':
                full_user = target_domain
            if full_user:
                lines.append(f"👤 Пользователь: {full_user}")

    if re.search(r'utm', host_for_check, re.IGNORECASE):
        lines.append("⚠️ Примечание: Неверная попытка подключения по VPN")
    if re.search(r'mail1', host_for_check, re.IGNORECASE):
        lines.append("📧 Примечание: Попытка подключения к почтовому серверу с неверными данными")

    full_log = alert_json.get('full_log', '')
    if full_log.strip():
        lines.append("\n--- Полный лог ---")
        lines.append(full_log[:10000])

    return "\n".join(lines)

# === Основной код ===
try:
    alert_json = json.load(sys.stdin)
except Exception:
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        with open(sys.argv[1]) as f:
            alert_json = json.load(f)
    else:
        sys.exit(1)

rule_id = safe_get(alert_json, 'rule', 'id')
if rule_id not in RESPONSIBLE_MAP:
    sys.exit(0)

alert_level = safe_get(alert_json, 'rule', 'level')
description = safe_get(alert_json, 'rule', 'description')
agent_name = safe_get(alert_json, 'agent', 'name')
timestamp = alert_json.get('timestamp', 'N/A')
full_log = alert_json.get('full_log', '')

data = alert_json.get('data', {})
is_windows = isinstance(data, dict) and 'win' in data
event_id = 'N/A'
if is_windows:
    event_id = safe_get(data, 'win', 'system', 'eventID')
    if event_id == 'N/A':
        event_id = safe_get(data, 'win', 'system', 'EventID')

if str(event_id).strip() == "4740":
    description = "Попытка ввода трёх неверных паролей за 2 минуты"

src_ip = alert_json.get('srcip', 'N/A')
if src_ip == 'N/A' and isinstance(data, dict):
    src_ip = safe_get(data, 'win', 'eventdata', 'ipAddress')
    if src_ip == 'N/A':
        src_ip = data.get('srcip', 'N/A')

target_host = 'N/A'
if is_windows:
    target_host = safe_get(data, 'win', 'system', 'computer')
host_for_check = target_host if target_host != 'N/A' else agent_name

is_group_change = False
if is_windows and str(event_id).strip() in ('4728', '4729', '4732', '4733', '4737', '4738', '4746', '4747', '4757'):
    is_group_change = True

# === Формирование Telegram-сообщения ===
lines = []
lines.append("🪟 *Windows Allert*" if is_windows else "🐧 *Non-Windows Allert*")

if timestamp != 'N/A':
    lines.append(f"🕗 *Время:* {timestamp}")
if rule_id != 'N/A':
    lines.append(f"🆔 *Rule ID:* {rule_id}")
if alert_level != 'N/A':
    lines.append(f"🚨 *Уровень:* {alert_level}")
if description != 'N/A':
    lines.append(f"📝 *Description:* {description}")
if agent_name != 'N/A':
    lines.append(f"🖥️ *Agent:* {agent_name}")

if rule_id == "100110":
    lines.insert(1, "🚨 *CRITICAL ALERT: Domain Admins group modified!*")
elif rule_id == "100112":
    lines.insert(1, "🚨 *CRITICAL ALERT: Enterprise Admins group modified!*")
elif rule_id in ("100111", "100112"):
    lines.insert(1, "🚨 *CRITICAL: Изменение членства в группах доступа*")
elif rule_id == "60115":
    lines.insert(1, "🔒 *ALERT: Учётная запись заблокирована!*")

if is_windows:
    if target_host != 'N/A':
        lines.append(f"🎯 *Целевой Хост:* {target_host}")
    workstation = safe_get(data, 'win', 'eventdata', 'workstationName')
    if workstation != 'N/A':
        lines.append(f"📍 *Источник:* {workstation}")
    if src_ip != 'N/A':
        lines.append(f"🌐 *IP Источника:* {src_ip}")

    if is_group_change:
        event_id_str = str(event_id).strip()
        if event_id_str == "4737":
            lines.append("👤 Состав группы изменён (возможно, удаление участника)")
            subject_user = safe_get(data, 'win', 'eventdata', 'subjectUserName')
            subject_domain = safe_get(data, 'win', 'eventdata', 'subjectDomainName')
            if subject_user != 'N/A':
                modifier = f"{subject_domain}\\{subject_user}" if subject_domain != 'N/A' else subject_user
                lines.append(f"✏️ Изменил: {escape_markdown_basic(modifier)}")
        else:
            member_name = safe_get(data, 'win', 'eventdata', 'memberName')
            affected_user = 'N/A'
            if member_name != 'N/A' and isinstance(member_name, str):
                if member_name.startswith('CN='):
                    affected_user = member_name[3:].split(',')[0]
                else:
                    affected_user = member_name
            if affected_user == 'N/A':
                target_user_fallback = safe_get(data, 'win', 'eventdata', 'targetUserName')
                if target_user_fallback != 'N/A':
                    affected_user = target_user_fallback
            if affected_user != 'N/A':
                lines.append(f"👤 Добавлен/удалён: {escape_markdown_basic(affected_user)}")

            subject_user = safe_get(data, 'win', 'eventdata', 'subjectUserName')
            subject_domain = safe_get(data, 'win', 'eventdata', 'subjectDomainName')
            if subject_user != 'N/A':
                modifier = f"{subject_domain}\\{subject_user}" if subject_domain != 'N/A' else subject_user
                lines.append(f"✏️ Изменил: {escape_markdown_basic(modifier)}")
    else:
        # Обработка остальных событий (включая 4740)
        target_user = safe_get(data, 'win', 'eventdata', 'targetUserName')
        target_domain = safe_get(data, 'win', 'eventdata', 'targetDomainName')
        full_user = None
        if target_user != 'N/A' and target_domain != 'N/A':
            full_user = f"{target_domain}\\{target_user}"
        elif target_user != 'N/A':
            full_user = target_user
        elif target_domain != 'N/A':
            full_user = target_domain
        if full_user:
            lines.append(f"👤 Пользователь: {escape_markdown_basic(full_user)}")

telegram_msg = "\n".join(lines)
bitrix_description = build_bitrix_description(alert_json, rule_id, is_windows, data, event_id, host_for_check)

# === Определение чата Telegram ===
if rule_id in ("100110", "100111"):
    telegram_chat_id = "-{CHAT_ID_TELEGRAMM}"
    telegram_thread_id = 5
elif rule_id == "100150":
    log_lower = full_log.lower()
    noise_keywords = [
        "облегченный поиск", "обновление баз", "проверка лицензии", "авто установка",
        "загрузка обновлений", "test_siem_connection", "автоматическая установка",
        "базы обновлены", "устройство давно не подключалось", "установка kaspersky endpoint", "отчет",
        "поиск вредоносного по", "обнаружено новое устройство", "было недоступно",
        "облегченный еженедельный", "добавление компонентов bitlocker",
        "поиск и удаление", "предупреждение", "добавлено", "поиск уязвимостей",
        "аудит (модификация объектов)", "устройство удалено", "операция с устройством запрещена",
        "статус шифрования данных", "автоматически перемещено", "обновление для пк",
        "устройство стало неуправляемым", "базы устарели"
    ]
  #=== Выше фильтрация спама который нам не нужно получать от KSC, можно реализовать через xml правила, но так проще и быстрее
    if any(kw in log_lower for kw in noise_keywords):
        sys.exit(0)

    cef = parse_ksc_cef(full_log)
    host = cef.get('dhost', 'N/A')
    ip = cef.get('dst', 'N/A')
    group = cef.get('cs9', 'N/A')
    product = KSC_PRODUCT_NAMES.get(cef.get('cs2', 'N/A'), cef.get('cs2', 'N/A'))
    task_name = cef.get('cs10', 'N/A')
    task_id = cef.get('cs4', 'N/A')
    task_state = cef.get('cn2', 'N/A')
    state_desc = ""
    if task_state != 'N/A':
        states = {"0": "Неизвестно", "1": "Выполняется", "2": "Успешно", "3": "Ошибка", "4": "Отменено"}
        state_desc = f" → {states.get(task_state, task_state)}"

    event_msg = cef.get('msg', '').strip()
    if task_name != 'N/A':
        task_line = f"📋 Задача: {task_name} (ID: {task_id}){state_desc}"
    elif event_msg:
        task_line = f"💬 Сообщение: {event_msg}"
    else:
        task_line = f"📝 Тип: {description or 'Событие KSC'}"

    telegram_msg = (
        f"🚨 *KSC Событие*\n"
        f"🆔 Rule ID: {rule_id}\n"
        f"📊 Уровень: {alert_level}\n"
        f"🖥️ Хост: {host} ({ip})\n"
        f"📂 Группа: {group}\n"
        f"📦 Продукт: {product}\n"
        f"{task_line}"
    )
    telegram_msg = escape_markdown_basic(telegram_msg)
    telegram_chat_id = "-{CHAT_ID_TELEGRAMM}"
    telegram_thread_id = 20
elif "Попытка подключения к почтовому серверу с неверными данными" in telegram_msg:
    telegram_chat_id = "-{CHAT_ID_TELEGRAMM}"
    telegram_thread_id = 14
elif "Попытка ввода трёх неверных паролей за 2 минуты" in telegram_msg:
    telegram_chat_id = "-{CHAT_ID_TELEGRAMM}"
    telegram_thread_id = 3
elif "Неверная попытка подключения по VPN" in telegram_msg:
    telegram_chat_id = "-{CHAT_ID_TELEGRAMM}"
    telegram_thread_id = 18
else:
    telegram_chat_id = MAIN_CHAT_ID
    telegram_thread_id = None

# === Отправка в Telegram ===
telegram_payload = {
    'chat_id': telegram_chat_id,
    'text': telegram_msg,
    'parse_mode': 'Markdown'
}
if telegram_thread_id:
    telegram_payload['message_thread_id'] = telegram_thread_id

try:
    HOOK_URL = "https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    requests.post(HOOK_URL, json=telegram_payload, timeout=10)
except Exception:
    pass

# === Отправка в Bitrix24 (кроме 60115) ===
if rule_id != "60115":
    flow_id = BITRIX_FLOW_MAP[rule_id]
    title = TASK_TITLE_MAP.get(rule_id, f"Wazuh Alert: {rule_id}")
    if rule_id == "100150":
        cef = parse_ksc_cef(full_log)
        task_name = cef.get('cs10', 'N/A')
        if task_name != 'N/A':
            title = f"KSC: {task_name}"

    bitrix_payload = {
        "fields": {
            "TITLE": title,
            "DESCRIPTION": bitrix_description,
            "RESPONSIBLE_ID": RESPONSIBLE_MAP[rule_id],
            "AUDITORS": [{USER_ID_BITRIX}, {USER_ID_BITRIX}, {USER_ID_BITRIX}],
            "STATUS": "2",
            "PRIORITY": "1",
            "GROUP_ID": GROUP_ID,
            "FLOW_ID": flow_id
        }
    }

    try:
        requests.post(BITRIX_WEBHOOK, json=bitrix_payload, timeout=10)
    except Exception:
        pass
