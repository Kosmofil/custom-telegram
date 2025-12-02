# custom-telegram

 Wazuh → Bitrix24 & Telegram Alert Integrator

Этот скрипт отправляет критические оповещения из **Wazuh** в **Bitrix24** (как задачи) и в **Telegram** (в указанные чаты с поддержкой тем).

Поддерживает:
- События Windows AD (изменение групп администраторов, блокировка учётных записей)
- События Kaspersky Security Center (KSC)
- Фильтрацию "спама" от KSC
- Автоматическое определение чата и темы в Telegram по типу события

# 1. Перейти в директорию интеграций Wazuh
cd /var/ossec/integrations

Скачать скрипт напрямую с GitHub (raw-ссылка)
sudo curl -fsSL "https://raw.githubusercontent.com/Kosmofil/custom-telegram/main/custom_telegram.py" \
  -o /var/ossec/integrations/custom_telegram.py

sudo curl -fsSL "https://raw.githubusercontent.com/Kosmofil/custom-telegram/main/custom_telegram" \
  -o /var/ossec/integrations/custom_telegram

  # 3. Выдать права на выполнение и установить владельца
sudo chmod 750 /var/ossec/integrations/custom_telegram.py
sudo chmod 750 /var/ossec/integrations/custom_telegram
sudo chown root:wazuh /var/ossec/integrations/custom_telegram.py
sudo chown root:wazuh /var/ossec/integrations/custom_telegram

# добавить секцию integration в файл ossec.conf

