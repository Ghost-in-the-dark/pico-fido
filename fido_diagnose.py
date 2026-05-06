#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Диагностическая утилита для поиска FIDO устройств
Помогает определить, видит ли система подключенный ключ
"""

import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def check_hidapi():
    """Проверка доступности hidapi"""
    try:
        import hid
        logger.info("✓ hidapi установлен")
        return True
    except ImportError:
        logger.error("✗ hidapi НЕ установлен")
        logger.info("  Установите: pip install hidapi")
        return False

def check_fido2():
    """Проверка доступности fido2"""
    try:
        from fido2.hid import CtapHidDevice
        logger.info("✓ fido2 установлена")
        return True
    except ImportError:
        logger.error("✗ fido2 НЕ установлена")
        logger.info("  Установите: pip install fido2")
        return False

def list_all_hid_devices():
    """Вывод всех HID устройств в системе"""
    logger.info("\n=== Все HID устройства ===")
    try:
        import hid
        devices = hid.enumerate()
        
        if not devices:
            logger.info("  Нет HID устройств")
            return []
        
        for i, dev in enumerate(devices):
            vid = dev['vendor_id']
            pid = dev['product_id']
            manufacturer = dev.get('manufacturer_string', 'N/A') or 'N/A'
            product = dev.get('product_string', 'N/A') or 'N/A'
            usage_page = dev.get('usage_page', 0)
            path = dev.get('path', 'N/A')
            
            logger.info(f"\n[{i}] {manufacturer} - {product}")
            logger.info(f"    VID:PID = {vid:04X}:{pid:04X}")
            logger.info(f"    Usage Page: 0x{usage_page:04X}")
            logger.info(f"    Path: {path}")
            
            # Проверка на FIDO
            is_fido = False
            reasons = []
            
            # Известные VID вендоров FIDO
            fido_vids = {
                0x2E8A: "Raspberry Pi",
                0x1050: "Yubico",
                0x0483: "SoloKeys/STM",
                0x18D1: "Google",
                0x1FC9: "NXP",
            }
            
            if vid in fido_vids:
                is_fido = True
                reasons.append(f"Вендор: {fido_vids[vid]}")
            
            if usage_page == 0xF1D0:
                is_fido = True
                reasons.append("FIDO Usage Page (0xF1D0)")
            
            if is_fido:
                logger.info(f"    ★ ВОЗМОЖНО FIDO УСТРОЙСТВО: {', '.join(reasons)}")
        
        return devices
        
    except Exception as e:
        logger.error(f"Ошибка при сканировании HID: {e}")
        return []

def try_fido_connection():
    """Попытка подключения через fido2"""
    logger.info("\n=== Попытка подключения через fido2 ===")
    try:
        from fido2.hid import CtapHidDevice
        
        devices = list(CtapHidDevice.list_devices())
        
        if devices:
            logger.info(f"✓ Найдено {len(devices)} FIDO устройство(й)")
            for i, dev in enumerate(devices):
                logger.info(f"  [{i}] {dev}")
            return devices
        else:
            logger.warning("✗ Устройства не найдены через CtapHidDevice.list_devices()")
            logger.info("  Возможные причины:")
            logger.info("  1. Устройство занято другим процессом (браузер)")
            logger.info("  2. Нет прав доступа к /dev/hidraw*")
            logger.info("  3. Устройство не поддерживает CTAP2")
            return []
            
    except Exception as e:
        logger.error(f"Ошибка: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return []

def check_permissions():
    """Проверка прав доступа к hidraw устройствам"""
    logger.info("\n=== Права доступа к hidraw ===")
    import os
    
    hidraw_devices = []
    for root, dirs, files in os.walk('/dev'):
        for file in files:
            if file.startswith('hidraw'):
                hidraw_devices.append(os.path.join(root, file))
    
    if not hidraw_devices:
        logger.info("  Устройства /dev/hidraw* не найдены")
        return
    
    for dev in sorted(hidraw_devices):
        try:
            stat_info = os.stat(dev)
            mode = oct(stat_info.st_mode)[-3:]
            readable = os.access(dev, os.R_OK)
            writable = os.access(dev, os.W_OK)
            
            status = []
            if readable: status.append("R")
            if writable: status.append("W")
            
            logger.info(f"  {dev}: режим={mode}, права={''.join(status)}")
            
        except Exception as e:
            logger.info(f"  {dev}: ошибка доступа ({e})")

def main():
    logger.info("=" * 60)
    logger.info("Диагностика FIDO устройств")
    logger.info("=" * 60)
    
    has_hidapi = check_hidapi()
    has_fido2 = check_fido2()
    
    if not has_hidapi or not has_fido2:
        logger.info("\n⚠ Не все библиотеки установлены!")
        logger.info("Выполните: pip install hidapi fido2 customtkinter")
        sys.exit(1)
    
    all_devices = list_all_hid_devices()
    fido_devices = try_fido_connection()
    check_permissions()
    
    logger.info("\n" + "=" * 60)
    logger.info("РЕКОМЕНДАЦИИ:")
    logger.info("=" * 60)
    
    if not fido_devices and all_devices:
        logger.info("""
1. Закройте все браузеры и приложения, которые могут использовать ключ
2. Проверьте права доступа (см. выше). Если нет прав 'W':
   - Запустите программу от root: sudo python3 pico_fido_gui.py
   - ИЛИ настройте udev правила (файл 70-fido.rules в репозитории)
   
3. Переподключите устройство после настройки правил:
   sudo udevadm control --reload-rules && sudo udevadm trigger

4. Если устройство найдено в HID списке, но не через fido2:
   - Возможно это только U2F (CTAP1) устройство
   - Или прошивка не поддерживает CTAP2 команды
""")
    elif not all_devices:
        logger.info("""
- Устройство не видно в системе
- Проверьте USB подключение
- Попробуйте другой порт/кабель
- Убедитесь, что устройство включено
""")
    else:
        logger.info("\n✓ Устройство найдено и готово к работе!")
        logger.info("Запускайте: python3 pico_fido_gui.py")

if __name__ == "__main__":
    main()
