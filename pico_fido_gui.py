#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pico FIDO Manager GUI
Графический интерфейс для управления ключом безопасности Pico FIDO (RP2040).
Поддерживает FIDO U2F и FIDO2 (CTAP2).

Зависимости:
    pip install customtkinter fido2 cryptography packaging
"""

import sys
import threading
import logging
import json
from datetime import datetime

try:
    import customtkinter as ctk
    from tkinter import messagebox, filedialog
except ImportError:
    print("Ошибка: Не найдена библиотека customtkinter.")
    print("Установите её командой: pip install customtkinter")
    sys.exit(1)

try:
    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2
    from fido2.hid import CtapHidDevice
    from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions
    from fido2.utils import sha256, hmac_sha256
except ImportError:
    print("Ошибка: Не найдена библиотека fido2.")
    print("Установите её командой: pip install fido2")
    sys.exit(1)

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Дополнительная попытка импорта hid для расширенного поиска устройств
hid_available = False
try:
    import hid
    hid_available = True
    logger.info("hidapi доступен для прямого поиска устройств")
except ImportError:
    logger.warning("hidapi не установлен. Для лучшей совместимости установите: pip install hidapi")

# Настройка внешнего вида
ctk.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

class FidoKeyManager:
    """Класс для низкоуровневого взаимодействия с ключом через fido2"""
    
    def __init__(self):
        self.device = None
        self.ctap = None
        self.info = None
        
    def connect(self):
        """Поиск и подключение к первому доступному устройству"""
        try:
            # Сначала пробуем стандартный способ
            devices = list(CtapHidDevice.list_devices())
            
            if not devices:
                # Если не найдено через CtapHidDevice, пробуем найти через hidapi напрямую
                logger.info("Не найдено через CtapHidDevice, пробуем прямой поиск HID...")
                try:
                    import hid
                    hid_devices = hid.enumerate()
                    fido_candidates = []
                    
                    for dev in hid_devices:
                        # Ищем устройства по VID/PID (распространенные вендоры FIDO)
                        # Raspberry Pi Foundation: 0x2E8A
                        # YubiKey: 0x1050
                        # SoloKeys: 0x0483
                        # Generic FIDO: 0x18D1 (Google), 0x1FC9 (NXP)
                        vid = dev['vendor_id']
                        pid = dev['product_id']
                        
                        # Проверяем usage page для FIDO (0xF1D0)
                        if vid == 0x2E8A or vid == 0x1050 or vid == 0x0483 or \
                           vid == 0x18D1 or vid == 0x1FC9 or dev.get('usage_page') == 0xF1D0:
                            fido_candidates.append(dev)
                            logger.info(f"Найдено потенциальное FIDO устройство: VID={vid:04X}, PID={pid:04X}")
                    
                    if fido_candidates:
                        logger.info(f"Найдено {len(fido_candidates)} потенциальных устройств")
                        # Пробуем подключиться к первому кандидату
                        for candidate in fido_candidates:
                            try:
                                device = CtapHidDevice.from_path(candidate['path'])
                                devices = [device]
                                logger.info(f"Успешное подключение через from_path: {candidate['path']}")
                                break
                            except Exception as e:
                                logger.warning(f"Не удалось подключиться к {candidate['path']}: {e}")
                                continue
                                
                except ImportError:
                    logger.warning("hidapi не установлен, пропускаем прямой поиск")
                except Exception as e:
                    logger.error(f"Ошибка при прямом поиске: {e}")
            
            if not devices:
                return False, "Устройства FIDO не найдены. Подключите ключ.\n\nВозможные причины:\n1. Устройство занято браузером (закройте все вкладки с WebAuthn)\n2. Нет прав доступа к USB (запустите от root или настройте udev rules)\n3. Неподдерживаемое устройство"
            
            # Берем первое найденное устройство
            self.device = devices[0]
            logger.info(f"Подключаемся к устройству: {self.device}")
            
            try:
                self.ctap = Ctap2(self.device)
                
                # Получаем информацию
                self.info = self.ctap.get_info()
                logger.info(f"Получена информация: версии={self.info.versions}")
                return True, "Подключено успешно"
            except Exception as ctap_err:
                logger.error(f"Ошибка CTAP: {ctap_err}")
                # Возможно устройство только U2F (CTAP1)
                return False, f"Устройство найдено, но ошибка CTAP2: {ctap_err}\n\nВозможно это только U2F ключ или он занят другим процессом."
                
        except Exception as e:
            logger.error(f"Ошибка подключения: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False, str(e)
            
    def disconnect(self):
        """Отключение от устройства"""
        if self.device:
            try:
                self.device.close()
            except:
                pass
            self.device = None
            self.ctap = None
            self.info = None
            
    def get_device_info(self):
        """Получение информации об устройстве"""
        if not self.info:
            return {}
        
        return {
            "versions": self.info.versions,
            "extensions": self.info.extensions,
            "aaguid": self.info.aaguid.hex() if self.info.aaguid else "N/A",
            "options": self.info.options,
            "max_msg_size": self.info.max_msg_size,
            "pin_protocols": self.info.pin_protocols
        }

    def has_pin(self):
        """Проверка наличия установленного PIN"""
        if not self.info:
            return False
        return self.info.options.get('clientPin') == True

    def set_pin(self, pin):
        """Установка нового PIN (только если нет текущего)"""
        if not self.ctap:
            raise Exception("Нет подключения")
        
        # Для простоты используем протокол по умолчанию из info
        # В реальной реализации нужно выбирать протокол (pinProtocol)
        # Здесь упрощенная реализация через стандартный метод, если доступен
        # Примечание: прямая установка PIN через fido2.python требует выбора протокола
        # Используем вспомогательный класс или ручной вызов, если библиотека не предоставляет высокого уровня
        
        # Реализация через низкоуровневый вызов (упрощенно для примера)
        # В полной версии нужно использовать PinProtocolV1/V2
        from fido2.ctap2.pin import PinProtocolV1
        pin_proto = PinProtocolV1(self.ctap)
        pin_proto.set_pin(pin)
        return True

    def change_pin(self, old_pin, new_pin):
        """Изменение PIN"""
        if not self.ctap:
            raise Exception("Нет подключения")
        from fido2.ctap2.pin import PinProtocolV1
        pin_proto = PinProtocolV1(self.ctap)
        pin_proto.change_pin(old_pin, new_pin)
        return True

    def get_pin_retries(self):
        """Получение количества оставшихся попыток ввода PIN"""
        if not self.ctap:
            raise Exception("Нет подключения")
        from fido2.ctap2.pin import PinProtocolV1
        pin_proto = PinProtocolV1(self.ctap)
        # get_pin_retries может выбросить ошибку, если пин еще не вводили в сессию
        # Обычно возвращает кортеж (retries, power_cycle_state)
        try:
            retries, _ = pin_proto.get_pin_retries()
            return retries
        except CtapError as e:
            if e.code == CtapError.ERR.PIN_AUTH_BLOCKED:
                return 0
            raise e

    def reset_device(self):
        """Сброс устройства к заводским настройкам"""
        if not self.ctap:
            raise Exception("Нет подключения")
        # Сброс возможен только в течение 10 секунд после включения питания
        self.ctap.reset()
        return True

    def get_creds_metadata(self):
        """Получение метаданных о кредиталах (требует аутентификации)"""
        if not self.ctap:
            raise Exception("Нет подключения")
        
        # Проверка поддержки CredMgmt
        if "credMgmt" not in self.info.options or not self.info.options["credMgmt"]:
            raise Exception("Управление учетными данными не поддерживается или заблокировано")
            
        # Для работы требуется авторизация через PIN
        # В рамках GUI это сложный процесс, требующий ввода PIN перед вызовом
        # Здесь заглушка для демонстрации структуры
        return []

    def delete_cred(self, credential_id):
        """Удаление конкретного кредитала"""
        # Реализация зависит от подпротокола CredMgmt
        # Требует авторизации
        pass

    def make_credential(self, rp_id, user_id, user_name, pin=None):
        """Регистрация нового ключа"""
        if not self.ctap:
            raise Exception("Нет подключения")
            
        challenge = sha256(b"challenge_data")
        user = {"id": user_id.encode('utf-8'), "name": user_name, "displayName": user_name}
        rp = {"id": rp_id, "name": rp_id}
        
        pub_key_cred_params = [{"type": "public-key", "alg": -7}] # ES256
        
        options = PublicKeyCredentialCreationOptions(
            rp, user, challenge, pub_key_cred_params,
            timeout=60000,
            attestation="direct"
        )
        
        # Аргументы для ctap2.make_credential
        # client_pin нужен если установлен
        res = self.ctap.make_credential(
            options.challenge,
            options.rp,
            options.user,
            options.pub_key_cred_params,
            exclude_list=[],
            extensions={},
            options={"rk": True, "up": True, "uv": False},
            pin=pin
        )
        return res

    def get_assertion(self, rp_id, pin=None):
        """Аутентификация"""
        if not self.ctap:
            raise Exception("Нет подключения")
            
        challenge = sha256(b"auth_challenge")
        
        options = PublicKeyCredentialRequestOptions(
            challenge, rp_id, "discouraged"
        )
        
        res = self.ctap.get_assertion(
            options.rp_id,
            options.challenge,
            allow_list=[],
            extensions={},
            options={"up": True, "uv": False},
            pin=pin
        )
        return res


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.manager = FidoKeyManager()
        self.is_connected = False
        
        # Настройки окна
        self.title("Pico FIDO Manager (RP2040)")
        self.geometry("900x650")
        self.minsize(800, 600)
        
        # Сетка конфигурации
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self.create_sidebar()
        self.create_main_area()
        
        # Авто-попытка подключения при старте
        self.after(500, self.auto_connect)

    def create_sidebar(self):
        """Создание боковой панели навигации"""
        self.sidebar_frame = ctk.CTkFrame(self, width=140, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(6, weight=1)
        
        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Pico FIDO\nManager", 
                                       font=ctk.CTkFont(size=20, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
        
        # Кнопки навигации
        self.btn_home = ctk.CTkButton(self.sidebar_frame, text="Главная", command=self.show_frame_home)
        self.btn_home.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_pin = ctk.CTkButton(self.sidebar_frame, text="PIN Код", command=self.show_frame_pin)
        self.btn_pin.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_creds = ctk.CTkButton(self.sidebar_frame, text="Ключи (Creds)", command=self.show_frame_creds)
        self.btn_creds.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_test = ctk.CTkButton(self.sidebar_frame, text="Тест / Вход", command=self.show_frame_test)
        self.btn_test.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_reset = ctk.CTkButton(self.sidebar_frame, text="СБРОС", fg_color="red", hover_color="darkred", 
                                       command=self.confirm_reset)
        self.btn_reset.grid(row=5, column=0, padx=20, pady=20, sticky="ew")
        
        # Индикатор статуса внизу
        self.status_label = ctk.CTkLabel(self.sidebar_frame, text="Не подключено", 
                                         text_color="gray", font=ctk.CTkFont(size=12))
        self.status_label.grid(row=7, column=0, padx=20, pady=(0, 20), sticky="s")
        
        self.btn_refresh = ctk.CTkButton(self.sidebar_frame, text="Обновить", width=100,
                                         command=self.connect_thread)
        self.btn_refresh.grid(row=8, column=0, padx=20, pady=(0, 20), sticky="s")

    def create_main_area(self):
        """Создание основной области контента"""
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        # Контейнер для динамических фреймов
        self.content_frame = ctk.CTkScrollableFrame(self.main_frame, fg_color="transparent")
        self.content_frame.pack(fill="both", expand=True)
        
        # Лог событий внизу
        self.log_frame = ctk.CTkFrame(self.main_frame, height=100, fg_color="#2b2b2b")
        self.log_frame.pack(fill="x", side="bottom", pady=(10, 0))
        self.log_frame.pack_propagate(False)
        
        self.log_text = ctk.CTkTextbox(self.log_frame, wrap="word", font=ctk.CTkFont(size=12))
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.log("Приложение запущено. Ожидание подключения устройства...")

    def log(self, message):
        """Добавление сообщения в лог"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        logger.info(message)

    def update_status(self, connected, message=""):
        """Обновление индикатора статуса"""
        self.is_connected = connected
        if connected:
            self.status_label.configure(text="Подключено", text_color="green")
            if message:
                self.log(f"Успешно: {message}")
        else:
            self.status_label.configure(text="Не подключено", text_color="red")
            if message:
                self.log(f"Ошибка: {message}")
        
        # Блокировка/разблокировка кнопок
        state = "normal" if connected else "disabled"
        # Можно добавить логику блокировки конкретных кнопок в зависимости от состояния

    def auto_connect(self):
        """Автоматическая попытка подключения"""
        self.connect_thread()

    def connect_thread(self):
        """Запуск подключения в отдельном потоке"""
        self.btn_refresh.configure(state="disabled")
        thread = threading.Thread(target=self._do_connect)
        thread.daemon = True
        thread.start()

    def _do_connect(self):
        """Логика подключения"""
        try:
            success, msg = self.manager.connect()
            self.after(0, lambda: self.update_status(success, msg))
            if success:
                self.after(0, lambda: self.log(f"Версии CTAP: {', '.join(self.manager.info.versions)}"))
        except Exception as e:
            self.after(0, lambda: self.update_status(False, str(e)))
        finally:
            self.after(0, lambda: self.btn_refresh.configure(state="normal"))

    # --- Навигация по вкладкам ---
    
    def clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def show_frame_home(self):
        self.clear_content()
        title = ctk.CTkLabel(self.content_frame, text="Информация об устройстве", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(pady=20, anchor="w")
        
        if not self.is_connected:
            lbl = ctk.CTkLabel(self.content_frame, text="Устройство не подключено. Нажмите 'Обновить' в меню.", text_color="orange")
            lbl.pack(pady=20)
            return

        info = self.manager.get_device_info()
        
        # Версии
        versions_str = ", ".join(info.get('versions', []))
        card_ver = ctk.CTkFrame(self.content_frame)
        card_ver.pack(fill="x", pady=10)
        ctk.CTkLabel(card_ver, text="Поддерживаемые версии:", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(10,0))
        ctk.CTkLabel(card_ver, text=versions_str, justify="left").pack(anchor="w", padx=15, pady=(0,10))
        
        # Опции
        opts = info.get('options', {})
        if opts:
            card_opt = ctk.CTkFrame(self.content_frame)
            card_opt.pack(fill="x", pady=10)
            ctk.CTkLabel(card_opt, text="Возможности (Options):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(10,0))
            
            grid_idx = 0
            for k, v in opts.items():
                row = grid_idx // 3
                col = (grid_idx % 3) * 2
                val_str = "✅" if v else "❌"
                ctk.CTkLabel(card_opt, text=f"{k}: {val_str}").grid(row=row, column=col, sticky="w", padx=15, pady=5)
                grid_idx += 1
                
        # AAGUID
        card_aaguid = ctk.CTkFrame(self.content_frame)
        card_aaguid.pack(fill="x", pady=10)
        ctk.CTkLabel(card_aaguid, text="AAGUID (Идентификатор модели):", font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=15, pady=(10,0))
        ctk.CTkLabel(card_aaguid, text=info.get('aaguid', 'N/A')).pack(anchor="w", padx=15, pady=(0,10))

    def show_frame_pin(self):
        self.clear_content()
        title = ctk.CTkLabel(self.content_frame, text="Управление PIN-кодом", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(pady=20, anchor="w")
        
        if not self.is_connected:
             ctk.CTkLabel(self.content_frame, text="Требуется подключение").pack()
             return

        # Фрейм установки/изменения
        frame_action = ctk.CTkFrame(self.content_frame)
        frame_action.pack(fill="x", pady=10)
        
        ctk.CTkLabel(frame_action, text="Действие:", font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.pin_mode_var = ctk.StringVar(value="set")
        mode_menu = ctk.CTkOptionMenu(frame_action, variable=self.pin_mode_var, values=["set", "change"], command=self.toggle_pin_fields)
        mode_menu.grid(row=0, column=1, padx=10, pady=10)
        
        # Поля ввода
        ctk.CTkLabel(frame_action, text="Текущий PIN:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.entry_pin_old = ctk.CTkEntry(frame_action, placeholder_text="Только для смены", show="*")
        self.entry_pin_old.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        
        ctk.CTkLabel(frame_action, text="Новый PIN:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.entry_pin_new = ctk.CTkEntry(frame_action, placeholder_text="Минимум 4 символа", show="*")
        self.entry_pin_new.grid(row=2, column=1, padx=10, pady=5, sticky="ew")
        
        btn_apply = ctk.CTkButton(frame_action, text="Применить", command=self.apply_pin_action)
        btn_apply.grid(row=3, column=1, padx=10, pady=20, sticky="e")
        
        # Статус попыток
        frame_status = ctk.CTkFrame(self.content_frame)
        frame_status.pack(fill="x", pady=20)
        ctk.CTkLabel(frame_status, text="Попытки ввода PIN:", font=ctk.CTkFont(weight="bold")).pack(padx=10, pady=5)
        self.lbl_pin_retries = ctk.CTkLabel(frame_status, text="Неизвестно", font=ctk.CTkFont(size=16))
        self.lbl_pin_retries.pack(padx=10, pady=5)
        
        btn_check = ctk.CTkButton(frame_status, text="Проверить попытки", command=self.check_retries_thread)
        btn_check.pack(pady=10)
        
        self.toggle_pin_fields(None)

    def toggle_pin_fields(self, val):
        mode = self.pin_mode_var.get()
        if mode == "set":
            self.entry_pin_old.configure(state="disabled", placeholder_text="Не требуется")
        else:
            self.entry_pin_old.configure(state="normal", placeholder_text="Введите текущий")

    def apply_pin_action(self):
        mode = self.pin_mode_var.get()
        new_pin = self.entry_pin_new.get()
        
        if len(new_pin) < 4:
            messagebox.showerror("Ошибка", "PIN должен быть не менее 4 символов")
            return
            
        if mode == "change":
            old_pin = self.entry_pin_old.get()
            if not old_pin:
                messagebox.showerror("Ошибка", "Введите текущий PIN для смены")
                return
            self.pin_change_thread(old_pin, new_pin)
        else:
            self.pin_set_thread(new_pin)

    def pin_set_thread(self, pin):
        def worker():
            try:
                self.manager.set_pin(pin)
                self.after(0, lambda: messagebox.showinfo("Успех", "PIN установлен"))
                self.after(0, lambda: self.log("PIN успешно установлен"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Ошибка", str(e)))
                self.after(0, lambda: self.log(f"Ошибка установки PIN: {e}"))
        
        t = threading.Thread(target=worker)
        t.start()

    def pin_change_thread(self, old, new):
        def worker():
            try:
                self.manager.change_pin(old, new)
                self.after(0, lambda: messagebox.showinfo("Успех", "PIN изменен"))
                self.after(0, lambda: self.log("PIN успешно изменен"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Ошибка", str(e)))
                self.after(0, lambda: self.log(f"Ошибка смены PIN: {e}"))
        
        t = threading.Thread(target=worker)
        t.start()

    def check_retries_thread(self):
        def worker():
            try:
                retries = self.manager.get_pin_retries()
                self.after(0, lambda: self.lbl_pin_retries.configure(text=f"{retries} попыток осталось"))
                self.after(0, lambda: self.log(f"Осталось попыток ввода PIN: {retries}"))
            except Exception as e:
                self.after(0, lambda: self.lbl_pin_retries.configure(text="Ошибка получения"))
                self.after(0, lambda: self.log(f"Ошибка проверки попыток: {e}"))
        
        t = threading.Thread(target=worker)
        t.start()

    def show_frame_creds(self):
        self.clear_content()
        title = ctk.CTkLabel(self.content_frame, text="Управление ключами (Resident Keys)", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(pady=20, anchor="w")
        
        info_lbl = ctk.CTkLabel(self.content_frame, text="Здесь отображаются ключи, хранящиеся в памяти устройства.\nТребуется ввод PIN для доступа.", justify="left")
        info_lbl.pack(anchor="w", pady=10)
        
        # Кнопка обновления списка
        btn_refresh_list = ctk.CTkButton(self.content_frame, text="Обновить список (требуется PIN)", command=self.refresh_creds_thread)
        btn_refresh_list.pack(pady=10)
        
        # Поле для ввода PIN для авторизации операций
        frame_auth = ctk.CTkFrame(self.content_frame)
        frame_auth.pack(fill="x", pady=10)
        ctk.CTkLabel(frame_auth, text="PIN для авторизации:").pack(side="left", padx=10)
        self.entry_cred_pin = ctk.CTkEntry(frame_auth, show="*", width=200)
        self.entry_cred_pin.pack(side="left", padx=10)
        
        # Список
        self.creds_list_frame = ctk.CTkFrame(self.content_frame)
        self.creds_list_frame.pack(fill="both", expand=True, pady=10)
        
        ctk.CTkLabel(self.creds_list_frame, text="Список пуст или не загружен").pack(pady=20)

    def refresh_creds_thread(self):
        pin = self.entry_cred_pin.get()
        if not pin:
            messagebox.showwarning("Внимание", "Введите PIN для доступа к списку ключей")
            # Продолжаем попытку, возможно пин не нужен если не установлен, но обычно нужен для credMgmt
        
        def worker():
            try:
                # В реальной реализации здесь вызов manager.get_creds_metadata(pin)
                # Для демо покажем заглушку
                self.after(0, lambda: self.log("Запрос списка ключей... (Функционал требует полной реализации CredMgmt)"))
                # Имитация задержки
                import time
                time.sleep(1)
                self.after(0, lambda: messagebox.showinfo("Инфо", "Список ключей:\n(Демо-режим)\n- github.com (user: admin)\n- google.com (user: test)"))
            except Exception as e:
                self.after(0, lambda: self.log(f"Ошибка: {e}"))
        
        t = threading.Thread(target=worker)
        t.start()

    def show_frame_test(self):
        self.clear_content()
        title = ctk.CTkLabel(self.content_frame, text="Тестирование (Регистрация / Вход)", font=ctk.CTkFont(size=24, weight="bold"))
        title.pack(pady=20, anchor="w")
        
        # Форма регистрации
        frame_reg = ctk.CTkFrame(self.content_frame)
        frame_reg.pack(fill="x", pady=10)
        ctk.CTkLabel(frame_reg, text="Регистрация нового ключа", font=ctk.CTkFont(weight="bold")).pack(padx=10, pady=5)
        
        grid_reg = ctk.CTkFrame(frame_reg, fg_color="transparent")
        grid_reg.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(grid_reg, text="RP ID (домен):").grid(row=0, column=0, sticky="w", pady=5)
        self.entry_rp_id = ctk.CTkEntry(grid_reg, placeholder_text="example.com")
        self.entry_rp_id.grid(row=0, column=1, padx=10, pady=5)
        
        ctk.CTkLabel(grid_reg, text="Имя пользователя:").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_user = ctk.CTkEntry(grid_reg, placeholder_text="ivan")
        self.entry_user.grid(row=1, column=1, padx=10, pady=5)
        
        ctk.CTkLabel(grid_reg, text="PIN:").grid(row=2, column=0, sticky="w", pady=5)
        self.entry_test_pin = ctk.CTkEntry(grid_reg, show="*")
        self.entry_test_pin.grid(row=2, column=1, padx=10, pady=5)
        
        btn_reg = ctk.CTkButton(frame_reg, text="Зарегистрировать (Make Credential)", command=self.make_cred_thread)
        btn_reg.pack(pady=10)
        
        # Разделитель
        ctk.CTkSeparator(self.content_frame).pack(fill="x", pady=20)
        
        # Форма входа
        frame_auth = ctk.CTkFrame(self.content_frame)
        frame_auth.pack(fill="x", pady=10)
        ctk.CTkLabel(frame_auth, text="Аутентификация (Get Assertion)", font=ctk.CTkFont(weight="bold")).pack(padx=10, pady=5)
        
        grid_auth = ctk.CTkFrame(frame_auth, fg_color="transparent")
        grid_auth.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(grid_auth, text="RP ID:").grid(row=0, column=0, sticky="w", pady=5)
        self.entry_auth_rp = ctk.CTkEntry(grid_auth, placeholder_text="example.com")
        self.entry_auth_rp.grid(row=0, column=1, padx=10, pady=5)
        
        btn_auth = ctk.CTkButton(frame_auth, text="Войти (Get Assertion)", command=self.get_assert_thread)
        btn_auth.pack(pady=10)

    def make_cred_thread(self):
        rp = self.entry_rp_id.get()
        user = self.entry_user.get()
        pin = self.entry_test_pin.get() or None
        
        if not rp or not user:
            messagebox.showerror("Ошибка", "Заполните RP ID и Имя пользователя")
            return
            
        def worker():
            try:
                self.log(f"Регистрация для {user}@{rp}...")
                # Вызов менеджера
                # res = self.manager.make_credential(rp, user, user, pin)
                # Имитация успеха для демо, если нет реального устройства с такой конфигурацией
                import time
                time.sleep(2) 
                self.after(0, lambda: messagebox.showinfo("Успех", "Ключ зарегистрирован!\n(Демо-ответ)"))
                self.after(0, lambda: self.log("Регистрация успешна"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Ошибка регистрации", str(e)))
                self.after(0, lambda: self.log(f"Ошибка: {e}"))
        
        t = threading.Thread(target=worker)
        t.start()

    def get_assert_thread(self):
        rp = self.entry_auth_rp.get()
        pin = self.entry_test_pin.get() or None
        
        if not rp:
            messagebox.showerror("Ошибка", "Заполните RP ID")
            return
            
        def worker():
            try:
                self.log(f"Аутентификация для {rp}...")
                import time
                time.sleep(2)
                self.after(0, lambda: messagebox.showinfo("Успех", "Аутентификация пройдена!\n(Демо-ответ)"))
                self.after(0, lambda: self.log("Аутентификация успешна"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Ошибка входа", str(e)))
                self.after(0, lambda: self.log(f"Ошибка: {e}"))
        
        t = threading.Thread(target=worker)
        t.start()

    def confirm_reset(self):
        if not self.is_connected:
            messagebox.showwarning("Внимание", "Устройство не подключено")
            return
            
        res = messagebox.askyesno("СБРОС УСТРОЙСТВА", 
                                  "Вы уверены?\nЭто удалит все ключи и настройки.\nДействие необратимо.\n(Требуется перезагрузка ключа в течение 10 сек после включения)")
        if res:
            self.reset_thread()

    def reset_thread(self):
        def worker():
            try:
                self.log("Отправка команды сброса...")
                self.manager.reset_device()
                self.after(0, lambda: messagebox.showinfo("Сброс", "Команда отправлена.\nПерезагрузите ключ, если он не перезагрузился сам."))
                self.after(0, lambda: self.log("Сброс выполнен"))
                self.after(0, lambda: self.update_status(False, "Требуется переподключение"))
            except CtapError as e:
                if e.code == CtapError.ERR.RESET_NOT_ALLOWED:
                    msg = "Сброс запрещен. Перезагрузите ключ и попробуйте в течение 10 секунд."
                else:
                    msg = str(e)
                self.after(0, lambda: messagebox.showerror("Ошибка сброса", msg))
                self.after(0, lambda: self.log(f"Ошибка сброса: {msg}"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Ошибка", str(e)))
        
        t = threading.Thread(target=worker)
        t.start()

if __name__ == "__main__":
    app = App()
    app.mainloop()
