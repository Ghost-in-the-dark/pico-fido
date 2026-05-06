#!/usr/bin/env python3
"""
Pico FIDO Key Manager
Программа для настройки и управления ключом безопасности Pico FIDO (RP2040)
Поддерживает FIDO U2F (CTAP1) и FIDO2 (CTAP2) протоколы

Автор: Assistant
Лицензия: AGPLv3
"""

import sys
import os
import json
import argparse
import getpass
from typing import Optional, List, Dict, Any

try:
    from fido2.hid import CtapHidDevice
    from fido2.client import Fido2Client, ClientError, DefaultClientDataCollector
    from fido2.ctap2.pin import ClientPin, PinProtocolV2
    from fido2.ctap2 import CredentialManagement
    from fido2.ctap import CtapError
    from fido2.webauthn import (
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
        PublicKeyCredentialRpEntity,
        PublicKeyCredentialUserEntity,
        UserVerificationRequirement,
        AttestedCredentialData,
    )
    from fido2.utils import sha256, hmac_sha256
except ImportError as e:
    print(f"Ошибка: Не удалось импортировать необходимые библиотеки.")
    print(f"Установите зависимости: pip install fido2 cryptography")
    print(f"Детали: {e}")
    sys.exit(1)


class PicoFIDOManager:
    """Класс для управления ключом Pico FIDO"""

    DEFAULT_ORIGIN = "https://pico-fido.local"
    DEFAULT_RP = {"id": "pico-fido.local", "name": "Pico FIDO Key"}
    DEFAULT_PIN = None  # Будет запрошен у пользователя при необходимости

    def __init__(self, origin: str = None, rp: dict = None):
        """
        Инициализация менеджера ключа
        
        Args:
            origin: Origin для WebAuthn операций
            rp: Relying Party информация
        """
        self.origin = origin or self.DEFAULT_ORIGIN
        self.rp = rp or self.DEFAULT_RP
        self.device = None
        self.client = None
        self.client_pin = None
        self.pin_protocol = None
        self.pin_token = None
        self._connect()

    def _connect(self):
        """Подключение к устройству FIDO"""
        # Поиск устройства через USB HID
        self.device = next(CtapHidDevice.list_devices(), None)
        
        if self.device is None:
            # Попытка найти через PC/SC (NFC)
            try:
                from fido2.pcsc import CtapPcscDevice
                self.device = next(CtapPcscDevice.list_devices(), None)
                if self.device:
                    print("✓ Подключено через NFC (PC/SC)")
            except Exception:
                pass
        
        if self.device is None:
            raise RuntimeError("Не найдено устройств FIDO. Убедитесь, что ключ подключен.")
        
        print(f"✓ Найдено устройство: {self.device}")
        
        # Создание FIDO2 клиента
        self.client = Fido2Client(
            self.device,
            client_data_collector=DefaultClientDataCollector(
                origin=self.origin,
                verify=lambda rp_id, origin: True
            ),
            user_interaction=self
        )
        
        # Инициализация PIN протокола
        self.pin_protocol = PinProtocolV2()
        self.client_pin = ClientPin(self.client._backend.ctap2)
        
        print(f"✓ Информациия об устройстве:")
        info = self.client._backend.info
        print(f"  - Версия CTAP: {info.version}")
        print(f"  - Поддержка FIDO2: {info.options.get('plat', False) or info.options.get('clientPin', False)}")
        print(f"  - Поддержка Resident Keys: {info.options.get('rk', False)}")
        print(f"  - Поддержка PIN: {info.options.get('clientPin', False)}")
        print(f"  - Поддержка Credential Management: {info.options.get('credMgmt', False)}")
        print(f"  - Версии протоколов: {info.versions}")

    def prompt_up(self):
        """Запрос на активацию пользователем (нажатие кнопки)"""
        print("\n⚠️  Коснитесь сенсора на ключе безопасности...")
        return True

    def request_pin(self, permissions, rp_id):
        """Запрос PIN у пользователя"""
        if self.DEFAULT_PIN:
            return self.DEFAULT_PIN
        pin = getpass.getpass("Введите PIN для ключа безопасности: ")
        return pin

    def request_uv(self, permissions, rp_id):
        """Запрос пользовательской верификации"""
        print("Требуется пользовательская верификация.")
        return True

    def get_info(self) -> dict:
        """Получение информации об устройстве"""
        info = self.client._backend.info
        return {
            'versions': info.versions,
            'extensions': info.extensions,
            'aaguid': info.aaguid.hex() if info.aaguid else None,
            'options': info.options,
            'max_msg_size': info.max_msg_size,
            'pin_protocols': info.pin_protocols,
            'algorithms': [str(alg) for alg in info.algorithms] if info.algorithms else None,
            'max_credential_count_in_list': info.max_credential_count_in_list,
            'max_credential_id_length': info.max_credential_id_length,
            'transports': info.transports,
        }

    def reset_device(self, confirm: bool = False):
        """
        Сброс устройства к заводским настройкам
        
        Args:
            confirm: Требовать подтверждение операции
        """
        if confirm:
            response = input("⚠️  ВНИМАНИЕ: Все данные будут удалены! Продолжить? (yes/no): ")
            if response.lower() != 'yes':
                print("Сброс отменен.")
                return
        
        print("Выполняется сброс устройства...")
        try:
            self.client._backend.ctap2.reset()
            print("✓ Устройство успешно сброшено")
            # Переподключение после сброса
            self._connect()
        except CtapError as e:
            print(f"✗ Ошибка сброса: {e}")
            raise

    def set_pin(self, pin: str = None):
        """
        Установка PIN-кода
        
        Args:
            pin: PIN-код (4-63 символа). Если не указан, будет запрошен у пользователя.
        """
        if not pin:
            pin = getpass.getpass("Введите новый PIN (4-63 символа): ")
            pin_confirm = getpass.getpass("Подтвердите PIN: ")
            if pin != pin_confirm:
                raise ValueError("PIN-коды не совпадают")
        
        if len(pin) < 4:
            raise ValueError("PIN должен содержать минимум 4 символа")
        if len(pin) > 63:
            raise ValueError("PIN должен содержать максимум 63 символа")
        
        print("Установка PIN-кода...")
        try:
            self.client_pin.set_pin(pin)
            print("✓ PIN-код успешно установлен")
        except CtapError as e:
            print(f"✗ Ошибка установки PIN: {e}")
            raise

    def change_pin(self, old_pin: str = None, new_pin: str = None):
        """
        Изменение PIN-кода
        
        Args:
            old_pin: Текущий PIN-код
            new_pin: Новый PIN-код
        """
        if not old_pin:
            old_pin = getpass.getpass("Введите текущий PIN: ")
        
        if not new_pin:
            new_pin = getpass.getpass("Введите новый PIN: ")
            new_pin_confirm = getpass.getpass("Подтвердите новый PIN: ")
            if new_pin != new_pin_confirm:
                raise ValueError("Новые PIN-коды не совпадают")
        
        print("Изменение PIN-кода...")
        try:
            self.client_pin.change_pin(old_pin, new_pin)
            print("✓ PIN-код успешно изменен")
        except CtapError as e:
            print(f"✗ Ошибка изменения PIN: {e}")
            raise

    def get_pin_retries(self) -> int:
        """Получение количества оставшихся попыток ввода PIN"""
        try:
            retries, _ = self.client_pin.get_pin_retries()
            return retries
        except CtapError as e:
            if e.code == CtapError.ERR.PIN_NOT_SET:
                return -1  # PIN не установлен
            raise

    def _authenticate_pin(self, pin: str = None, permissions: int = None) -> bytes:
        """
        Аутентификация по PIN и получение токена
        
        Args:
            pin: PIN-код. Если не указан, будет запрошен у пользователя.
            permissions: Битовая маска разрешений
        
        Returns:
            PIN токен
        """
        if not pin:
            pin = getpass.getpass("Введите PIN: ")
        
        if permissions is None:
            permissions = (
                ClientPin.PERMISSION.MAKE_CREDENTIAL |
                ClientPin.PERMISSION.CREDENTIAL_MGMT |
                ClientPin.PERMISSION.GET_ASSERTION
            )
        
        try:
            self.pin_token = self.client_pin.get_pin_token(pin, permissions=permissions)
            return self.pin_token
        except CtapError as e:
            print(f"✗ Ошибка аутентификации PIN: {e}")
            raise

    def get_credential_metadata(self) -> dict:
        """
        Получение метаданных об учетных данных
        
        Returns:
            Словарь с информацией о хранилище учетных данных
        """
        if not self.pin_token:
            self._authenticate_pin()
        
        try:
            cred_mgmt = CredentialManagement(
                self.client._backend.ctap2,
                self.pin_protocol,
                self.pin_token
            )
            metadata = cred_mgmt.get_metadata()
            return {
                'existing_cred_count': metadata.get(CredentialManagement.RESULT.EXISTING_CRED_COUNT, 0),
                'max_remaining_count': metadata.get(CredentialManagement.RESULT.MAX_REMAINING_COUNT, 0),
            }
        except CtapError as e:
            print(f"✗ Ошибка получения метаданных: {e}")
            raise

    def list_credentials(self) -> List[dict]:
        """
        Список всех сохраненных учетных данных (Resident Keys)
        
        Returns:
            Список словарей с информацией об учетных данных
        """
        if not self.pin_token:
            self._authenticate_pin()
        
        credentials = []
        try:
            cred_mgmt = CredentialManagement(
                self.client._backend.ctap2,
                self.pin_protocol,
                self.pin_token
            )
            
            # Получение списка RP
            rps = cred_mgmt.enumerate_rps()
            print(f"\nНайдено {len(rps)} relying party(ies):")
            
            for rp_entry in rps:
                rp_info = rp_entry[CredentialManagement.RESULT.RP]
                rp_id_hash = rp_entry[CredentialManagement.RESULT.RP_ID_HASH]
                
                print(f"\n  RP: {rp_info.get('name', rp_info.get('id', 'Unknown'))} ({rp_info.get('id', 'N/A')})")
                
                # Получение учетных данных для этого RP
                creds = cred_mgmt.enumerate_creds(rp_id_hash)
                for cred in creds:
                    cred_info = {
                        'rp_id': rp_info.get('id'),
                        'rp_name': rp_info.get('name'),
                        'user_id': cred[CredentialManagement.RESULT.USER].get('id', b'').hex(),
                        'user_name': cred[CredentialManagement.RESULT.USER].get('name', 'Unknown'),
                        'user_display_name': cred[CredentialManagement.RESULT.USER].get('displayName', ''),
                        'credential_id': cred[CredentialManagement.RESULT.CREDENTIAL_ID].hex(),
                        'public_key': cred.get(CredentialManagement.RESULT.PUBLIC_KEY),
                        'total_credentials': cred.get(CredentialManagement.RESULT.TOTAL_CREDENTIALS),
                    }
                    credentials.append(cred_info)
                    print(f"    - Пользователь: {cred_info['user_name']}")
                    print(f"      ID учетной записи: {cred_info['credential_id'][:16]}...")
            
            return credentials
            
        except CtapError as e:
            print(f"✗ Ошибка получения списка учетных данных: {e}")
            raise

    def delete_credential(self, credential_id: str = None, index: int = None):
        """
        Удаление учетной записи
        
        Args:
            credential_id: Hex-строка с ID учетной записи
            index: Индекс учетной записи в списке (если credential_id не указан)
        """
        if not self.pin_token:
            self._authenticate_pin()
        
        try:
            cred_mgmt = CredentialManagement(
                self.client._backend.ctap2,
                self.pin_protocol,
                self.pin_token
            )
            
            # Если указан индекс, получаем credential_id из списка
            if index is not None and credential_id is None:
                creds = self.list_credentials()
                if index < 0 or index >= len(creds):
                    raise ValueError(f"Неверный индекс: {index}. Доступно {len(creds)} учетных записей.")
                credential_id = creds[index]['credential_id']
                print(f"Удаление учетной записи {index}: {credential_id[:16]}...")
            
            if not credential_id:
                raise ValueError("Необходимо указать credential_id или index")
            
            # Преобразование hex строки в байты
            cred_id_bytes = bytes.fromhex(credential_id)
            
            cred = {
                "id": cred_id_bytes,
                "type": "public-key"
            }
            
            print("Удаление учетной записи...")
            cred_mgmt.delete_cred(cred)
            print("✓ Учетная запись успешно удалена")
            
        except CtapError as e:
            print(f"✗ Ошибка удаления: {e}")
            raise

    def register_credential(self, rp_id: str = None, rp_name: str = None, 
                          user_id: bytes = None, user_name: str = None,
                          resident_key: bool = True, user_verification: str = 'discouraged'):
        """
        Регистрация новой учетной записи (Make Credential)
        
        Args:
            rp_id: ID relying party
            rp_name: Имя relying party
            user_id: ID пользователя (bytes)
            user_name: Имя пользователя
            resident_key: Сохранять ли учетную запись на устройстве (Resident Key)
            user_verification: Требуемая верификация ('required', 'preferred', 'discouraged')
        """
        rp_id = rp_id or self.rp['id']
        rp_name = rp_name or self.rp['name']
        user_id = user_id or os.urandom(32)
        user_name = user_name or "User"
        
        rp = PublicKeyCredentialRpEntity(id=rp_id, name=rp_name)
        user = PublicKeyCredentialUserEntity(id=user_id, name=user_name, display_name=user_name)
        
        uv_requirement = {
            'required': UserVerificationRequirement.REQUIRED,
            'preferred': UserVerificationRequirement.PREFERRED,
            'discouraged': UserVerificationRequirement.DISCOURAGED,
        }.get(user_verification.lower(), UserVerificationRequirement.DISCOURAGED)
        
        options = PublicKeyCredentialCreationOptions(
            rp=rp,
            user=user,
            challenge=os.urandom(32),
            pub_key_cred_params=[
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -8},  # EdDSA
            ],
            resident_key=resident_key,
            user_verification=uv_requirement,
        )
        
        print(f"Регистрация учетной записи:")
        print(f"  RP: {rp_name} ({rp_id})")
        print(f"  Пользователь: {user_name}")
        print(f"  Resident Key: {resident_key}")
        
        try:
            result = self.client.make_credential(options)
            print("✓ Учетная запись успешно зарегистрирована")
            
            # Информация о созданной учетной записи
            attestation_object = result.attestation_object
            auth_data = attestation_object.auth_data
            
            if auth_data.credential_data:
                cred_data = auth_data.credential_data
                print(f"  Credential ID: {cred_data.credential_id.hex()[:32]}...")
                print(f"  Тип ключа: {cred_data.public_key.ALGORITHM}")
            
            return {
                'success': True,
                'attestation_object': attestation_object,
                'credential_id': auth_data.credential_data.credential_id if auth_data.credential_data else None,
            }
            
        except CtapError as e:
            print(f"✗ Ошибка регистрации: {e}")
            raise
        except ClientError as e:
            print(f"✗ Ошибка клиента: {e}")
            raise

    def authenticate(self, rp_id: str = None, allow_list: List[dict] = None,
                    user_verification: str = 'discouraged') -> dict:
        """
        Аутентификация с использованием учетной записи (Get Assertion)
        
        Args:
            rp_id: ID relying party
            allow_list: Список разрешенных credential IDs
            user_verification: Требуемая верификация
        """
        rp_id = rp_id or self.rp['id']
        
        uv_requirement = {
            'required': UserVerificationRequirement.REQUIRED,
            'preferred': UserVerificationRequirement.PREFERRED,
            'discouraged': UserVerificationRequirement.DISCOURAGED,
        }.get(user_verification.lower(), UserVerificationRequirement.DISCOURAGED)
        
        options = PublicKeyCredentialRequestOptions(
            challenge=os.urandom(32),
            rp_id=rp_id,
            allow_credentials=allow_list,
            user_verification=uv_requirement,
        )
        
        print(f"Аутентификация для: {rp_id}")
        
        try:
            result = self.client.get_assertion(options)
            print("✓ Аутентификация успешна")
            
            assertions = result.get_assertions()
            for i, assertion in enumerate(assertions):
                print(f"  Учетная запись {i + 1}:")
                print(f"    Credential ID: {assertion.credential['id'][:16]}...")
                print(f"    Флаги: {assertion.auth_data.flags:08b}")
                print(f"    Counter: {assertion.auth_data.counter}")
            
            return {
                'success': True,
                'assertions': assertions,
            }
            
        except CtapError as e:
            print(f"✗ Ошибка аутентификации: {e}")
            raise

    def export_credentials(self, filename: str = None) -> str:
        """
        Экспорт списка учетных данных в JSON файл
        
        Args:
            filename: Имя файла для экспорта
        
        Returns:
            Путь к файлу
        """
        credentials = self.list_credentials()
        metadata = self.get_credential_metadata()
        
        export_data = {
            'metadata': metadata,
            'credentials': credentials,
            'timestamp': str(__import__('datetime').datetime.now()),
        }
        
        if not filename:
            filename = f"pico_fido_export_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        print(f"✓ Экспорт выполнен в файл: {filename}")
        return filename

    def interactive_menu(self):
        """Интерактивное меню управления ключом"""
        while True:
            print("\n" + "="*60)
            print("  Pico FIDO Key Manager - Главное меню")
            print("="*60)
            print("1. Информация об устройстве")
            print("2. Управление PIN-кодом")
            print("3. Просмотр учетных записей")
            print("4. Регистрация новой учетной записи")
            print("5. Аутентификация")
            print("6. Удаление учетной записи")
            print("7. Экспорт учетных записей")
            print("8. Сброс устройства")
            print("9. Выход")
            print("="*60)
            
            choice = input("\nВыберите действие (1-9): ").strip()
            
            try:
                if choice == '1':
                    info = self.get_info()
                    print("\n--- Информация об устройстве ---")
                    for key, value in info.items():
                        if value is not None:
                            print(f"  {key}: {value}")
                
                elif choice == '2':
                    self._pin_management_menu()
                
                elif choice == '3':
                    self.list_credentials()
                
                elif choice == '4':
                    self._register_menu()
                
                elif choice == '5':
                    self._authenticate_menu()
                
                elif choice == '6':
                    self._delete_menu()
                
                elif choice == '7':
                    filename = input("Имя файла для экспорта (Enter для авто): ").strip()
                    self.export_credentials(filename if filename else None)
                
                elif choice == '8':
                    self.reset_device(confirm=True)
                
                elif choice == '9':
                    print("\nДо свидания!")
                    break
                
                else:
                    print("Неверный выбор. Попробуйте снова.")
                    
            except KeyboardInterrupt:
                print("\n\nОперация прервана.")
            except Exception as e:
                print(f"\n✗ Произошла ошибка: {e}")
                if os.environ.get('DEBUG'):
                    import traceback
                    traceback.print_exc()

    def _pin_management_menu(self):
        """Меню управления PIN-кодом"""
        print("\n--- Управление PIN-кодом ---")
        print("1. Установить PIN")
        print("2. Изменить PIN")
        print("3. Проверить количество попыток")
        print("4. Назад")
        
        choice = input("\nВыберите действие (1-4): ").strip()
        
        if choice == '1':
            self.set_pin()
        elif choice == '2':
            self.change_pin()
        elif choice == '3':
            retries = self.get_pin_retries()
            if retries == -1:
                print("PIN не установлен")
            else:
                print(f"Осталось попыток: {retries}")
        elif choice == '4':
            return

    def _register_menu(self):
        """Меню регистрации учетной записи"""
        print("\n--- Регистрация новой учетной записи ---")
        rp_id = input("RP ID (Enter для значения по умолчанию): ").strip()
        rp_name = input("RP Name (Enter для значения по умолчанию): ").strip()
        user_name = input("Имя пользователя (Enter для значения по умолчанию): ").strip()
        
        rk_input = input("Resident Key? (y/n, Enter для yes): ").strip().lower()
        resident_key = rk_input != 'n'
        
        uv_input = input("User Verification (required/preferred/discouraged, Enter для discouraged): ").strip().lower()
        user_verification = uv_input if uv_input in ['required', 'preferred', 'discouraged'] else 'discouraged'
        
        self.register_credential(
            rp_id=rp_id or None,
            rp_name=rp_name or None,
            user_name=user_name or None,
            resident_key=resident_key,
            user_verification=user_verification
        )

    def _authenticate_menu(self):
        """Меню аутентификации"""
        print("\n--- Аутентификация ---")
        rp_id = input("RP ID (Enter для значения по умолчанию): ").strip()
        
        uv_input = input("User Verification (required/preferred/discouraged, Enter для discouraged): ").strip().lower()
        user_verification = uv_input if uv_input in ['required', 'preferred', 'discouraged'] else 'discouraged'
        
        self.authenticate(
            rp_id=rp_id or None,
            user_verification=user_verification
        )

    def _delete_menu(self):
        """Меню удаления учетной записи"""
        print("\n--- Удаление учетной записи ---")
        print("1. Удалить по индексу")
        print("2. Удалить по Credential ID")
        print("3. Назад")
        
        choice = input("\nВыберите действие (1-3): ").strip()
        
        if choice == '1':
            try:
                index = int(input("Введите индекс учетной записи: ").strip())
                self.delete_credential(index=index)
            except ValueError:
                print("Неверный индекс")
        elif choice == '2':
            cred_id = input("Введите Credential ID (hex): ").strip()
            self.delete_credential(credential_id=cred_id)
        elif choice == '3':
            return


def main():
    """Точка входа программы"""
    parser = argparse.ArgumentParser(
        description='Pico FIDO Key Manager - Управление ключом безопасности Pico FIDO (RP2040)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s --info                    Показать информацию об устройстве
  %(prog)s --list                    Список всех учетных записей
  %(prog)s --set-pin                 Установить PIN-код
  %(prog)s --register --rp test.com  Зарегистрировать новую учетную запись
  %(prog)s --interactive             Запустить интерактивный режим
        """
    )
    
    # Основные режимы работы
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('-i', '--info', action='store_true',
                           help='Показать информацию об устройстве')
    mode_group.add_argument('-l', '--list', action='store_true',
                           help='Список учетных записей')
    mode_group.add_argument('--set-pin', action='store_true',
                           help='Установить PIN-код')
    mode_group.add_argument('--change-pin', action='store_true',
                           help='Изменить PIN-код')
    mode_group.add_argument('--register', action='store_true',
                           help='Зарегистрировать новую учетную запись')
    mode_group.add_argument('--authenticate', action='store_true',
                           help='Аутентифицироваться')
    mode_group.add_argument('--delete', type=str, metavar='CRED_ID',
                           help='Удалить учетную запись по Credential ID')
    mode_group.add_argument('--reset', action='store_true',
                           help='Сбросить устройство к заводским настройкам')
    mode_group.add_argument('--export', type=str, nargs='?', const='auto', metavar='FILE',
                           help='Экспортировать учетные записи в JSON')
    mode_group.add_argument('--interactive', action='store_true',
                           help='Интерактивный режим управления')
    
    # Параметры
    parser.add_argument('--rp-id', type=str, default=None,
                       help='Relying Party ID')
    parser.add_argument('--rp-name', type=str, default=None,
                       help='Relying Party Name')
    parser.add_argument('--user-name', type=str, default=None,
                       help='Имя пользователя')
    parser.add_argument('--origin', type=str, default=None,
                       help='Origin для WebAuthn операций')
    parser.add_argument('--pin', type=str, default=None,
                       help='PIN-код (не рекомендуется использовать в CLI)')
    parser.add_argument('--no-resident-key', action='store_true',
                       help='Не создавать Resident Key при регистрации')
    parser.add_argument('--uv', type=str, choices=['required', 'preferred', 'discouraged'],
                       default='discouraged',
                       help='Требование пользовательской верификации')
    parser.add_argument('--force', action='store_true',
                       help='Пропустить подтверждения')
    parser.add_argument('--debug', action='store_true',
                       help='Режим отладки')
    
    args = parser.parse_args()
    
    if args.debug:
        os.environ['DEBUG'] = '1'
    
    try:
        # Инициализация менеджера
        manager = PicoFIDOManager(
            origin=args.origin,
            rp={'id': args.rp_id, 'name': args.rp_name} if args.rp_id or args.rp_name else None
        )
        
        if args.pin:
            PicoFIDOManager.DEFAULT_PIN = args.pin
        
        # Выполнение запрошенной операции
        if args.info:
            info = manager.get_info()
            print(json.dumps(info, indent=2, default=str))
        
        elif args.list:
            manager.list_credentials()
        
        elif args.set_pin:
            manager.set_pin()
        
        elif args.change_pin:
            manager.change_pin()
        
        elif args.register:
            manager.register_credential(
                rp_id=args.rp_id,
                rp_name=args.rp_name,
                user_name=args.user_name,
                resident_key=not args.no_resident_key,
                user_verification=args.uv
            )
        
        elif args.authenticate:
            manager.authenticate(
                rp_id=args.rp_id,
                user_verification=args.uv
            )
        
        elif args.delete:
            manager.delete_credential(credential_id=args.delete)
        
        elif args.reset:
            manager.reset_device(confirm=not args.force)
        
        elif args.export:
            filename = None if args.export == 'auto' else args.export
            manager.export_credentials(filename)
        
        elif args.interactive:
            manager.interactive_menu()
        
        else:
            # Если режим не указан, запускаем интерактивный
            manager.interactive_menu()
    
    except RuntimeError as e:
        print(f"\n✗ Ошибка: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nОперация прервана пользователем.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Неожиданная ошибка: {e}", file=sys.stderr)
        if os.environ.get('DEBUG'):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
