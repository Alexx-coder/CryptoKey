import secrets
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import base58
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time
import random
import string
import uuid
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

class MenuKey:
    def __init__(self):
        self.name = "CryptoKey"
        self.version = "v1.0"
        self.current_password = ""
        self.current_salt_length = 0
        self.current_iterations = 0
    
    def menu(self):
        print(f"Привет! Я {self.name}. Моя задача генерировать не повторяющиеся ключи или пароли\n")

        print("\nВнимание: Мы НЕ несем ответственность за:")
        print("- Небезопасность сгенерированных паролей")
        print("- Потерю данных из-за слабых ключей")
        print("- Любой ущерб от использования программы")
        accept_the_policy = input("Примите условие соглашения. Да (Согласен) и Нет (Не согласен): ").strip().lower()
        if accept_the_policy == "да":
            print("Вы приняли условие соглашения!")
        elif accept_the_policy == "нет":
            print("Вы не приняли условие соглашения!")
            time.sleep(2)
            sys.exit()
        else:
            print("Не понятен ваш ответ. Повторите попытку.")
            time.sleep(1)
            self.menu()


        print("Переход в отдел выбора функций...")
        time.sleep(2)

        while True:
            print("1 - Рандомные комбинации")
            print("2 - PIN-Код")
            print("3 - Простой хэш (Не безопасно!)")
            print("4 - Хэш со солью")
            print("5 - Fernet")
            print("6 - RSA")
            print("7 - Base64")
            print("8 - Base58")
            print("9 - AES (128/256)")
            print("10 - UUID")

            time.sleep(1)


            choice = input("Введите (0-10): ").strip()
            if choice == "1":
                print("Переход...")
                time.sleep(1)
                self.random_comb()
            elif choice == "2":
                print("Переход...")
                time.sleep(1)
                self.pincode()
            elif choice == "3":
                print("Переход...")
                time.sleep(1)
                self.just_hash()
            elif choice == "4":
                print("Переход...")
                time.sleep(1)
                self.hash_and_salt()
            elif choice == "5":
                print("Переход...")
                time.sleep(1)
                self.fernet_()
            elif choice == "6":
                print("Переход...")
                time.sleep(1)
                self.rsa_()
            elif choice == "7":
                print("Переход...")
                time.sleep(1)
                self.base64_()
            elif choice == "8":
                print("Переход...")
                time.sleep(1)
                self.base58_()
            elif choice == "9":
                print("Переход...")
                time.sleep(1)
                self.aes_()
            elif choice == "10":
                print("Переход...")
                time.sleep(1)
                self.uuid_()
            elif choice == "0":
                print("Выхожу...")
                time.sleep(1)
                sys.exit()
            else:
                print(f"Произошла ошибка: Функция {choice} не найдена. Повторите попытку.")
                continue

    def random_comb(self):
      print("Генерация рандомных комбинаций")

      while True:
        try:
            int_choice = int(input("Введите кол-во символов: "))
    
            if int_choice <= 0:
                print("Число должно быть положительным. Попробуйте снова")
                continue
    
            print("Начинаю генерацию...")
            time.sleep(1)
            chars = string.ascii_letters + string.digits 
            password = ''.join(random.choice(chars) for _ in range(int_choice))

            print("Ваш пароль сгенерирован:", password)

            while True:
                ещё = input("\nСгенерировать пароль ещё раз: (да/нет): ").strip().lower()
        
                if ещё == "да":
                    password = ''.join(random.choice(chars) for _ in range(int_choice))
                    print("Новый пароль сгенерирован:", password)
                    continue
                elif ещё == "нет":
                    print("Выхожу из данной функции")
                    break
                else:
                    print("Введите 'да' или 'нет'")
                    continue

            
            копировать = input("\nСкопировать последний пароль? (да/нет): ").strip().lower()
            if копировать == "да":
                try:
                    import pyperclip
                    pyperclip.copy(password)
                    print("Пароль скопирован в буфер обмена!")
                except ImportError:
                    print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                except Exception as RC:
                    print(f"Ошибка при копировании: {RC}")
            elif копировать == "нет":
                print("Пароль не скопирован")
            else:
                print("Введите 'да' или 'нет'")
    
            restart = input("\nХотите сгенерировать новый пароль с другим количеством символов? (да/нет): ").strip().lower()
            if restart != "да":
                print("Программа завершена.")
                break
                
        except ValueError:
            print("Неправильный формат. Введите целое число. Попробуйте снова")
            continue


    def pincode(self):
        print("Генерация PIN-Кодов")

        print("Начинаю генерацию...")
        time.sleep(1)
        while True:
          length = 9
          pin = ''.join(str(random.randint(0, 9)) for _ in range(length))

          print(f"Ваш сгенерированный PIN-Код: {pin}")

          while True:
              else_ = input("\nСгенерировать ещё раз (да/нет): ").strip().lower()
              if else_ == "да":
                  pin = ''.join(str(random.randint(0, 9)) for _ in range(length))
                  print(f"Ваш сгенерированный PIN-Код: {pin}")
              elif else_ == "нет":
                  print("Выхожу из данной функции")
                  break
              else:
                    print("Введите 'да' или 'нет'")
                    continue
               
            
          копировать = input("\nСкопировать последний пароль? (да/нет): ").strip().lower()
          if копировать == "да":
            try:
                import pyperclip
                pyperclip.copy(pin)
                print("Пароль скопирован в буфер обмена!")
            except ImportError:
                print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
            except Exception as PC:
                print(f"Ошибка при копировании: {PC}")
          elif копировать == "нет":
            print("Пароль не скопирован")
          else:
             print("Введите 'да' или 'нет'")
    
          restart = input("\nХотите сгенерировать новый пароль с другим количеством символов? (да/нет): ").strip().lower()
          if restart != "да":
            print("Программа завершена.")
            break
          
    def just_hash(self):
        print("Простой хэш (Не безопасно)")

        while True:
            print("1 - SHA-256 (64 символа)")
            print("2 - SHA-512 (128 символов)")  
            print("3 - Выход")
            choice = input("Введите (1-3): ").strip()
            if choice == "1":
                try:
                    lenght = int(input("Введите длину: ").strip())
                    
                    print("Начинаю генерацию...")
                    time.sleep(1)
                    hash_str = hashlib.sha256(str(lenght).encode()).hexdigest()
                    print(f"Ваш сгенерированный пароль: {hash_str}")

                    while True:
                        else_ = input("\nСгенерировать ещё раз (да/нет): ").strip().lower()
                        if else_ == "да":
                            hash_str = hashlib.sha256(str(lenght).encode()).hexdigest()
                            print(f"Ваш сгенерированный пароль: {hash_str}")
                    
                        elif else_ == "нет":
                            print("Выхожу из данной функции")
                            break
                        else:
                            print("Введите 'да' или 'нет'")
                            continue
                        
                    копировать = input("\nСкопировать последний пароль? (да/нет): ").strip().lower()
                    if копировать == "да":
                        try:
                           import pyperclip
                           pyperclip.copy(hash_str)
                           print("Пароль скопирован в буфер обмена!")
                        except ImportError:
                            print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                        except Exception as JH:
                            print(f"Ошибка при копировании: {JH}")
                    elif копировать == "нет":
                        print("Пароль не скопирован")
                    else:
                        print("Введите 'да' или 'нет'")
                        
                except ValueError:
                    print("Ошибка: Введите целое число для длины.")
                    continue
            
            elif choice == "2":
                try:
                    lenght = int(input("Введите длину: ").strip())
                    
                    print("Начинаю генерацию...")
                    time.sleep(1)
                    hash_str = hashlib.sha512(str(lenght).encode()).hexdigest()
                    print(f"Ваш сгенерированный пароль: {hash_str}")

                    while True:
                        else_ = input("\nСгенерировать ещё раз (да/нет): ").strip().lower()
                        if else_ == "да":
                            hash_str = hashlib.sha512(str(lenght).encode()).hexdigest()
                            print(f"Ваш сгенерированный пароль: {hash_str}")
                    
                        elif else_ == "нет":
                            print("Выхожу из данной функции")
                            break
                        else:
                            print("Введите 'да' или 'нет'")
                            continue
                        
                    копировать = input("\nСкопировать последний пароль? (да/нет): ").strip().lower()
                    if копировать == "да":
                        try:
                           import pyperclip
                           pyperclip.copy(hash_str)
                           print("Пароль скопиран в буфер обмена!")
                        except ImportError:
                            print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                        except Exception as JH:
                            print(f"Ошибка при копировании: {JH}")
                    elif копировать == "нет":
                        print("Пароль не скопирован")
                    else:
                        print("Введите 'да' или 'нет'")
                        
                except ValueError:
                    print("Ошибка: Введите целое число для длины.")
                    continue
            
            elif choice == "3":
                print("Выход из данной функции")
                time.sleep(1)
                return
                
            else:
                print("Не понятен ваш ответ. Попробуйте снова.")
                continue

    def hash_and_salt(self):
       print("Хэш со солью")

       while True:
          print("1 - Хэш со солью (Secrets)")
          print("2 - Хэш со солью (PBKDF2HMAC)")
          print("3 - Выход")

          choice_hash = input("Введите (1-3): ").strip()

          if choice_hash == "1":
             print("Хэш со солью (Secrets)")
             
             while True:
                 try:
                   lenght = int(input("Введите длину: ").strip())
                   if lenght <= 0:
                       print("Возникла ошибка: Неправильный формат. Попробуйте снова.")
                       continue
                   if lenght >= 0:
                       print("Начинаю генерацию...")
                       time.sleep(1)

                       salt = secrets.token_bytes(lenght)
                       salt_hex = salt.hex()

                       password = input("Введите пароль для хэширования: ").strip()

                       hash_result = hashlib.sha256(salt + password.encode()).hexdigest()

                       print(f"Соль (hex): {salt_hex}")
                       print(f"Хэш пароля с солью: {hash_result}")
                       print(f"Полная строка (соль:хэш): {salt_hex}:{hash_result}")

                       while True:
                         else_ = input("\nСгенерировать ещё раз (да/нет): ").strip().lower()
                         if else_ == "да":
                           salt = secrets.token_bytes(lenght)
                           salt_hex = salt.hex()
                           hash_result = hashlib.sha256(salt + password.encode()).hexdigest()
                           print(f"\nНовая соль (hex): {salt_hex}")
                           print(f"Новый хэш: {hash_result}")
                           print(f"Полная строка: {salt_hex}:{hash_result}")
                         elif else_ == "нет":
                           print("Выхожу из данной функции")
                           break
                         else:
                           print("Введите 'да' или 'нет'")
                           continue
                       
                   
                       copy_choice = input("\nЧто скопировать?\n1 - Только хэш\n2 - Только соль\n3 - Соль и хэш вместе\n4 - Не копировать\nВыберите (1-4): ").strip()
                   
                       if copy_choice == "1":
                        try:
                           import pyperclip
                           pyperclip.copy(hash_result)
                           print("Хэш скопирован в буфер обмена!")
                        except ImportError:
                           print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                        except Exception as HS:
                           print(f"Ошибка при копировании: {HS}")


                       elif copy_choice == "2":
                         try:
                           import pyperclip
                           pyperclip.copy(salt_hex)
                           print("Соль скопирована в буфер обмена!")
                         except ImportError:
                           print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                         except Exception as HS:
                           print(f"Ошибка при копировании: {HS}")
                   elif copy_choice == "3":
                       try:
                           import pyperclip
                           pyperclip.copy(f"{salt_hex}:{hash_result}")
                           print("Соль и хэш скопированы в буфер обмена!")
                       except ImportError:
                           print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                       except Exception as HS:
                           print(f"Ошибка при копировании: {HS}")
                   elif copy_choice == "4":
                       print("Ничего не копирую")
                   else:
                       print("Неверный выбор")
            

                   continue_choice = input("\nХотите продолжить с другой длиной соли? (да/нет): ").strip().lower()
                   if continue_choice != "да":
                       break
                       
                 except ValueError:
                    print("Ошибка: Введите целое число для длины.")
                    continue
                 except Exception as HE:
                    print(f"Произошла ошибка: {HE}")
                    continue
                 
          elif choice_hash == "2":
              print("Хэш со солью (PBKDF2HMAC)")

              while True:
                try:
                    self.current_password = input("Введите пароль для хэширования: ").strip()

                    self.current_salt_length = int(input("Введите длину соли (байты, 16+ рекомендуется): ").strip())
                    if self.current_salt_length <= 16:
                        print("Возникла ошибка: Малое кол-во символов. Минимум 16 символов. Попробуйте снова.")
                        continue

                    self.current_iterations = int(input("Введите количество итераций (100000+ рекомендуется): ").strip())
                    if self.current_iterations <= 100000:
                        print("Возникла ошибка: Малое кол-во символов. Минимум 100000 символов. Попробуйте снова.")
                        continue

                    print("Начинаю генерацию...")
                    time.sleep(1)

                    salt = secrets.token_bytes(self.current_salt_length)
                   
                   # PBKDF2 хэширование
                    kdf = PBKDF2HMAC(
                       algorithm=hashes.SHA256(),
                       length=32,
                       salt=salt,
                       iterations=self.current_iterations
                    )
                   
                    hash_bytes = kdf.derive(self.current_password.encode())
                    hash_hex = hash_bytes.hex()
                    salt_hex = salt.hex()
                   
                    print(f"Соль (hex): {salt_hex}")
                    print(f"Длина соли: {self.current_salt_length} байт")
                    print(f"Итерации: {self.current_iterations}")
                    print(f"Хэш PBKDF2: {hash_hex}")
                    print(f"Полная строка: {salt_hex}:{hash_hex}")

                    while True:
                       else_ = input("\nСгенерировать ещё раз (да/нет): ").strip().lower()
                       if else_ == "да":
                           # Новая соль, тот же пароль и параметры
                           salt = secrets.token_bytes(self.current_salt_length)
                           salt_hex = salt.hex()
                           kdf = PBKDF2HMAC(
                               algorithm=hashes.SHA256(),
                               length=32,
                               salt=salt,
                               iterations=self.current_iterations
                           )
                           hash_bytes = kdf.derive(self.current_password.encode())
                           hash_hex = hash_bytes.hex()
                           print(f"\nНовая соль (hex): {salt_hex}")
                           print(f"Новый хэш PBKDF2: {hash_hex}")
                           print(f"Полная строка: {salt_hex}:{hash_hex}")
                       elif else_ == "нет":
                           print("Выхожу из данной функции")
                           break
                       else:
                           print("Введите 'да' или 'нет'")
                           continue
                       
                
                    copy_choice = input("\nЧто скопировать?\n1 - Только хэш\n2 - Только соль\n3 - Соль и хэш вместе\n4 - Не копировать\nВыберите (1-4): ").strip()
                   
                    if copy_choice == "1":
                        try:
                           import pyperclip
                           pyperclip.copy(hash_hex)
                           print("Хэш скопирован в буфер обмена!")
                        except ImportError:
                           print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                        except Exception as HS:
                           print(f"Ошибка при копировании: {HS}")
                    elif copy_choice == "2":
                        try:
                           import pyperclip
                           pyperclip.copy(salt_hex)
                           print("Соль скопирована в буфер обмена!")
                        except ImportError:
                           print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                        except Exception as HS:
                           print(f"Ошибка при копировании: {HS}")
                    elif copy_choice == "3":
                        try:
                           import pyperclip
                           pyperclip.copy(f"{salt_hex}:{hash_hex}")
                           print("Соль и хэш скопированы в буфер обмена!")
                        except ImportError:
                           print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                        except Exception as HS:
                           print(f"Ошибка при копировании: {HS}")
                    elif copy_choice == "4":
                        print("Ничего не копирую")
                    else:
                        print("Неверный выбор")
                       
                   # Продолжить или выйти
                    continue_choice = input("\nХотите продолжить с другими параметрами? (да/нет): ").strip().lower()
                    if continue_choice != "да":
                       break
                       
                except ValueError:
                    print("Ошибка: Введите целое число для длины или итераций.")
                    continue
                except Exception as HSE:
                    print(f"Произошла ошибка: {HSE}")
                    continue

          elif choice_hash == "3":
             print("Выход из данной функции")
             time.sleep(1)
             return
             
          else:
             print("Не понятен ваш ответ. Попробуйте снова.")
             continue
          

    def fernet_(self):
        print("Fernet")

        while True:
            print("1 - Генерация ключа")
            print("2 - Зашифровать сообщение")
            print("3 - Расшифровать сообщение")
            print("4 - Выход")

            choice_fernet = input("Введите (1-4): ").strip()
            if choice_fernet == "1":
                print("Начинаю генерацию...")
                time.sleep(1)

                key = Fernet.generate_key()
                key_str = key.decode('utf-8')

                print(f"Ваш ключ Fernet: {key_str}")
                print(f"Длина ключа: {len(key_str)} символов")
                
                while True:
                    else_ = input("\nСгенерировать ещё раз (да/нет): ").strip().lower()
                    if else_ == "да":
                        key = Fernet.generate_key()
                        key_str = key.decode('utf-8')
                        print(f"\nНовый ключ Fernet: {key_str}")
                    elif else_ == "нет":
                        print("Выхожу из генерации ключей")
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
                копировать = input("\nСкопировать ключ? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(key_str)
                        print("Ключ скопирован в буфер обмена!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as FE:
                        print(f"Ошибка при копировании: {FE}")
                elif копировать == "нет":
                    print("Ключ не скопирован")
                else:
                    print("Введите 'да' или 'нет'")


            elif choice_fernet == "2":
                print("Зашифровать сообщение")

                while True:
                    try:
                        key_input = input("Введите ключ Fernet: ").strip()
                        if not key_input:
                            print("Ключ Fernet не должен быть пустым. Повторите попытку")
                            continue

                        fernet = Fernet(key_input.encode())

                        message = input("Введите сообщение для шифрования: ").strip()
                        if not message:
                            print("Сообщение не может быть пустым")
                            continue
                        
                        print("Шифрую...")
                        time.sleep(1)

                        encrypted = fernet.encrypt(message.encode())
                        encrypted_str = encrypted.decode('utf-8')
                        
                        print(f"Зашифрованное сообщение: {encrypted_str}")

                        while True:
                            else_ = input("\nЗашифровать ещё одно сообщение этим же ключом? (да/нет): ").strip().lower()
                            if else_ == "да":
                                message = input("Введите новое сообщение: ").strip()
                                encrypted = fernet.encrypt(message.encode())
                                encrypted_str = encrypted.decode('utf-8')
                                print(f"Зашифрованное сообщение: {encrypted_str}")
                            elif else_ == "нет":
                                break
                            else:
                                print("Введите 'да' или 'нет'")
                                continue
                        
                        # Копирование зашифрованного
                        копировать = input("\nСкопировать зашифрованное сообщение? (да/нет): ").strip().lower()
                        if копировать == "да":
                            try:
                                import pyperclip
                                pyperclip.copy(encrypted_str)
                                print("Зашифрованное сообщение скопировано!")
                            except ImportError:
                                print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                            except Exception as FE:
                                print(f"Ошибка при копировании: {FE}")
                        elif копировать == "нет":
                            print("Сообщение не скопировано")
                        else:
                            print("Введите 'да' или 'нет'")
                        
                        # Продолжить с другим ключом?
                        продолжить = input("\nХотите зашифровать другое сообщение с другим ключом? (да/нет): ").strip().lower()
                        if продолжить != "да":
                            break
                            
                    except Exception as FEEE:
                        print(f"Ошибка: {FEEE}. Проверьте ключ и попробуйте снова.")
                        continue



            elif choice_fernet == "3":
                print("Расшифровать сообщение")

                while True:
                    try:
                        key_input = input("Введите ключ Fernet: ").strip()
                        if not key_input:
                            print("Ключ не может быть пустым")
                            continue
                        
                        # Создаем объект Fernet
                        fernet = Fernet(key_input.encode())
                        
                        # Ввод зашифрованного сообщения
                        encrypted_input = input("Введите зашифрованное сообщение: ").strip()
                        if not encrypted_input:
                            print("Сообщение не может быть пустым")
                            continue
                        
                        print("Расшифровываю...")
                        time.sleep(1)
                        
                        # Дешифрование
                        decrypted = fernet.decrypt(encrypted_input.encode())
                        decrypted_str = decrypted.decode('utf-8')
                        
                        print(f"Расшифрованное сообщение: {decrypted_str}")
                        
                        # Копирование расшифрованного
                        копировать = input("\nСкопировать расшифрованное сообщение? (да/нет): ").strip().lower()
                        if копировать == "да":
                            try:
                                import pyperclip
                                pyperclip.copy(decrypted_str)
                                print("Расшифрованное сообщение скопировано!")
                            except ImportError:
                                print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                            except Exception as FE:
                                print(f"Ошибка при копировании: {FE}")
                        elif копировать == "нет":
                            print("Сообщение не скопировано")
                        else:
                            print("Введите 'да' или 'нет'")
                        
                        # Продолжить с другим сообщением?
                        продолжить = input("\nХотите расшифровать другое сообщение? (да/нет): ").strip().lower()
                        if продолжить != "да":
                            break
                            
                    except Exception as FEE:
                        print(f"Ошибка: {FEE}. Неверный ключ или поврежденное сообщение.")
                        continue
            
            elif choice_fernet == "4":
                print("Выход из функции Fernet")
                time.sleep(1)
                return
            
            else:
                print("Не понятен ваш ответ. Попробуйте снова.")
                continue



    def rsa_(self):
        print("RSA")

        while True:
            print("1 - Генерация ключей")
            print("2 - Шифрование")
            print("3 - Дешифрование")
            print("4 - Выход")
            
            choice = input("Введите (1-4): ").strip()
            
            if choice == "1":
                print("Начинаю генерацию...")
                time.sleep(1)
                
                # Генерация приватного ключа
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                # Получение публичного ключа
                public_key = private_key.public_key()
                
                # Сериализация ключей
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                print(f"Приватный ключ сгенерирован: {private_pem}")
                print(f"Публичный ключ сгенерирован: {public_pem}")

                while True:
                    else_ = input("\nСгенерировать ещё раз (да/нет): ").strip().lower()
                    if else_ == "да":
                        private_key = rsa.generate_private_key(
                            public_exponent=65537,
                            key_size=2048
                        )
                        public_key = private_key.public_key()
                        
                        private_pem = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ).decode('utf-8')
                        
                        public_pem = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).decode('utf-8')
                        
                        print(f"\nНовая пара ключей сгенерирована!")
                        print(f"Приватный ключ: {private_pem}")
                        print(f"Публичный ключ: {public_pem}")
                    elif else_ == "нет":
                        print("Выхожу из генерации ключей")
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
                # Копирование
                копировать = input("\nСкопировать публичный ключ? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(public_pem)
                        print("Публичный ключ скопирован!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as RS:
                        print(f"Ошибка при копировании: {RS}")
                elif копировать == "нет":
                    print("Ключ не скопирован")
                else:
                    print("Введите 'да' или 'нет'")
            
            elif choice == "2":
                print("Шифрование публичным ключом")
                
                try:
                    # Ввод публичного ключа
                    public_pem = input("Введите публичный ключ: ").strip()
                    
                    # Ввод сообщения
                    message = input("Введите сообщение: ").strip()
                    
                    print("Шифрую...")
                    time.sleep(1)
                    
                    # Загрузка ключа
                    public_key = serialization.load_pem_public_key(
                        public_pem.encode('utf-8')
                    )
                    
                    # Шифрование
                    encrypted = public_key.encrypt(
                        message.encode('utf-8'),
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Base64 кодирование
                    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
                    
                    print(f"Зашифрованное сообщение: {encrypted_b64}")

                    while True:
                        else_ = input("\nЗашифровать ещё одно сообщение? (да/нет): ").strip().lower()
                        if else_ == "да":
                            message = input("Введите новое сообщение: ").strip()
                            encrypted = public_key.encrypt(
                                message.encode('utf-8'),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
                            print(f"Зашифрованное сообщение: {encrypted_b64}")
                        elif else_ == "нет":
                            break
                        else:
                            print("Введите 'да' или 'нет'")
                            continue
                    
                    # Копирование
                    копировать = input("\nСкопировать зашифрованное сообщение? (да/нет): ").strip().lower()
                    if копировать == "да":
                        try:
                            import pyperclip
                            pyperclip.copy(encrypted_b64)
                            print("Зашифрованное сообщение скопировано!")
                        except ImportError:
                            print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                        except Exception as RS:
                            print(f"Ошибка при копировании: {RS}")
                    elif копировать == "нет":
                        print("Сообщение не скопировано")
                    else:
                        print("Введите 'да' или 'нет'")
                        
                except Exception as RSAE:
                    print(f"Ошибка: {RSAE}")
                    continue
            
            elif choice == "3":
                print("Дешифрование приватным ключом")
                
                try:
                    # Ввод приватного ключа
                    private_pem = input("Введите приватный ключ: ").strip()
                    
                    # Ввод зашифрованного сообщения
                    encrypted_b64 = input("Введите зашифрованное сообщение: ").strip()
                    
                    print("Дешифрую...")
                    time.sleep(1)
                    
                    # Загрузка ключа
                    private_key = serialization.load_pem_private_key(
                        private_pem.encode('utf-8'),
                        password=None
                    )
                    
                    # Декодирование из base64
                    encrypted = base64.b64decode(encrypted_b64)
                    
                    # Дешифрование
                    decrypted = private_key.decrypt(
                        encrypted,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    decrypted_str = decrypted.decode('utf-8')
                    
                    print(f"Расшифрованное сообщение: {decrypted_str}")

                    while True:
                        else_ = input("\nДешифровать ещё одно сообщение? (да/нет): ").strip().lower()
                        if else_ == "да":
                            encrypted_b64 = input("Введите зашифрованное сообщение: ").strip()
                            encrypted = base64.b64decode(encrypted_b64)
                            decrypted = private_key.decrypt(
                                encrypted,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            decrypted_str = decrypted.decode('utf-8')
                            print(f"Расшифрованное сообщение: {decrypted_str}")
                        elif else_ == "нет":
                            break
                        else:
                            print("Введите 'да' или 'нет'")
                            continue
                    
                    # Копирование
                    копировать = input("\nСкопировать расшифрованное сообщение? (да/нет): ").strip().lower()
                    if копировать == "да":
                        try:
                            import pyperclip
                            pyperclip.copy(decrypted_str)
                            print("Расшифрованное сообщение скопировано!")
                        except ImportError:
                            print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                        except Exception as RS:
                            print(f"Ошибка при копировании: {RS}")
                    elif копировать == "нет":
                        print("Сообщение не скопировано")
                    else:
                        print("Введите 'да' или 'нет'")
                        
                except Exception as RSAE:
                    print(f"Ошибка: {RSAE}")
                    continue
            
            elif choice == "4":
                print("Выход из функции RSA")
                time.sleep(1)
                return
            
            else:
                print("Не понятен ваш ответ. Попробуйте снова.")
                continue


    def base64_(self):
        print("Base64 кодирование")

        while True:
            print("\n1 - Кодировать в Base64")
            print("2 - Декодировать из Base64")
            print("3 - Выход")
            
            choice = input("Введите (1-3): ").strip()
            
            if choice == "1":
                # Ввод текста для кодирования
                text_to_encode = input("Введите текст для кодирования: ").strip()
                
                if not text_to_encode:
                    print("Текст не может быть пустым")
                    continue
                
                print("Кодирую...")
                time.sleep(1)
                
                # Кодирование в Base64
                encoded_bytes = base64.b64encode(text_to_encode.encode('utf-8'))
                encoded_text = encoded_bytes.decode('utf-8')
                
                print(f"Base64 результат: {encoded_text}")

                while True:
                    else_ = input("\nЗакодировать ещё раз? (да/нет): ").strip().lower()
                    if else_ == "да":
                        text_to_encode = input("Введите новый текст: ").strip()
                        encoded_bytes = base64.b64encode(text_to_encode.encode('utf-8'))
                        encoded_text = encoded_bytes.decode('utf-8')
                        print(f"Base64 результат: {encoded_text}")
                    elif else_ == "нет":
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
                # Копирование
                копировать = input("\nСкопировать результат? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(encoded_text)
                        print("Результат скопирован!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as B64:
                        print(f"Ошибка при копировании: {B64}")
                elif копировать == "нет":
                    print("Результат не скопирован")
                else:
                    print("Введите 'да' или 'нет'")
            
            elif choice == "2":
                # Ввод Base64 для декодирования
                base64_text = input("Введите Base64 для декодирования: ").strip()
                
                if not base64_text:
                    print("Текст не может быть пустым")
                    continue
                
                print("Декодирую...")
                time.sleep(1)
                
                try:
                    # Декодирование из Base64
                    decoded_bytes = base64.b64decode(base64_text)
                    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                    
                    print(f"Декодированный текст: {decoded_text}")
                except Exception as B64E:
                    print(f"Ошибка: Неверный Base64 формат. {B64E}")
                    continue

                while True:
                    else_ = input("\nДекодировать ещё раз? (да/нет): ").strip().lower()
                    if else_ == "да":
                        base64_text = input("Введите новый Base64: ").strip()
                        try:
                            decoded_bytes = base64.b64decode(base64_text)
                            decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                            print(f"Декодированный текст: {decoded_text}")
                        except Exception as e:
                            print(f"Ошибка: {e}")
                            continue
                    elif else_ == "нет":
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
                # Копирование
                копировать = input("\nСкопировать результат? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(decoded_text)
                        print("Результат скопирован!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as B64:
                        print(f"Ошибка при копировании: {B64}")
                elif копировать == "нет":
                    print("Результат не скопирован")
                else:
                    print("Введите 'да' или 'нет'")
            
            elif choice == "3":
                print("Выход из функции Base64")
                time.sleep(1)
                return
            
            else:
                print("Не понятен ваш ответ. Попробуйте снова.")
                continue



    def base58_(self):
        print("Base58 кодирование")

        while True:
            print("\n1 - Кодировать в Base58")
            print("2 - Декодировать из Base58")
            print("3 - Выход")
            
            choice = input("Введите (1-3): ").strip()
            
            if choice == "1":
                # Ввод текста для кодирования
                text_to_encode = input("Введите текст для кодирования: ").strip()
                
                if not text_to_encode:
                    print("Текст не может быть пустым")
                    continue
                
                print("Кодирую...")
                time.sleep(1)
                
                # Кодирование в Base58
                encoded_bytes = text_to_encode.encode('utf-8')
                encoded_text = base58.b58encode(encoded_bytes).decode('utf-8')
                
                print(f"Base58 результат: {encoded_text}")

                while True:
                    else_ = input("\nЗакодировать ещё раз? (да/нет): ").strip().lower()
                    if else_ == "да":
                        text_to_encode = input("Введите новый текст: ").strip()
                        encoded_bytes = text_to_encode.encode('utf-8')
                        encoded_text = base58.b58encode(encoded_bytes).decode('utf-8')
                        print(f"Base58 результат: {encoded_text}")
                    elif else_ == "нет":
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
                # Копирование
                копировать = input("\nСкопировать результат? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(encoded_text)
                        print("Результат скопирован!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as B58:
                        print(f"Ошибка при копировании: {B58}")
                elif копировать == "нет":
                    print("Результат не скопирован")
                else:
                    print("Введите 'да' или 'нет'")
            
            elif choice == "2":
                # Ввод Base58 для декодирования
                base58_text = input("Введите Base58 для декодирования: ").strip()
                
                if not base58_text:
                    print("Текст не может быть пустым")
                    continue
                
                print("Декодирую...")
                time.sleep(1)
                
                try:
                    # Декодирование из Base58
                    decoded_bytes = base58.b58decode(base58_text)
                    decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                    
                    print(f"Декодированный текст: {decoded_text}")
                except Exception as B58E:
                    print(f"Ошибка: Неверный Base58 формат. {B58E}")
                    continue

                while True:
                    else_ = input("\nДекодировать ещё раз? (да/нет): ").strip().lower()
                    if else_ == "да":
                        base58_text = input("Введите новый Base58: ").strip()
                        try:
                            decoded_bytes = base58.b58decode(base58_text)
                            decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                            print(f"Декодированный текст: {decoded_text}")
                        except Exception as B58E:
                            print(f"Ошибка: {B58E}")
                            continue
                    elif else_ == "нет":
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
                # Копирование
                копировать = input("\nСкопировать результат? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(decoded_text)
                        print("Результат скопирован!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as B58:
                        print(f"Ошибка при копировании: {B58}")
                elif копировать == "нет":
                    print("Результат не скопирован")
                else:
                    print("Введите 'да' или 'нет'")
            
            elif choice == "3":
                print("Выход из функции Base58")
                time.sleep(1)
                return
            
            else:
                print("Не понятен ваш ответ. Попробуйте снова.")
                continue

    
    def aes_(self):
        print("AES шифрование")

        while True:
            print("\n1 - Сгенерировать ключ")
            print("2 - Зашифровать сообщение")
            print("3 - Расшифровать сообщение")
            print("4 - Выход")
            
            choice = input("Введите (1-4): ").strip()
            
            if choice == "1":
                print("Выберите размер ключа:")
                print("1 - AES-128 (16 байт/128 бит)")
                print("2 - AES-256 (32 байта/256 бит)")
                
                
                size_choice = input("Введите (1-3): ").strip()
                
                if size_choice == "1":
                    key_size = 16
                    aes_name = "AES-128"
                elif size_choice == "2":
                    key_size = 32
                    aes_name = "AES-256"
                else:
                    print("Неверный выбор")
                    continue
                
                print(f"Генерация {aes_name} ключа...")
                time.sleep(1)
        
                try:
                    from Crypto import Random
                except ImportError:
                    print("Ошибка: Установите pycryptodome: pip install pycryptodome")
                    continue
                
                # Генерация ключа
                aes_key = Random.get_random_bytes(key_size)
                aes_key_hex = aes_key.hex()
                
                print(f"{aes_name} ключ ({key_size} байт):")
                print(f"HEX: {aes_key_hex}")
                print(f"Base64: {base64.b64encode(aes_key).decode()}")
                
                while True:
                    else_ = input("\nСгенерировать ещё ключ? (да/нет): ").strip().lower()
                    if else_ == "да":
                        aes_key = Random.get_random_bytes(key_size)
                        aes_key_hex = aes_key.hex()
                        print(f"\nНовый {aes_name} ключ HEX: {aes_key_hex}")
                    elif else_ == "нет":
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
                # Копирование
                копировать = input("\nСкопировать ключ? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(aes_key_hex)
                        print("Ключ скопирован!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as AES:
                        print(f"Ошибка при копировании: {AES}")
                elif копировать == "нет":
                    print("Ключ не скопирован")
                else:
                    print("Введите 'да' или 'нет'")
            
            elif choice == "2":
                print("Зашифровать сообщение AES")
                
                try:
                    from Crypto.Cipher import AES
                    from Crypto.Util.Padding import pad
                    from Crypto import Random
                    
                    # Ввод размера ключа
                    print("Какой размер ключа используете?")
                    print("1 - AES-128 (32 hex символа)")
                    print("2 - AES-256 (64 hex символа)")
                    print("3 - AES-512 (128 hex символов)")
                    
                    size_choice = input("Введите (1-3): ").strip()
                    
                    if size_choice == "1":
                        hex_length = 32
                        key_size = 16
                    elif size_choice == "2":
                        hex_length = 64
                        key_size = 32
                    elif size_choice == "3":
                        hex_length = 128
                        key_size = 64
                    else:
                        print("Неверный выбор")
                        continue
                    
                    # Ввод ключа
                    key_input = input(f"Введите AES ключ ({hex_length} hex символов): ").strip()
                    
                    if len(key_input) != hex_length:
                        print(f"Ошибка: Ключ должен быть {hex_length} hex символов")
                        continue
                    
                    # Конвертация hex в байты
                    aes_key = bytes.fromhex(key_input)
                    
                    # Ввод сообщения
                    message = input("Введите сообщение для шифрования: ").strip()
                    
                    if not message:
                        print("Сообщение не может быть пустым")
                        continue
                    
                    print("Шифрую...")
                    time.sleep(1)
                    
                    # Генерация случайного IV
                    iv = Random.get_random_bytes(16)
                    
                    # Создание AES шифра
                    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    
                    # Шифрование
                    padded_message = pad(message.encode('utf-8'), AES.block_size)
                    encrypted = cipher.encrypt(padded_message)
                    
                    # Комбинируем IV + зашифрованные данные
                    result = iv + encrypted
                    result_b64 = base64.b64encode(result).decode()
                    
                    print(f"IV (первые 16 байт): {iv.hex()}")
                    print(f"Зашифрованное сообщение (Base64): {result_b64}")
                    
                    while True:
                        else_ = input("\nЗашифровать ещё сообщение этим ключом? (да/нет): ").strip().lower()
                        if else_ == "да":
                            message = input("Введите новое сообщение: ").strip()
                            iv = Random.get_random_bytes(16)
                            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                            padded_message = pad(message.encode('utf-8'), AES.block_size)
                            encrypted = cipher.encrypt(padded_message)
                            result = iv + encrypted
                            result_b64 = base64.b64encode(result).decode()
                            print(f"Новое зашифрованное сообщение: {result_b64}")
                        elif else_ == "нет":
                            break
                        else:
                            print("Введите 'да' или 'нет'")
                            continue
                    
                    # Копирование
                    копировать = input("\nСкопировать зашифрованное сообщение? (да/нет): ").strip().lower()
                    if копировать == "да":
                        try:
                            import pyperclip
                            pyperclip.copy(result_b64)
                            print("Сообщение скопировано!")
                        except ImportError:
                            print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                        except Exception as AES:
                            print(f"Ошибка при копировании: {AES}")
                    elif копировать == "нет":
                        print("Сообщение не скопировано")
                    else:
                        print("Введите 'да' или 'нет'")
                        
                except ImportError:
                    print("Ошибка: Установите pycryptodome: pip install pycryptodome")
                    continue
                except Exception as AESE:
                    print(f"Ошибка: {AESE}")
                    continue
            
            
            elif choice == "4":
                print("Выход из функции AES")
                time.sleep(1)
                return
            
            else:
                print("Не понятен ваш ответ. Попробуйте снова.")
                continue



    def uuid_(self):
        print("UUID генерация")

        while True:
            print("\n1 - UUID4 (случайный)")
            print("2 - UUID1 (на основе времени)")
            print("3 - UUID5 (на основе имени)")
            print("4 - Выход")
            
            choice = input("Введите (1-4): ").strip()
            
            if choice == "1":
                print("Генерация случайного UUID4...")
                time.sleep(1)
                
        
                uuid_result = uuid.uuid4()
                uuid_str = str(uuid_result)
                
                print(f"UUID4: {uuid_str}")
                print(f"HEX: {uuid_result.hex}")
                print(f"Int: {uuid_result.int}")

                while True:
                    else_ = input("\nСгенерировать ещё UUID4? (да/нет): ").strip().lower()
                    if else_ == "да":
                        uuid_result = uuid.uuid4()
                        uuid_str = str(uuid_result)
                        print(f"\nНовый UUID4: {uuid_str}")
                    elif else_ == "нет":
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
            
                копировать = input("\nСкопировать UUID? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(uuid_str)
                        print("UUID скопирован!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as UD:
                        print(f"Ошибка при копировании: {UD}")
                elif копировать == "нет":
                    print("UUID не скопирован")
                else:
                    print("Введите 'да' или 'нет'")
            
            elif choice == "2":
                print("Генерация UUID1 (на основе времени)...")
                time.sleep(1)
                
        
                uuid_result = uuid.uuid1()
                uuid_str = str(uuid_result)
                
                print(f"UUID1: {uuid_str}")
                print(f"Временная метка: {uuid_result.time}")
                print(f"Узел (MAC): {uuid_result.node}")
                
                while True:
                    else_ = input("\nСгенерировать ещё UUID1? (да/нет): ").strip().lower()
                    if else_ == "да":
                        uuid_result = uuid.uuid1()
                        uuid_str = str(uuid_result)
                        print(f"\nНовый UUID1: {uuid_str}")
                    elif else_ == "нет":
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
                копировать = input("\nСкопировать UUID? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(uuid_str)
                        print("UUID скопирован!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as UD:
                        print(f"Ошибка при копировании: {UD}")
                elif копировать == "нет":
                    print("UUID не скопирован")
                else:
                    print("Введите 'да' или 'нет'")
            
            elif choice == "3":
                print("UUID5 (на основе имени)")
                
                namespace_input = input("Введите пространство имён (например, URL): ").strip()
                name_input = input("Введите имя для хэширования: ").strip()
                
                if not namespace_input or not name_input:
                    print("Оба поля должны быть заполнены")
                    continue
                
                print("Генерирую UUID5...")
                time.sleep(1)
                
               
                try:
                    namespace_uuid = uuid.UUID(namespace_input)
                except ValueError:
                    if namespace_input.lower() == 'dns':
                        namespace_uuid = uuid.NAMESPACE_DNS
                    elif namespace_input.lower() == 'url':
                        namespace_uuid = uuid.NAMESPACE_URL
                    elif namespace_input.lower() == 'oid':
                        namespace_uuid = uuid.NAMESPACE_OID
                    elif namespace_input.lower() == 'x500':
                        namespace_uuid = uuid.NAMESPACE_X500
                    else:
                        try:
                            namespace_uuid = uuid.UUID(namespace_input)
                        except:
                            print("Неверный namespace. Используйте: dns, url, oid, x500 или UUID")
                            continue
                

                uuid_result = uuid.uuid5(namespace_uuid, name_input)
                uuid_str = str(uuid_result)
                
                print(f"Namespace: {namespace_uuid}")
                print(f"Имя: {name_input}")
                print(f"UUID5: {uuid_str}")
                print(f"HEX: {uuid_result.hex}")
                
                while True:
                    else_ = input("\nСгенерировать ещё UUID5 с другим именем? (да/нет): ").strip().lower()
                    if else_ == "да":
                        name_input = input("Введите новое имя: ").strip()
                        uuid_result = uuid.uuid5(namespace_uuid, name_input)
                        uuid_str = str(uuid_result)
                        print(f"\nНовый UUID5: {uuid_str}")
                    elif else_ == "нет":
                        break
                    else:
                        print("Введите 'да' или 'нет'")
                        continue
                
                # Копирование
                копировать = input("\nСкопировать UUID? (да/нет): ").strip().lower()
                if копировать == "да":
                    try:
                        import pyperclip
                        pyperclip.copy(uuid_str)
                        print("UUID скопирован!")
                    except ImportError:
                        print("Не удалось скопировать. Установите pyperclip: pip install pyperclip")
                    except Exception as UD:
                        print(f"Ошибка при копировании: {UD}")
                elif копировать == "нет":
                    print("UUID не скопирован")
                else:
                    print("Введите 'да' или 'нет'")
            
            elif choice == "4":
                print("Выход из функции UUID")
                time.sleep(1)
                return
            
            else:
                print("Не понятен ваш ответ. Попробуйте снова.")
                continue



# Запуск программы
if __name__ == "__main__":
    try:
      print(f"Добро пожаловать в CryptoKey")

      app = MenuKey()
      app.menu()

    except KeyboardInterrupt:
        print("\nБот остановлен пользователем")
    except Exception as CV:
        print(f"\n Возникла критическая ошибка: {CV}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nCryptoKey завершает работу! До свидания!")