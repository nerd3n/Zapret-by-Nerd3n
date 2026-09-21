# Происхождение компонентов

Папка `bundle` содержит неизменённые исполняемые файлы и стратегии из
[Flowseal/zapret-discord-youtube, ревизия 865da4f4c3659523bf79bc6edf0446e7d7969614](https://github.com/Flowseal/zapret-discord-youtube/tree/865da4f4c3659523bf79bc6edf0446e7d7969614).
Python-приложение импортирует аргументы из BAT как данные. BAT и `service.bat`
при этом не выполняются. Шесть вариантов с ID `experiment-…` добавлены этим UI;
они не являются стратегиями, проверенными или рекомендованными авторами upstream.

## Авторы, исходники и лицензии

| Компонент | Происхождение и условия |
| --- | --- |
| Скрипты Flowseal и zapret/winws | MIT; bol-van и Flowseal. Оригинальный файл сохранён как `bundle/LICENSE.txt`. [Лицензия сборки](https://github.com/Flowseal/zapret-discord-youtube/blob/865da4f4c3659523bf79bc6edf0446e7d7969614/LICENSE.txt). |
| Движок `winws.exe` | В бинарнике найдены строки `v72.9` и `c849e55ef0f1c244206f5a05ff7b1ab41a3824ee`. [Исходники этой ревизии](https://github.com/bol-van/zapret/tree/c849e55ef0f1c244206f5a05ff7b1ab41a3824ee), [MIT](https://github.com/bol-van/zapret/blob/c849e55ef0f1c244206f5a05ff7b1ab41a3824ee/docs/LICENSE.txt), [официальная сборка Windows](https://github.com/bol-van/zapret-win-bundle). Строки версии не заменяют воспроизводимую проверку сборки. |
| `WinDivert.dll`, `WinDivert64.sys` | Basil; LGPLv3 либо GPLv2 по выбору получателя. [Исходники](https://github.com/basil00/WinDivert), [полный текст лицензий](https://github.com/basil00/WinDivert/blob/v2.2.2/LICENSE). Ресурс драйвера сообщает версию 2.2; точная привязка бинарника к исходному коммиту не устанавливалась. |
| `cygwin1.dll` | Cygwin Authors, версия ресурса 3.4.10. LGPLv3-or-later и описанное авторами исключение для связывания. [Условия](https://cygwin.com/licensing.html), [получение исходников](https://cygwin.com/git.html). |
| zlib внутри `winws.exe` | В бинарнике присутствует идентификатор zlib 1.3.1; Jean-loup Gailly и Mark Adler. [Исходники](https://github.com/madler/zlib/tree/v1.3.1), [лицензия zlib](https://zlib.net/zlib_license.html). |

MIT сборки не заменяет лицензии библиотек и драйвера. Эта поставка сохраняет
upstream-уведомления и ссылки на исходники; комплект полных соответствующих
исходников зависимостей и аудит условий публичного распространения не выполнялись.

## SHA-256 поставленных файлов

Хеши вычислены 21 сентября 2026 года и совпали с локальной копией указанной
ревизии Flowseal. Они идентифицируют файлы. Windows Get-AuthenticodeSignature для WinDivert64.sys вернул Valid (Signature verified). Воспроизводимая сборка по исходникам не выполнялась.

| Файл относительно `bundle` | SHA-256 |
| --- | --- |
| `bin/winws.exe` | `affb4f69d2ea302a7abccd5325d81826e140ddae014f1e070bc4a6c0dd555188` |
| `bin/WinDivert.dll` | `c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2` |
| `bin/WinDivert64.sys` | `8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2` |
| `bin/cygwin1.dll` | `103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b` |
| `LICENSE.txt` | `8ea76af265366af6ef96595705ad21cafab82f2786203ae70d29a970260434dc` |

## Пределы проверки стратегий

Все 22 штатных файла разобраны; все 33 использованных имени опций найдены во
встроенных строках справки именно поставленного `winws.exe`. Параметры вариантов
`--dpi-desync-repeats` и `--dpi-desync-split-pos` дополнительно сверены с
[разбором аргументов движка указанной ревизии](https://github.com/bol-van/zapret/blob/c849e55ef0f1c244206f5a05ff7b1ab41a3824ee/nfq/nfqws.c).
Варианты меняют только существующие repeats на 4/12 или 6/8, либо split-pos на 2/3.

Передача всех 28 наборов аргументов через Windows `subprocess` проверена
безопасным Python-процессом, включая пути с пробелами, кириллицей и символами
`&`, `%`, `!`. Это проверка кавычек и границ аргументов, а не запуска Cygwin/winws.
Исполнение `winws.exe`, загрузка WinDivert и работа обхода требуют отдельной
проверки с повышенными правами в нужной сети. Статическая проверка параметров
не подтверждает работу YouTube, QUIC или голосовых каналов Discord у провайдера.

## Интерфейс и оболочка

Оригинальный код zapret by nerd3n: MIT, nerd3n (2026), см. LICENSE. Python 3.13.5 поставляется внутри EXE; его уведомления сохранены в PYTHON-LICENSE.txt. GSAP 3.15.0 взят из официального npm-пакета, исходный заголовок сохранён; применяется Standard No Charge License, см. GSAP-LICENSE.txt. Эта лицензия отличается от MIT.

