Docker — це інструмент, який допомагає запускати програми в спеціальних контейнерах. Мета цієї практичної було дослідити та проексперементувати з обмеженнями ресурсів у середовищі Docker. Я маю на увазі освоїти ліміт відкритих файлів, встановлення лімітів процесів та файлів, використання утиліти perf, обмеження на максимальний розмір файлу, часу та інше. В моїй ситуації в мене встановлено FreeBSD на якій я не могу встановити середовище докер бо він працює з лінуксом та не втає на FreeBSD тому я знайшла альтернативу докеру це jail. Це як середовище як процесів в FreeBSD. Але перед тим як працювати з цим середовищем треба його встановити та налаштувати. Спочатку я встановила пакет

pkg install ezjail

Далі налаштувала систему для роботи з rctl та sysctl. Далі створила файл з конфігурацією jail «jail.conf». Далі прописала команди для системи для роботи jail

sysrc jail_enable="YES"

sysrc jail_list="testjail"

Далі перезапустила сервіс jail та запустила його за допомогою цієї команди

service ezjail start

далі перевірила що він дійсно працює

jls

потім увімкнула наступну команду щоб увійти в jail

jexec testjail /bin/sh.

Додатково створила директорії для jail 

mkdir -p /usr/jails/testjail

і скопіювала в них базові файли системи

tar -xvpf /usr/freebsd-dist/base.txz -C /usr/jails/testjail

tar -xvpf /usr/freebsd-dist/kernel.txz -C /usr/jails/testjail.

# Завдання 3.1

За допомогою середовища jail я виконала завдання на обмеження кількості відкритих файлів. Далі по черзі прописала всі запропоновані команди суть яких змінювати ліміт і перевіряти що вони дійсно змінюються 

$ ulimit -n

$ ulimit -aS | grep "open files"

$ ulimit -aH | grep "open files"

$ ulimit -n 3000

$ ulimit -aS | grep "open files"

$ ulimit -aH | grep "open files"

$ ulimit -n 3001

$ ulimit -n 2000

$ ulimit -n

$ ulimit -aS | grep "open files"

$ ulimit -aH | grep "open files"

$ ulimit -n 3000

На рахунок root прав я спочатку заходила в root, а потім вже в jail, тобто я вже знаходилась в root. 

# Завдання 3.2

За цим завданням потрібно було встановити утиліту perf, але так як вона відсутня у FreeBSD замість неї я використала альтернативний спосіб моніторингу. Перше це провела аналіз навантаження на CPU у реальному часі далі встановила оновлення кожну секунду після цього запустила команду vmstat 1

Щоб подивитись загальне навантаження системи. Потім перевірила, які ліміти процесів встановлено в системі: 

ulimit -a

ulimit -t

Далі проаналізувала процеси які споживають найбільше ресурсів. 

ps aux | sort -nrk 3 | head -10

Далі запустила навантажувальний тест, щоб подивитись як змінюватимуться ресурси. 

yes > /dev/null &

яка запускає нескінченний процес завантаження CPU

Після запуску виконала команду 

vmstat 1

щоб подивитися, як змінюються показники

Зупинка процесу:

pkill yes.

Також провела навантаження на пам’ять та диск. 

# Завдання 3.3

#include <stdio.h>

#include <stdlib.h>

#include <unistd.h>

#include <fcntl.h>

#include <sys/stat.h>

#define FILENAME "dice_rolls.txt"  

#define MAX_FILE_SIZE 1024   

#define BATCH_SIZE 100 

int cube() {

    return (arc4random() % 6) + 1;
    
}

int main() {

    int fd;
    
    struct stat file_stat;
    
    char buffer[BATCH_SIZE * 3];  
    
    fd = open(FILENAME, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    
    if (fd == -1) {
    
        perror("Помилка відкриття файлу");
        
        return EXIT_FAILURE;
        
    }
    
    while (1) {
    
        if (stat(FILENAME, &file_stat) == -1) {
        
            perror("Помилка отримання розміру файлу");
            
            close(fd);
            
            return EXIT_FAILURE;
            
        }
        
        if (file_stat.st_size >= MAX_FILE_SIZE) {
        
            printf("Досягнуто максимального розміру файлу (%d байт). Завершення роботи.\n", MAX_FILE_SIZE);
            
            break;
            
        }
        
        int pos = 0;
        
        for (int i = 0; i < BATCH_SIZE; i++) {
        
            pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%d\n", roll_dice());
            
        }
        
        if (file_stat.st_size + pos > MAX_FILE_SIZE) {
        
            printf("Запис перевищить ліміт файлу, припиняємо роботу.\n");
            
            break;
            
        }
        
        if (write(fd, buffer, pos) == -1) {
        
            perror("Помилка запису у файл");
            
            close(fd);
            
            return EXIT_FAILURE;
            
        }
        
        printf("Записано %d кидків\n", BATCH_SIZE);
        
    }
    
    close(fd);
    
    return EXIT_SUCCESS;
    
}

Компілюю та у результаті: 

The recording will exceed the file limit. Stop the operations. 

Write 100 rolls

Програма починається з визначення макросів. FILENAME задає ім'я файлу, куди записуватимуться результати кидків. MAX_FILE_SIZE встановлює максимальний розмір файлу у 1024 байти. BATCH_SIZE визначає кількість кидків кубика за один цикл запису. Функція roll_dice() відповідає за генерацію випадкового числа від 1 до 6, що імітує кидок шестигранного кубика. Потім виконується відкриття файлу за допомогою open(FILENAME, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR), що дозволяє здійснювати запис, створює файл за його відсутності та додає дані в кінець. Якщо відкриття не вдалося, програма завершується з помилкою. Основний цикл починається з виклику stat(FILENAME, &file_stat), який отримує поточний розмір файлу. Якщо розмір перевищує MAX_FILE_SIZE, програма припиняє виконання. Далі генерується BATCH_SIZE випадкових кидків кубика, після чого перевіряється, чи новий запис не перевищить допустимий розмір файлу. Якщо обмеження не порушується, результати записуються у файл. Завершальний етап – закриття файлу командою close(fd), що гарантує правильне завершення роботи програми.

# Завдання 3.4

Це завдання подібне до попереднього. 

import random

import signal

import sys

def timeout_handler(signum, frame):

    print("\n The execution time is over. The lottery has been terminated!")

    sys.exit(1)
    
signal.signal(signal.SIGXCPU, timeout_handler)

def generate_lottery():

    numbers_49 = random.sample(range(1, 50), 7)
    
    numbers_36 = random.sample(range(1, 37), 6)
    
    return numbers_49, numbers_36
    
filename = "lottery_results.txt"

try:

    with open(filename, "w") as f:
    
        for _ in range(1000000):  
        
            n49, n36 = generate_lottery()
            
            f.write(f"7 із 49: {n49} | 6 із 36: {n36}\n")
            
except Exception as e:

    print(f" Error: {e}")
    
print(f" The lottery is over. Results in {filename}")

Компіляцію наступним чином відбувається і отримаємо результат:

root@host:/home/dasha # python3 PR3_4.py

The lottery end. Result in lottery_results.txt

Ми задаємося обмеженням на час ЦП через ulimit -t 5 (5 секунд), запускаємо программу і через 5 секунд вона завершується і за цей час імітує лотерею, тобто коли вичерпався час ЦП, програма завершується, а результати записуються у файл.

# Завдання 3.5

Для даного завдання я створила файл з кодом на пайтон, який перевіряє чи передається два аргументи, перевіряє чи існує вихідний файл, обробляє перевищення розміру файлу. За допомогою наступної команди створила вихідний файл, тобто джерело і цільовий.

echo "Hello World" > file1.txt

touch file2.txt 

Після цього запустила програму

python3 PR3_5.py file1.txt file2.txt.

За допомогою цієї команди перевіряємо чи містяться там дані

cat file2.txt

і за завданням потрібно було перевірити помилки, тобто викликати програму без аргументів або з неіснуючим файлом. 

python3 PR3_5.py

python3 PR3_5.py file_not_exist.txt file2.txt

python3 PR3_5.py file1.txt /root/protected_file.txt  

# Завдання 3.6

Нашим завданням було продемонструвати обмеження розміру стеку в системі за допомогою рекурсивної функції. Щоб запустити код нам потрібно дізнатися який в системі ліміт на стек за допомогою команди 

ulimit -s

Далі написали програму 

import sys

sys.setrecursionlimit(2000) 

print(f"Current recursion limit: {sys.getrecursionlimit()}")

def recursive_function(depth=0):

    print(f"Recursion depth: {depth}")
    
    recursive_function(depth + 1)
    
recursive_function() 

Ми створили нескінчену рекурсію щоб викликати помилку стеку. Запустивши код через деякий час ми отримали помилку. Далі зменшили обмеження стеку

ulimit -s 512

після цього запустили програму і помилка виникла швидше.

# Завдання 1.21

Для початку перевірила поточні ліміти

Ulimit -a

Далі обмежила кількість відкритих файлів

Ulimit -n 1024

Далі обмежила максимальний розмір пам’яті для процесу 

Ulimit -m 524288

Далі обмежила пам’ять для процесу через підтримку rctl

sysrc rctl_enable="YES"

service rctl start

Додала обмеження для процесу sleep

sleep 1000 &

pgrep sleep

Обмежила процес

rctl -a process:2339:memoryuse:deny=256M

І перевірила обмеження

rctl -l process:2339

Далі перевірила чи rctl працює обмеження на пам’ять тому запустила тест 

dd if=/dev/zero of=/dev/null bs=1M count=300

Процес завершився помилкою через обмеження пам’яті тому rctl працює

Далі перевірила чи є обмеження на CPU тому запустила важкий процес 

openssl speed

Перевірила, чи не перевищує використання CPU 50%:

top -P.


https://github.com/Daria123H/README_-_-3.git

