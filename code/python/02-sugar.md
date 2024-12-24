## 装饰器 decorator

如果想知道 `print_prime` 总共花费的时间

```python
def is_prime(n):
    if n <= 1: return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0: return False
    return True

def print_prime(max_num):
    import time
    t1 = time.time()
    count = 0
    for num in range(2, max_num + 1):
        if is_prime(num):
            count += 1
            print(num)
  t2 = time.time()
    print('time spend: {}; total: {}'.format(t2 - t1, count))

def print_prime2(max_num):
    import time
    t1 = time.time()
    count = 0
    for num in range(2, max_num + 1 + 10000):
        if is_prime(num):
            count += 1
            print(num)
  t2 = time.time()
    print('time spend: {}; total: {}'.format(t2 - t1, count))

max_num = 10000
print_prime(max_num)
```

使用装饰器后转为以下内容

```python
def print_prime_decorator(func):
  def wrapper(*args):
      import time
      t1 = time.time()
      result = func(*args)
      t2 = time.time()
      print('time spend: {}'.format(t2 - t1))
      return result
  return wrapper

def is_prime(n):
  if n <= 1: return False
  for i in range(2, int(n**0.5) + 1):
      if n % i == 0: return False
  return True

@print_prime_decorator
def print_prime(max_num):
  for num in range(2, max_num + 1):
      if is_prime(num):
          print(num)

@print_prime_decorator
def print_prime2(max_num):
    for num in range(2, max_num + 1 + 10000):
        if is_prime(num):
            print(num)

max_num = 10000
print_prime(max_num)
print_prime2(max_num)
```

函数执行时，会先进入到 wrapper 中，情况适用于需要大量重复相同的代码，如此一来只需要在函数前添加一个装饰器函数即可，提升代码可读性

## 类 class