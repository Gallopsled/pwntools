import os
for module in os.listdir(os.path.dirname(__file__)):
    if module == '__init__.py' or module[-3:] != '.py':
        continue
    m = __import__(module[:-3], globals(), locals(), [], -1)
    for k, v in m.__dict__.items():
        if getattr(v, '__module__', '').startswith(__name__) and not k.startswith('_'):
            globals()[k] = v
del module, k, v, m
