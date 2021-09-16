
# Workaround for Python3 compat
try:
  INTEGER_TYPES = (int, int)
except NameError:
  long = int
  INTEGER_TYPES = (int,)
