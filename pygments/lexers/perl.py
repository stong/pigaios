# -*- coding: utf-8 -*-
"""
    pygments.lexers.perl
    ~~~~~~~~~~~~~~~~~~~~

    Lexers for Perl and related languages.

    :copyright: Copyright 2006-2015 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

import re

from pygments.lexer import RegexLexer, ExtendedRegexLexer, include, bygroups, \
    using, this, default, words
from pygments.token import Text, Comment, Operator, Keyword, Name, String, \
    Number, Punctuation
from pygments.util import shebang_matches

__all__ = ['PerlLexer', 'Perl6Lexer']


class PerlLexer(RegexLexer):
    """
    For `Perl <http://www.perl.org>`_ source code.
    """

    name = 'Perl'
    aliases = ['perl', 'pl']
    filenames = ['*.pl', '*.pm', '*.t']
    mimetypes = ['text/x-perl', 'application/x-perl']

    flags = re.DOTALL | re.MULTILINE
    # TODO: give this to a perl guy who knows how to parse perl...
    tokens = {
        'balanced-regex': [
            (r'/(\\\\|\\[^\\]|[^\\/])*/[egimosx]*', String.Regex, '#pop'),
            (r'!(\\\\|\\[^\\]|[^\\!])*![egimosx]*', String.Regex, '#pop'),
            (r'\\(\\\\|[^\\])*\\[egimosx]*', String.Regex, '#pop'),
            (r'\{(\\\\|\\[^\\]|[^\\}])*\}[egimosx]*', String.Regex, '#pop'),
            (r'<(\\\\|\\[^\\]|[^\\>])*>[egimosx]*', String.Regex, '#pop'),
            (r'\[(\\\\|\\[^\\]|[^\\\]])*\][egimosx]*', String.Regex, '#pop'),
            (r'\((\\\\|\\[^\\]|[^\\)])*\)[egimosx]*', String.Regex, '#pop'),
            (r'@(\\\\|\\[^\\]|[^\\@])*@[egimosx]*', String.Regex, '#pop'),
            (r'%(\\\\|\\[^\\]|[^\\%])*%[egimosx]*', String.Regex, '#pop'),
            (r'\$(\\\\|\\[^\\]|[^\\$])*\$[egimosx]*', String.Regex, '#pop'),
        ],
        'root': [
            (r'\#.*?$', Comment.Single),
            (r'^=[a-zA-Z0-9]+\s+.*?\n=cut', Comment.Multiline),
            (words((
                'case', 'continue', 'do', 'else', 'elsif', 'for', 'foreach',
                'if', 'last', 'my', 'next', 'our', 'redo', 'reset', 'then',
                'unless', 'until', 'while', 'use', 'print', 'new', 'BEGIN',
                'CHECK', 'INIT', 'END', 'return'), suffix=r'\b'),
             Keyword),
            (r'(format)(\s+)(\w+)(\s*)(=)(\s*\n)',
             bygroups(Keyword, Text, Name, Text, Punctuation, Text), 'format'),
            (r'(eq|lt|gt|le|ge|ne|not|and|or|cmp)\b', Operator.Word),
            # common delimiters
            (r's/(\\\\|\\[^\\]|[^\\/])*/(\\\\|\\[^\\]|[^\\/])*/[egimosx]*',
                String.Regex),
            (r's!(\\\\|\\!|[^!])*!(\\\\|\\!|[^!])*![egimosx]*', String.Regex),
            (r's\\(\\\\|[^\\])*\\(\\\\|[^\\])*\\[egimosx]*', String.Regex),
            (r's@(\\\\|\\[^\\]|[^\\@])*@(\\\\|\\[^\\]|[^\\@])*@[egimosx]*',
                String.Regex),
            (r's%(\\\\|\\[^\\]|[^\\%])*%(\\\\|\\[^\\]|[^\\%])*%[egimosx]*',
                String.Regex),
            # balanced delimiters
            (r's\{(\\\\|\\[^\\]|[^\\}])*\}\s*', String.Regex, 'balanced-regex'),
            (r's<(\\\\|\\[^\\]|[^\\>])*>\s*', String.Regex, 'balanced-regex'),
            (r's\[(\\\\|\\[^\\]|[^\\\]])*\]\s*', String.Regex,
                'balanced-regex'),
            (r's\((\\\\|\\[^\\]|[^\\)])*\)\s*', String.Regex,
                'balanced-regex'),

            (r'm?/(\\\\|\\[^\\]|[^\\/\n])*/[gcimosx]*', String.Regex),
            (r'm(?=[/!\\{<\[(@%$])', String.Regex, 'balanced-regex'),
            (r'((?<==~)|(?<=\())\s*/(\\\\|\\[^\\]|[^\\/])*/[gcimosx]*',
                String.Regex),
            (r'\s+', Text),
            (words((
                'abs', 'accept', 'alarm', 'atan2', 'bind', 'binmode', 'bless', 'caller', 'chdir',
                'chmod', 'chomp', 'chop', 'chown', 'chr', 'chroot', 'close', 'closedir', 'connect',
                'continue', 'cos', 'crypt', 'dbmclose', 'dbmopen', 'defined', 'delete', 'die',
                'dump', 'each', 'endgrent', 'endhostent', 'endnetent', 'endprotoent',
                'endpwent', 'endservent', 'eof', 'eval', 'exec', 'exists', 'exit', 'exp', 'fcntl',
                'fileno', 'flock', 'fork', 'format', 'formline', 'getc', 'getgrent', 'getgrgid',
                'getgrnam', 'gethostbyaddr', 'gethostbyname', 'gethostent', 'getlogin',
                'getnetbyaddr', 'getnetbyname', 'getnetent', 'getpeername', 'getpgrp',
                'getppid', 'getpriority', 'getprotobyname', 'getprotobynumber',
                'getprotoent', 'getpwent', 'getpwnam', 'getpwuid', 'getservbyname',
                'getservbyport', 'getservent', 'getsockname', 'getsockopt', 'glob', 'gmtime',
                'goto', 'grep', 'hex', 'import', 'index', 'int', 'ioctl', 'join', 'keys', 'kill', 'last',
                'lc', 'lcfirst', 'length', 'link', 'listen', 'local', 'localtime', 'log', 'lstat',
                'map', 'mkdir', 'msgctl', 'msgget', 'msgrcv', 'msgsnd', 'my', 'next', 'no', 'oct', 'open',
                'opendir', 'ord', 'our', 'pack', 'package', 'pipe', 'pop', 'pos', 'printf',
                'prototype', 'push', 'quotemeta', 'rand', 'read', 'readdir',
                'readline', 'readlink', 'readpipe', 'recv', 'redo', 'ref', 'rename', 'require',
                'reverse', 'rewinddir', 'rindex', 'rmdir', 'scalar', 'seek', 'seekdir',
                'select', 'semctl', 'semget', 'semop', 'send', 'setgrent', 'sethostent', 'setnetent',
                'setpgrp', 'setpriority', 'setprotoent', 'setpwent', 'setservent',
                'setsockopt', 'shift', 'shmctl', 'shmget', 'shmread', 'shmwrite', 'shutdown',
                'sin', 'sleep', 'socket', 'socketpair', 'sort', 'splice', 'split', 'sprintf', 'sqrt',
                'srand', 'stat', 'study', 'substr', 'symlink', 'syscall', 'sysopen', 'sysread',
                'sysseek', 'system', 'syswrite', 'tell', 'telldir', 'tie', 'tied', 'time', 'times', 'tr',
                'truncate', 'uc', 'ucfirst', 'umask', 'undef', 'unlink', 'unpack', 'unshift', 'untie',
                'utime', 'values', 'vec', 'wait', 'waitpid', 'wantarray', 'warn', 'write'), suffix=r'\b'),
             Name.Builtin),
            (r'((__(DATA|DIE|WARN)__)|(STD(IN|OUT|ERR)))\b', Name.Builtin.Pseudo),
            (r'<<([\'"]?)([a-zA-Z_]\w*)\1;?\n.*?\n\2\n', String),
            (r'__END__', Comment.Preproc, 'end-part'),
            (r'\$\^[ADEFHILMOPSTWX]', Name.Variable.Global),
            (r"\$[\\\"\[\]'&`+*.,;=%~?@$!<>(^|/-](?!\w)", Name.Variable.Global),
            (r'[$@%#]+', Name.Variable, 'varname'),
            (r'0_?[0-7]+(_[0-7]+)*', Number.Oct),
            (r'0x[0-9A-Fa-f]+(_[0-9A-Fa-f]+)*', Number.Hex),
            (r'0b[01]+(_[01]+)*', Number.Bin),
            (r'(?i)(\d*(_\d*)*\.\d+(_\d*)*|\d+(_\d*)*\.\d+(_\d*)*)(e[+-]?\d+)?',
             Number.Float),
            (r'(?i)\d+(_\d*)*e[+-]?\d+(_\d*)*', Number.Float),
            (r'\d+(_\d+)*', Number.Integer),
            (r"'(\\\\|\\[^\\]|[^'\\])*'", String),
            (r'"(\\\\|\\[^\\]|[^"\\])*"', String),
            (r'`(\\\\|\\[^\\]|[^`\\])*`', String.Backtick),
            (r'<([^\s>]+)>', String.Regex),
            (r'(q|qq|qw|qr|qx)\{', String.Other, 'cb-string'),
            (r'(q|qq|qw|qr|qx)\(', String.Other, 'rb-string'),
            (r'(q|qq|qw|qr|qx)\[', String.Other, 'sb-string'),
            (r'(q|qq|qw|qr|qx)\<', String.Other, 'lt-string'),
            (r'(q|qq|qw|qr|qx)([\W_])(.|\n)*?\2', String.Other),
            (r'package\s+', Keyword, 'modulename'),
            (r'sub\s+', Keyword, 'funcname'),
            (r'(\[\]|\*\*|::|<<|>>|>=|<=>|<=|={3}|!=|=~|'
             r'!~|&&?|\|\||\.{1,3})', Operator),
            (r'[-+/*%=<>&^|!\\~]=?', Operator),
            (r'[()\[\]:;,<>/?{}]', Punctuation),  # yes, there's no shortage
                                                  # of punctuation in Perl!
            (r'(?=\w)', Name, 'name'),
        ],
        'format': [
            (r'\.\n', String.Interpol, '#pop'),
            (r'[^\n]*\n', String.Interpol),
        ],
        'varname': [
            (r'\s+', Text),
            (r'\{', Punctuation, '#pop'),    # hash syntax?
            (r'\)|,', Punctuation, '#pop'),  # argument specifier
            (r'\w+::', Name.Namespace),
            (r'[\w:]+', Name.Variable, '#pop'),
        ],
        'name': [
            (r'\w+::', Name.Namespace),
            (r'[\w:]+', Name, '#pop'),
            (r'[A-Z_]+(?=\W)', Name.Constant, '#pop'),
            (r'(?=\W)', Text, '#pop'),
        ],
        'modulename': [
            (r'[a-zA-Z_]\w*', Name.Namespace, '#pop')
        ],
        'funcname': [
            (r'[a-zA-Z_]\w*[!?]?', Name.Function),
            (r'\s+', Text),
            # argument declaration
            (r'(\([$@%]*\))(\s*)', bygroups(Punctuation, Text)),
            (r';', Punctuation, '#pop'),
            (r'.*?\{', Punctuation, '#pop'),
        ],
        'cb-string': [
            (r'\\[{}\\]', String.Other),
            (r'\\', String.Other),
            (r'\{', String.Other, 'cb-string'),
            (r'\}', String.Other, '#pop'),
            (r'[^{}\\]+', String.Other)
        ],
        'rb-string': [
            (r'\\[()\\]', String.Other),
            (r'\\', String.Other),
            (r'\(', String.Other, 'rb-string'),
            (r'\)', String.Other, '#pop'),
            (r'[^()]+', String.Other)
        ],
        'sb-string': [
            (r'\\[\[\]\\]', String.Other),
            (r'\\', String.Other),
            (r'\[', String.Other, 'sb-string'),
            (r'\]', String.Other, '#pop'),
            (r'[^\[\]]+', String.Other)
        ],
        'lt-string': [
            (r'\\[<>\\]', String.Other),
            (r'\\', String.Other),
            (r'\<', String.Other, 'lt-string'),
            (r'\>', String.Other, '#pop'),
            (r'[^<>]+', String.Other)
        ],
        'end-part': [
            (r'.+', Comment.Preproc, '#pop')
        ]
    }

    def analyse_text(text):
        if shebang_matches(text, r'perl'):
            return True
        if re.search('(?:my|our)\s+[$@%(]', text):
            return 0.9


class Perl6Lexer(ExtendedRegexLexer):
    """
    For `Perl 6 <http://www.perl6.org>`_ source code.

    .. versionadded:: 2.0
    """

    name = 'Perl6'
    aliases = ['perl6', 'pl6']
    filenames = ['*.pl', '*.pm', '*.nqp', '*.p6', '*.6pl', '*.p6l', '*.pl6',
                 '*.6pm', '*.p6m', '*.pm6', '*.t']
    mimetypes = ['text/x-perl6', 'application/x-perl6']
    flags = re.MULTILINE | re.DOTALL | re.UNICODE

    PERL6_IDENTIFIER_RANGE = "['\w:-]"

    PERL6_KEYWORDS = (
        'BEGIN', 'CATCH', 'CHECK', 'CONTROL', 'END', 'ENTER', 'FIRST', 'INIT',
        'KEEP', 'LAST', 'LEAVE', 'NEXT', 'POST', 'PRE', 'START', 'TEMP',
        'UNDO', 'as', 'assoc', 'async', 'augment', 'binary', 'break', 'but',
        'cached', 'category', 'class', 'constant', 'contend', 'continue',
        'copy', 'deep', 'default', 'defequiv', 'defer', 'die', 'do', 'else',
        'elsif', 'enum', 'equiv', 'exit', 'export', 'fail', 'fatal', 'for',
        'gather', 'given', 'goto', 'grammar', 'handles', 'has', 'if', 'inline',
        'irs', 'is', 'last', 'leave', 'let', 'lift', 'loop', 'looser', 'macro',
        'make', 'maybe', 'method', 'module', 'multi', 'my', 'next', 'of',
        'ofs', 'only', 'oo', 'ors', 'our', 'package', 'parsed', 'prec',
        'proto', 'readonly', 'redo', 'ref', 'regex', 'reparsed', 'repeat',
        'require', 'required', 'return', 'returns', 'role', 'rule', 'rw',
        'self', 'slang', 'state', 'sub', 'submethod', 'subset', 'supersede',
        'take', 'temp', 'tighter', 'token', 'trusts', 'try', 'unary',
        'unless', 'until', 'use', 'warn', 'when', 'where', 'while', 'will',
    )

    PERL6_BUILTINS = (
        'ACCEPTS', 'HOW', 'REJECTS', 'VAR', 'WHAT', 'WHENCE', 'WHERE', 'WHICH',
        'WHO', 'abs', 'acos', 'acosec', 'acosech', 'acosh', 'acotan', 'acotanh',
        'all', 'any', 'approx', 'arity', 'asec', 'asech', 'asin', 'asinh',
        'assuming', 'atan', 'atan2', 'atanh', 'attr', 'bless', 'body', 'by',
        'bytes', 'caller', 'callsame', 'callwith', 'can', 'capitalize', 'cat',
        'ceiling', 'chars', 'chmod', 'chomp', 'chop', 'chr', 'chroot',
        'circumfix', 'cis', 'classify', 'clone', 'close', 'cmp_ok', 'codes',
        'comb', 'connect', 'contains', 'context', 'cos', 'cosec', 'cosech',
        'cosh', 'cotan', 'cotanh', 'count', 'defined', 'delete', 'diag',
        'dies_ok', 'does', 'e', 'each', 'eager', 'elems', 'end', 'eof', 'eval',
        'eval_dies_ok', 'eval_elsewhere', 'eval_lives_ok', 'evalfile', 'exists',
        'exp', 'first', 'flip', 'floor', 'flunk', 'flush', 'fmt', 'force_todo',
        'fork', 'from', 'getc', 'gethost', 'getlogin', 'getpeername', 'getpw',
        'gmtime', 'graphs', 'grep', 'hints', 'hyper', 'im', 'index', 'infix',
        'invert', 'is_approx', 'is_deeply', 'isa', 'isa_ok', 'isnt', 'iterator',
        'join', 'key', 'keys', 'kill', 'kv', 'lastcall', 'lazy', 'lc', 'lcfirst',
        'like', 'lines', 'link', 'lives_ok', 'localtime', 'log', 'log10', 'map',
        'max', 'min', 'minmax', 'name', 'new', 'nextsame', 'nextwith', 'nfc',
        'nfd', 'nfkc', 'nfkd', 'nok_error', 'nonce', 'none', 'normalize', 'not',
        'nothing', 'ok', 'once', 'one', 'open', 'opendir', 'operator', 'ord',
        'p5chomp', 'p5chop', 'pack', 'pair', 'pairs', 'pass', 'perl', 'pi',
        'pick', 'plan', 'plan_ok', 'polar', 'pop', 'pos', 'postcircumfix',
        'postfix', 'pred', 'prefix', 'print', 'printf', 'push', 'quasi',
        'quotemeta', 'rand', 're', 'read', 'readdir', 'readline', 'reduce',
        'reverse', 'rewind', 'rewinddir', 'rindex', 'roots', 'round',
        'roundrobin', 'run', 'runinstead', 'sameaccent', 'samecase', 'say',
        'sec', 'sech', 'sech', 'seek', 'shape', 'shift', 'sign', 'signature',
        'sin', 'sinh', 'skip', 'skip_rest', 'sleep', 'slurp', 'sort', 'splice',
        'split', 'sprintf', 'sqrt', 'srand', 'strand', 'subst', 'substr', 'succ',
        'sum', 'symlink', 'tan', 'tanh', 'throws_ok', 'time', 'times', 'to',
        'todo', 'trim', 'trim_end', 'trim_start', 'true', 'truncate', 'uc',
        'ucfirst', 'undef', 'undefine', 'uniq', 'unlike', 'unlink', 'unpack',
        'unpolar', 'unshift', 'unwrap', 'use_ok', 'value', 'values', 'vec',
        'version_lt', 'void', 'wait', 'want', 'wrap', 'write', 'zip',
    )

    PERL6_BUILTIN_CLASSES = (
        'Abstraction', 'Any', 'AnyChar', 'Array', 'Associative', 'Bag', 'Bit',
        'Blob', 'Block', 'Bool', 'Buf', 'Byte', 'Callable', 'Capture', 'Char', 'Class',
        'Code', 'Codepoint', 'Comparator', 'Complex', 'Decreasing', 'Exception',
        'Failure', 'False', 'Grammar', 'Grapheme', 'Hash', 'IO', 'Increasing',
        'Int', 'Junction', 'KeyBag', 'KeyExtractor', 'KeyHash', 'KeySet',
        'KitchenSink', 'List', 'Macro', 'Mapping', 'Match', 'Matcher', 'Method',
        'Module', 'Num', 'Object', 'Ordered', 'Ordering', 'OrderingPair',
        'Package', 'Pair', 'Positional', 'Proxy', 'Range', 'Rat', 'Regex',
        'Role', 'Routine', 'Scalar', 'Seq', 'Set', 'Signature', 'Str', 'StrLen',
        'StrPos', 'Sub', 'Submethod', 'True', 'UInt', 'Undef', 'Version', 'Void',
        'Whatever', 'bit', 'bool', 'buf', 'buf1', 'buf16', 'buf2', 'buf32',
        'buf4', 'buf64', 'buf8', 'complex', 'int', 'int1', 'int16', 'int2',
        'int32', 'int4', 'int64', 'int8', 'num', 'rat', 'rat1', 'rat16', 'rat2',
        'rat32', 'rat4', 'rat64', 'rat8', 'uint', 'uint1', 'uint16', 'uint2',
        'uint32', 'uint4', 'uint64', 'uint8', 'utf16', 'utf32', 'utf8',
    )

    PERL6_OPERATORS = (
        'X', 'Z', 'after', 'also', 'and', 'andthen', 'before', 'cmp', 'div',
        'eq', 'eqv', 'extra', 'ff', 'fff', 'ge', 'gt', 'le', 'leg', 'lt', 'm',
        'mm', 'mod', 'ne', 'or', 'orelse', 'rx', 's', 'tr', 'x', 'xor', 'xx',
        '++', '--', '**', '!', '+', '-', '~', '?', '|', '||', '+^', '~^', '?^',
        '^', '*', '/', '%', '%%', '+&', '+<', '+>', '~&', '~<', '~>', '?&',
        'gcd', 'lcm', '+', '-', '+|', '+^', '~|', '~^', '?|', '?^',
        '~', '&', '^', 'but', 'does', '<=>', '..', '..^', '^..', '^..^',
        '!=', '==', '<', '<=', '>', '>=', '~~', '===', '!eqv',
        '&&', '||', '^^', '//', 'min', 'max', '??', '!!', 'ff', 'fff', 'so',
        'not', '<==', '==>', '<<==', '==>>',
    )

    # Perl 6 has a *lot* of possible bracketing characters
    # this list was lifted from STD.pm6 (https://github.com/perl6/std)
    PERL6_BRACKETS = {
        '\u0028': '\u0029', '\u003c': '\u003e', '\u005b': '\u005d',
        '\u007b': '\u007d', '\u00ab': '\u00bb', '\u0f3a': '\u0f3b',
        '\u0f3c': '\u0f3d', '\u169b': '\u169c', '\u2018': '\u2019',
        '\u201a': '\u2019', '\u201b': '\u2019', '\u201c': '\u201d',
        '\u201e': '\u201d', '\u201f': '\u201d', '\u2039': '\u203a',
        '\u2045': '\u2046', '\u207d': '\u207e', '\u208d': '\u208e',
        '\u2208': '\u220b', '\u2209': '\u220c', '\u220a': '\u220d',
        '\u2215': '\u29f5', '\u223c': '\u223d', '\u2243': '\u22cd',
        '\u2252': '\u2253', '\u2254': '\u2255', '\u2264': '\u2265',
        '\u2266': '\u2267', '\u2268': '\u2269', '\u226a': '\u226b',
        '\u226e': '\u226f', '\u2270': '\u2271', '\u2272': '\u2273',
        '\u2274': '\u2275', '\u2276': '\u2277', '\u2278': '\u2279',
        '\u227a': '\u227b', '\u227c': '\u227d', '\u227e': '\u227f',
        '\u2280': '\u2281', '\u2282': '\u2283', '\u2284': '\u2285',
        '\u2286': '\u2287', '\u2288': '\u2289', '\u228a': '\u228b',
        '\u228f': '\u2290', '\u2291': '\u2292', '\u2298': '\u29b8',
        '\u22a2': '\u22a3', '\u22a6': '\u2ade', '\u22a8': '\u2ae4',
        '\u22a9': '\u2ae3', '\u22ab': '\u2ae5', '\u22b0': '\u22b1',
        '\u22b2': '\u22b3', '\u22b4': '\u22b5', '\u22b6': '\u22b7',
        '\u22c9': '\u22ca', '\u22cb': '\u22cc', '\u22d0': '\u22d1',
        '\u22d6': '\u22d7', '\u22d8': '\u22d9', '\u22da': '\u22db',
        '\u22dc': '\u22dd', '\u22de': '\u22df', '\u22e0': '\u22e1',
        '\u22e2': '\u22e3', '\u22e4': '\u22e5', '\u22e6': '\u22e7',
        '\u22e8': '\u22e9', '\u22ea': '\u22eb', '\u22ec': '\u22ed',
        '\u22f0': '\u22f1', '\u22f2': '\u22fa', '\u22f3': '\u22fb',
        '\u22f4': '\u22fc', '\u22f6': '\u22fd', '\u22f7': '\u22fe',
        '\u2308': '\u2309', '\u230a': '\u230b', '\u2329': '\u232a',
        '\u23b4': '\u23b5', '\u2768': '\u2769', '\u276a': '\u276b',
        '\u276c': '\u276d', '\u276e': '\u276f', '\u2770': '\u2771',
        '\u2772': '\u2773', '\u2774': '\u2775', '\u27c3': '\u27c4',
        '\u27c5': '\u27c6', '\u27d5': '\u27d6', '\u27dd': '\u27de',
        '\u27e2': '\u27e3', '\u27e4': '\u27e5', '\u27e6': '\u27e7',
        '\u27e8': '\u27e9', '\u27ea': '\u27eb', '\u2983': '\u2984',
        '\u2985': '\u2986', '\u2987': '\u2988', '\u2989': '\u298a',
        '\u298b': '\u298c', '\u298d': '\u298e', '\u298f': '\u2990',
        '\u2991': '\u2992', '\u2993': '\u2994', '\u2995': '\u2996',
        '\u2997': '\u2998', '\u29c0': '\u29c1', '\u29c4': '\u29c5',
        '\u29cf': '\u29d0', '\u29d1': '\u29d2', '\u29d4': '\u29d5',
        '\u29d8': '\u29d9', '\u29da': '\u29db', '\u29f8': '\u29f9',
        '\u29fc': '\u29fd', '\u2a2b': '\u2a2c', '\u2a2d': '\u2a2e',
        '\u2a34': '\u2a35', '\u2a3c': '\u2a3d', '\u2a64': '\u2a65',
        '\u2a79': '\u2a7a', '\u2a7d': '\u2a7e', '\u2a7f': '\u2a80',
        '\u2a81': '\u2a82', '\u2a83': '\u2a84', '\u2a8b': '\u2a8c',
        '\u2a91': '\u2a92', '\u2a93': '\u2a94', '\u2a95': '\u2a96',
        '\u2a97': '\u2a98', '\u2a99': '\u2a9a', '\u2a9b': '\u2a9c',
        '\u2aa1': '\u2aa2', '\u2aa6': '\u2aa7', '\u2aa8': '\u2aa9',
        '\u2aaa': '\u2aab', '\u2aac': '\u2aad', '\u2aaf': '\u2ab0',
        '\u2ab3': '\u2ab4', '\u2abb': '\u2abc', '\u2abd': '\u2abe',
        '\u2abf': '\u2ac0', '\u2ac1': '\u2ac2', '\u2ac3': '\u2ac4',
        '\u2ac5': '\u2ac6', '\u2acd': '\u2ace', '\u2acf': '\u2ad0',
        '\u2ad1': '\u2ad2', '\u2ad3': '\u2ad4', '\u2ad5': '\u2ad6',
        '\u2aec': '\u2aed', '\u2af7': '\u2af8', '\u2af9': '\u2afa',
        '\u2e02': '\u2e03', '\u2e04': '\u2e05', '\u2e09': '\u2e0a',
        '\u2e0c': '\u2e0d', '\u2e1c': '\u2e1d', '\u2e20': '\u2e21',
        '\u3008': '\u3009', '\u300a': '\u300b', '\u300c': '\u300d',
        '\u300e': '\u300f', '\u3010': '\u3011', '\u3014': '\u3015',
        '\u3016': '\u3017', '\u3018': '\u3019', '\u301a': '\u301b',
        '\u301d': '\u301e', '\ufd3e': '\ufd3f', '\ufe17': '\ufe18',
        '\ufe35': '\ufe36', '\ufe37': '\ufe38', '\ufe39': '\ufe3a',
        '\ufe3b': '\ufe3c', '\ufe3d': '\ufe3e', '\ufe3f': '\ufe40',
        '\ufe41': '\ufe42', '\ufe43': '\ufe44', '\ufe47': '\ufe48',
        '\ufe59': '\ufe5a', '\ufe5b': '\ufe5c', '\ufe5d': '\ufe5e',
        '\uff08': '\uff09', '\uff1c': '\uff1e', '\uff3b': '\uff3d',
        '\uff5b': '\uff5d', '\uff5f': '\uff60', '\uff62': '\uff63',
    }

    def _build_word_match(words, boundary_regex_fragment=None, prefix='', suffix=''):
        if boundary_regex_fragment is None:
            return r'\b(' + prefix + r'|'.join(re.escape(x) for x in words) + \
                suffix + r')\b'
        else:
            return r'(?<!' + boundary_regex_fragment + r')' + prefix + r'(' + \
                r'|'.join(re.escape(x) for x in words) + r')' + suffix + r'(?!' + \
                boundary_regex_fragment + r')'

    def brackets_callback(token_class):
        def callback(lexer, match, context):
            groups = match.groupdict()
            opening_chars = groups['delimiter']
            n_chars = len(opening_chars)
            adverbs = groups.get('adverbs')

            closer = Perl6Lexer.PERL6_BRACKETS.get(opening_chars[0])
            text = context.text

            if closer is None:  # it's not a mirrored character, which means we
                                # just need to look for the next occurrence

                end_pos = text.find(opening_chars, match.start('delimiter') + n_chars)
            else:   # we need to look for the corresponding closing character,
                    # keep nesting in mind
                closing_chars = closer * n_chars
                nesting_level = 1

                search_pos = match.start('delimiter')

                while nesting_level > 0:
                    next_open_pos = text.find(opening_chars, search_pos + n_chars)
                    next_close_pos = text.find(closing_chars, search_pos + n_chars)

                    if next_close_pos == -1:
                        next_close_pos = len(text)
                        nesting_level = 0
                    elif next_open_pos != -1 and next_open_pos < next_close_pos:
                        nesting_level += 1
                        search_pos = next_open_pos
                    else:  # next_close_pos < next_open_pos
                        nesting_level -= 1
                        search_pos = next_close_pos

                end_pos = next_close_pos

            if end_pos < 0:     # if we didn't find a closer, just highlight the
                                # rest of the text in this class
                end_pos = len(text)

            if adverbs is not None and re.search(r':to\b', adverbs):
                heredoc_terminator = text[match.start('delimiter') + n_chars:end_pos]
                end_heredoc = re.search(r'^\s*' + re.escape(heredoc_terminator) +
                                        r'\s*$', text[end_pos:], re.MULTILINE)

                if end_heredoc:
                    end_pos += end_heredoc.end()
                else:
                    end_pos = len(text)

            yield match.start(), token_class, text[match.start():end_pos + n_chars]
            context.pos = end_pos + n_chars

        return callback

    def opening_brace_callback(lexer, match, context):
        stack = context.stack

        yield match.start(), Text, context.text[match.start():match.end()]
        context.pos = match.end()

        # if we encounter an opening brace and we're one level
        # below a token state, it means we need to increment
        # the nesting level for braces so we know later when
        # we should return to the token rules.
        if len(stack) > 2 and stack[-2] == 'token':
            context.perl6_token_nesting_level += 1

    def closing_brace_callback(lexer, match, context):
        stack = context.stack

        yield match.start(), Text, context.text[match.start():match.end()]
        context.pos = match.end()

        # if we encounter a free closing brace and we're one level
        # below a token state, it means we need to check the nesting
        # level to see if we need to return to the token state.
        if len(stack) > 2 and stack[-2] == 'token':
            context.perl6_token_nesting_level -= 1
            if context.perl6_token_nesting_level == 0:
                stack.pop()

    def embedded_perl6_callback(lexer, match, context):
        context.perl6_token_nesting_level = 1
        yield match.start(), Text, context.text[match.start():match.end()]
        context.pos = match.end()
        context.stack.append('root')

    # If you're modifying these rules, be careful if you need to process '{' or '}'
    # characters. We have special logic for processing these characters (due to the fact
    # that you can nest Perl 6 code in regex blocks), so if you need to process one of
    # them, make sure you also process the corresponding one!
    tokens = {
        'common': [
            (r'#[`|=](?P<delimiter>(?P<first_char>[' + ''.join(PERL6_BRACKETS) + r'])(?P=first_char)*)',
             brackets_callback(Comment.Multiline)),
            (r'#[^\n]*$', Comment.Singleline),
            (r'^(\s*)=begin\s+(\w+)\b.*?^\1=end\s+\2', Comment.Multiline),
            (r'^(\s*)=for.*?\n\s*?\n', Comment.Multiline),
            (r'^=.*?\n\s*?\n', Comment.Multiline),
            (r'(regex|token|rule)(\s*' + PERL6_IDENTIFIER_RANGE + '+:sym)',
             bygroups(Keyword, Name), 'token-sym-brackets'),
            (r'(regex|token|rule)(?!' + PERL6_IDENTIFIER_RANGE + ')(\s*' + PERL6_IDENTIFIER_RANGE + '+)?',
             bygroups(Keyword, Name), 'pre-token'),
            # deal with a special case in the Perl 6 grammar (role q { ... })
            (r'(role)(\s+)(q)(\s*)', bygroups(Keyword, Text, Name, Text)),
            (_build_word_match(PERL6_KEYWORDS, PERL6_IDENTIFIER_RANGE), Keyword),
            (_build_word_match(PERL6_BUILTIN_CLASSES, PERL6_IDENTIFIER_RANGE, suffix='(?::[UD])?'),
             Name.Builtin),
            (_build_word_match(PERL6_BUILTINS, PERL6_IDENTIFIER_RANGE), Name.Builtin),
            # copied from PerlLexer
            (r'[$@%&][.^:?=!~]?' + PERL6_IDENTIFIER_RANGE + '+(?:<<.*?>>|<.*?>|«.*?»)*',
             Name.Variable),
            (r'\$[!/](?:<<.*?>>|<.*?>|«.*?»)*', Name.Variable.Global),
            (r'::\?\w+', Name.Variable.Global),
            (r'[$@%&]\*' + PERL6_IDENTIFIER_RANGE + '+(?:<<.*?>>|<.*?>|«.*?»)*',
             Name.Variable.Global),
            (r'\$(?:<.*?>)+', Name.Variable),
            (r'(?:q|qq|Q)[a-zA-Z]?\s*(?P<adverbs>:[\w\s:]+)?\s*(?P<delimiter>(?P<first_char>[^0-9a-zA-Z:\s])'
             r'(?P=first_char)*)', brackets_callback(String)),
            # copied from PerlLexer
            (r'0_?[0-7]+(_[0-7]+)*', Number.Oct),
            (r'0x[0-9A-Fa-f]+(_[0-9A-Fa-f]+)*', Number.Hex),
            (r'0b[01]+(_[01]+)*', Number.Bin),
            (r'(?i)(\d*(_\d*)*\.\d+(_\d*)*|\d+(_\d*)*\.\d+(_\d*)*)(e[+-]?\d+)?',
             Number.Float),
            (r'(?i)\d+(_\d*)*e[+-]?\d+(_\d*)*', Number.Float),
            (r'\d+(_\d+)*', Number.Integer),
            (r'(?<=~~)\s*/(?:\\\\|\\/|.)*?/', String.Regex),
            (r'(?<=[=(,])\s*/(?:\\\\|\\/|.)*?/', String.Regex),
            (r'm\w+(?=\()', Name),
            (r'(?:m|ms|rx)\s*(?P<adverbs>:[\w\s:]+)?\s*(?P<delimiter>(?P<first_char>[^\w:\s])'
             r'(?P=first_char)*)', brackets_callback(String.Regex)),
            (r'(?:s|ss|tr)\s*(?::[\w\s:]+)?\s*/(?:\\\\|\\/|.)*?/(?:\\\\|\\/|.)*?/',
             String.Regex),
            (r'<[^\s=].*?\S>', String),
            (_build_word_match(PERL6_OPERATORS), Operator),
            (r'\w' + PERL6_IDENTIFIER_RANGE + '*', Name),
            (r"'(\\\\|\\[^\\]|[^'\\])*'", String),
            (r'"(\\\\|\\[^\\]|[^"\\])*"', String),
        ],
        'root': [
            include('common'),
            (r'\{', opening_brace_callback),
            (r'\}', closing_brace_callback),
            (r'.+?', Text),
        ],
        'pre-token': [
            include('common'),
            (r'\{', Text, ('#pop', 'token')),
            (r'.+?', Text),
        ],
        'token-sym-brackets': [
            (r'(?P<delimiter>(?P<first_char>[' + ''.join(PERL6_BRACKETS) + '])(?P=first_char)*)',
             brackets_callback(Name), ('#pop', 'pre-token')),
            default(('#pop', 'pre-token')),
        ],
        'token': [
            (r'\}', Text, '#pop'),
            (r'(?<=:)(?:my|our|state|constant|temp|let).*?;', using(this)),
            # make sure that quotes in character classes aren't treated as strings
            (r'<(?:[-!?+.]\s*)?\[.*?\]>', String.Regex),
            # make sure that '#' characters in quotes aren't treated as comments
            (r"(?<!\\)'(\\\\|\\[^\\]|[^'\\])*'", String.Regex),
            (r'(?<!\\)"(\\\\|\\[^\\]|[^"\\])*"', String.Regex),
            (r'#.*?$', Comment.Singleline),
            (r'\{', embedded_perl6_callback),
            ('.+?', String.Regex),
        ],
    }

    def analyse_text(text):
        def strip_pod(lines):
            in_pod = False
            stripped_lines = []

            for line in lines:
                if re.match(r'^=(?:end|cut)', line):
                    in_pod = False
                elif re.match(r'^=\w+', line):
                    in_pod = True
                elif not in_pod:
                    stripped_lines.append(line)

            return stripped_lines

        # XXX handle block comments
        lines = text.splitlines()
        lines = strip_pod(lines)
        text = '\n'.join(lines)

        if shebang_matches(text, r'perl6|rakudo|niecza|pugs'):
            return True

        saw_perl_decl = False
        rating = False

        # check for my/our/has declarations
        if re.search("(?:my|our|has)\s+(?:" + Perl6Lexer.PERL6_IDENTIFIER_RANGE +
                     "+\s+)?[$@%&(]", text):
            rating = 0.8
            saw_perl_decl = True

        for line in lines:
            line = re.sub('#.*', '', line)
            if re.match('^\s*$', line):
                continue

            # match v6; use v6; use v6.0; use v6.0.0;
            if re.match('^\s*(?:use\s+)?v6(?:\.\d(?:\.\d)?)?;', line):
                return True
            # match class, module, role, enum, grammar declarations
            class_decl = re.match('^\s*(?:(?P<scope>my|our)\s+)?(?:module|class|role|enum|grammar)', line)
            if class_decl:
                if saw_perl_decl or class_decl.group('scope') is not None:
                    return True
                rating = 0.05
                continue
            break

        return rating

    def __init__(self, **options):
        super(Perl6Lexer, self).__init__(**options)
        self.encoding = options.get('encoding', 'utf-8')
