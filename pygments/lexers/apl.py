# -*- coding: utf-8 -*-
"""
    pygments.lexers.apl
    ~~~~~~~~~~~~~~~~~~~

    Lexers for APL.

    :copyright: Copyright 2006-2015 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from pygments.lexer import RegexLexer
from pygments.token import Text, Comment, Operator, Keyword, Name, String, \
    Number, Punctuation

__all__ = ['APLLexer']


class APLLexer(RegexLexer):
    """
    A simple APL lexer.

    .. versionadded:: 2.0
    """
    name = 'APL'
    aliases = ['apl']
    filenames = ['*.apl']

    tokens = {
        'root': [
            # Whitespace
            # ==========
            (r'\s+', Text),
            #
            # Comment
            # =======
            # '⍝' is traditional; '#' is supported by GNU APL and NGN (but not Dyalog)
            ('[⍝#].*$', Comment.Single),
            #
            # Strings
            # =======
            (r'\'((\'\')|[^\'])*\'', String.Single),
            (r'"(("")|[^"])*"', String.Double),  # supported by NGN APL
            #
            # Punctuation
            # ===========
            # This token type is used for diamond and parenthesis
            # but not for bracket and ; (see below)
            ('[⋄◇()]', Punctuation),
            #
            # Array indexing
            # ==============
            # Since this token type is very important in APL, it is not included in
            # the punctuation token type but rather in the following one
            (r'[\[\];]', String.Regex),
            #
            # Distinguished names
            # ===================
            # following IBM APL2 standard
            ('⎕[A-Za-zΔ∆⍙][A-Za-zΔ∆⍙_¯0-9]*', Name.Function),
            #
            # Labels
            # ======
            # following IBM APL2 standard
            # (u'[A-Za-zΔ∆⍙][A-Za-zΔ∆⍙_¯0-9]*:', Name.Label),
            #
            # Variables
            # =========
            # following IBM APL2 standard
            ('[A-Za-zΔ∆⍙][A-Za-zΔ∆⍙_¯0-9]*', Name.Variable),
            #
            # Numbers
            # =======
            ('¯?(0[Xx][0-9A-Fa-f]+|[0-9]*\.?[0-9]+([Ee][+¯]?[0-9]+)?|¯|∞)'
             '([Jj]¯?(0[Xx][0-9A-Fa-f]+|[0-9]*\.?[0-9]+([Ee][+¯]?[0-9]+)?|¯|∞))?',
             Number),
            #
            # Operators
            # ==========
            ('[\.\\\/⌿⍀¨⍣⍨⍠⍤∘]', Name.Attribute),  # closest token type
            ('[+\-×÷⌈⌊∣|⍳?*⍟○!⌹<≤=>≥≠≡≢∊⍷∪∩~∨∧⍱⍲⍴,⍪⌽⊖⍉↑↓⊂⊃⌷⍋⍒⊤⊥⍕⍎⊣⊢⍁⍂≈⌸⍯↗]',
             Operator),
            #
            # Constant
            # ========
            ('⍬', Name.Constant),
            #
            # Quad symbol
            # ===========
            ('[⎕⍞]', Name.Variable.Global),
            #
            # Arrows left/right
            # =================
            ('[←→]', Keyword.Declaration),
            #
            # D-Fn
            # ====
            ('[⍺⍵⍶⍹∇:]', Name.Builtin.Pseudo),
            (r'[{}]', Keyword.Type),
        ],
    }
