"""CQL Lexer — tokenizes Cyber Query Language input."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class TokenType(enum.Enum):
    # Literals
    STRING = "STRING"
    NUMBER = "NUMBER"
    FIELD = "FIELD"
    REGEX = "REGEX"
    WILDCARD = "WILDCARD"

    # Operators
    EQ = "="
    NEQ = "!="
    GT = ">"
    GTE = ">="
    LT = "<"
    LTE = "<="
    LIKE = "LIKE"
    IN = "IN"
    NOT_IN = "NOT IN"
    CONTAINS = "CONTAINS"
    STARTSWITH = "STARTSWITH"
    ENDSWITH = "ENDSWITH"
    MATCHES = "MATCHES"

    # Boolean
    AND = "AND"
    OR = "OR"
    NOT = "NOT"

    # Punctuation
    PIPE = "|"
    LPAREN = "("
    RPAREN = ")"
    COMMA = ","
    DOT = "."

    # Special
    EOF = "EOF"
    AS = "AS"
    BY = "BY"

    # Assignment (for eval)
    ASSIGN = "ASSIGN"


# Keywords that map to token types
_KEYWORDS: dict[str, TokenType] = {
    "AND": TokenType.AND,
    "OR": TokenType.OR,
    "NOT": TokenType.NOT,
    "LIKE": TokenType.LIKE,
    "IN": TokenType.IN,
    "CONTAINS": TokenType.CONTAINS,
    "STARTSWITH": TokenType.STARTSWITH,
    "ENDSWITH": TokenType.ENDSWITH,
    "MATCHES": TokenType.MATCHES,
    "AS": TokenType.AS,
    "BY": TokenType.BY,
}

_OPERATOR_KEYWORDS = {
    TokenType.LIKE, TokenType.IN, TokenType.NOT_IN,
    TokenType.CONTAINS, TokenType.STARTSWITH,
    TokenType.ENDSWITH, TokenType.MATCHES,
}


@dataclass
class Token:
    type: TokenType
    value: str
    line: int = 1
    col: int = 0

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, L{self.line}:{self.col})"


class LexerError(Exception):
    def __init__(self, message: str, line: int, col: int):
        self.line = line
        self.col = col
        super().__init__(f"Lexer error at L{line}:{col}: {message}")


class Lexer:
    """Tokenize a CQL query string."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: list[Token] = []

    def _peek(self) -> str | None:
        if self.pos < len(self.text):
            return self.text[self.pos]
        return None

    def _advance(self) -> str:
        ch = self.text[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return ch

    def _skip_whitespace(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in " \t\r\n":
            self._advance()

    def _read_string(self, quote: str) -> str:
        """Read a quoted string, handling escape sequences."""
        result: list[str] = []
        while self.pos < len(self.text):
            ch = self._advance()
            if ch == "\\":
                if self.pos >= len(self.text):
                    raise LexerError("Unterminated escape sequence", self.line, self.col)
                nxt = self._advance()
                escape_map = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\"}
                escape_map[quote] = quote
                result.append(escape_map.get(nxt, nxt))
            elif ch == quote:
                return "".join(result)
            else:
                result.append(ch)
        raise LexerError(f"Unterminated string (expected {quote})", self.line, self.col)

    def _read_number(self) -> Token:
        start_col = self.col
        start = self.pos
        has_dot = False
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch == ".":
                if has_dot:
                    break
                has_dot = True
                self._advance()
            elif ch.isdigit():
                self._advance()
            else:
                break
        return Token(TokenType.NUMBER, self.text[start:self.pos], self.line, start_col)

    def _read_identifier(self) -> str:
        start = self.pos
        while self.pos < len(self.text):
            ch = self.text[self.pos]
            if ch.isalnum() or ch in "_":
                self._advance()
            else:
                break
        return self.text[start:self.pos]

    def _read_regex(self) -> str:
        """Read /pattern/ regex literal."""
        result: list[str] = []
        while self.pos < len(self.text):
            ch = self._advance()
            if ch == "\\":
                if self.pos < len(self.text):
                    result.append(ch)
                    result.append(self._advance())
                else:
                    result.append(ch)
            elif ch == "/":
                return "".join(result)
            else:
                result.append(ch)
        raise LexerError("Unterminated regex literal", self.line, self.col)

    def tokenize(self) -> list[Token]:
        """Tokenize the entire input and return list of tokens."""
        self.tokens = []
        while self.pos < len(self.text):
            self._skip_whitespace()
            if self.pos >= len(self.text):
                break

            ch = self.text[self.pos]
            start_line = self.line
            start_col = self.col

            # Quoted strings
            if ch in ('"', "'"):
                self._advance()
                val = self._read_string(ch)
                # Check if string contains wildcards
                if "*" in val or "?" in val:
                    self.tokens.append(Token(TokenType.WILDCARD, val, start_line, start_col))
                else:
                    self.tokens.append(Token(TokenType.STRING, val, start_line, start_col))
                continue

            # Regex literal /pattern/
            if ch == "/":
                # Only treat as regex if we're in value position (after operator)
                if self.tokens and self.tokens[-1].type in (
                    TokenType.EQ, TokenType.NEQ, TokenType.MATCHES,
                    TokenType.ASSIGN,
                ):
                    self._advance()
                    pattern = self._read_regex()
                    self.tokens.append(Token(TokenType.REGEX, pattern, start_line, start_col))
                    continue

            # Numbers (including negative)
            if ch.isdigit() or (ch == "-" and self.pos + 1 < len(self.text) and self.text[self.pos + 1].isdigit()):
                if ch == "-":
                    self._advance()
                    tok = self._read_number()
                    tok.value = "-" + tok.value
                    tok.col = start_col
                    self.tokens.append(tok)
                else:
                    self.tokens.append(self._read_number())
                continue

            # Two-char operators
            if self.pos + 1 < len(self.text):
                two = self.text[self.pos:self.pos + 2]
                if two == "!=":
                    self._advance()
                    self._advance()
                    self.tokens.append(Token(TokenType.NEQ, "!=", start_line, start_col))
                    continue
                if two == ">=":
                    self._advance()
                    self._advance()
                    self.tokens.append(Token(TokenType.GTE, ">=", start_line, start_col))
                    continue
                if two == "<=":
                    self._advance()
                    self._advance()
                    self.tokens.append(Token(TokenType.LTE, "<=", start_line, start_col))
                    continue

            # Single-char operators and punctuation
            if ch == "=":
                self._advance()
                self.tokens.append(Token(TokenType.EQ, "=", start_line, start_col))
                continue
            if ch == ">":
                self._advance()
                self.tokens.append(Token(TokenType.GT, ">", start_line, start_col))
                continue
            if ch == "<":
                self._advance()
                self.tokens.append(Token(TokenType.LT, "<", start_line, start_col))
                continue
            if ch == "|":
                self._advance()
                self.tokens.append(Token(TokenType.PIPE, "|", start_line, start_col))
                continue
            if ch == "(":
                self._advance()
                self.tokens.append(Token(TokenType.LPAREN, "(", start_line, start_col))
                continue
            if ch == ")":
                self._advance()
                self.tokens.append(Token(TokenType.RPAREN, ")", start_line, start_col))
                continue
            if ch == ",":
                self._advance()
                self.tokens.append(Token(TokenType.COMMA, ",", start_line, start_col))
                continue
            if ch == ".":
                self._advance()
                self.tokens.append(Token(TokenType.DOT, ".", start_line, start_col))
                continue

            # Identifiers / keywords / wildcard patterns
            if ch.isalpha() or ch == "_" or ch == "*":
                # Check for wildcard pattern (contains * or ?)
                ident_start = self.pos
                while self.pos < len(self.text):
                    c = self.text[self.pos]
                    if c.isalnum() or c in "_*?.":
                        self._advance()
                    else:
                        break
                word = self.text[ident_start:self.pos]

                # Check for keywords
                upper = word.upper()
                if upper in _KEYWORDS:
                    tt = _KEYWORDS[upper]
                    # Handle "NOT IN" as two-word keyword
                    if tt == TokenType.NOT:
                        saved_pos = self.pos
                        saved_line = self.line
                        saved_col = self.col
                        self._skip_whitespace()
                        if self.pos < len(self.text):
                            next_start = self.pos
                            while self.pos < len(self.text) and self.text[self.pos].isalpha():
                                self._advance()
                            next_word = self.text[next_start:self.pos]
                            if next_word.upper() == "IN":
                                self.tokens.append(Token(TokenType.NOT_IN, "NOT IN", start_line, start_col))
                                continue
                        # Restore position — it's just NOT
                        self.pos = saved_pos
                        self.line = saved_line
                        self.col = saved_col
                    self.tokens.append(Token(tt, upper, start_line, start_col))
                elif "*" in word or "?" in word:
                    self.tokens.append(Token(TokenType.WILDCARD, word, start_line, start_col))
                else:
                    self.tokens.append(Token(TokenType.FIELD, word, start_line, start_col))
                continue

            raise LexerError(f"Unexpected character: {ch!r}", self.line, self.col)

        self.tokens.append(Token(TokenType.EOF, "", self.line, self.col))
        return self.tokens
