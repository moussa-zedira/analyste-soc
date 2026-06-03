"""CQL Parser — builds an Abstract Syntax Tree from CQL tokens."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from apps.api.cql.lexer import Lexer, Token, TokenType

# ---------------------------------------------------------------------------
# AST Node types
# ---------------------------------------------------------------------------


@dataclass
class ASTNode:
    """Base class for all AST nodes."""

    pass


@dataclass
class Literal(ASTNode):
    value: Any
    token: Token | None = None


@dataclass
class FieldRef(ASTNode):
    """Reference to a field, possibly with dot notation (e.g., raw.ip)."""

    parts: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return ".".join(self.parts)


@dataclass
class Comparison(ASTNode):
    field: FieldRef
    operator: str  # =, !=, >, >=, <, <=, LIKE, IN, NOT IN, CONTAINS, etc.
    value: ASTNode  # Literal or ValueList


@dataclass
class ValueList(ASTNode):
    """List of values for IN operator."""

    values: list[Literal] = field(default_factory=list)


@dataclass
class BoolOp(ASTNode):
    op: str  # AND, OR
    left: ASTNode | None = None
    right: ASTNode | None = None


@dataclass
class NotExpr(ASTNode):
    operand: ASTNode | None = None


@dataclass
class PipeCommand(ASTNode):
    name: str = ""
    args: list[str] = field(default_factory=list)
    raw_text: str = ""


@dataclass
class Query(ASTNode):
    """Root AST node."""

    filter_expr: ASTNode | None = None
    commands: list[PipeCommand] = field(default_factory=list)
    earliest: str | None = None
    latest: str | None = None


@dataclass
class FunctionCall(ASTNode):
    name: str = ""
    args: list[ASTNode] = field(default_factory=list)


@dataclass
class EvalExpression(ASTNode):
    """Represents an eval expression (math, string ops, etc.)."""

    expression: str = ""


# ---------------------------------------------------------------------------
# Parser Error
# ---------------------------------------------------------------------------


class ParseError(Exception):
    def __init__(self, message: str, token: Token | None = None):
        self.token = token
        loc = ""
        if token:
            loc = f" at L{token.line}:{token.col}"
        super().__init__(f"Parse error{loc}: {message}")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

_OPERATOR_TYPES = {
    TokenType.EQ,
    TokenType.NEQ,
    TokenType.GT,
    TokenType.GTE,
    TokenType.LT,
    TokenType.LTE,
    TokenType.LIKE,
    TokenType.IN,
    TokenType.NOT_IN,
    TokenType.CONTAINS,
    TokenType.STARTSWITH,
    TokenType.ENDSWITH,
    TokenType.MATCHES,
}


class Parser:
    """Parse CQL token stream into an AST."""

    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    @classmethod
    def from_query(cls, query: str) -> Parser:
        lexer = Lexer(query)
        tokens = lexer.tokenize()
        return cls(tokens)

    def _current(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return Token(TokenType.EOF, "", 0, 0)

    def _peek(self, offset: int = 0) -> Token:
        idx = self.pos + offset
        if idx < len(self.tokens):
            return self.tokens[idx]
        return Token(TokenType.EOF, "", 0, 0)

    def _advance(self) -> Token:
        tok = self._current()
        self.pos += 1
        return tok

    def _expect(self, tt: TokenType) -> Token:
        tok = self._current()
        if tok.type != tt:
            raise ParseError(f"Expected {tt.name}, got {tok.type.name} ({tok.value!r})", tok)
        return self._advance()

    def _match(self, *types: TokenType) -> Token | None:
        if self._current().type in types:
            return self._advance()
        return None

    # -------------------------------------------------------------------
    # Top-level parse
    # -------------------------------------------------------------------

    def parse(self) -> Query:
        """Parse the full query into a Query AST node."""
        query = Query()

        # Extract time modifiers (earliest=..., latest=...)
        self._extract_time_modifiers(query)

        # Parse filter expression (if any, before first pipe)
        if self._current().type not in (TokenType.PIPE, TokenType.EOF):
            query.filter_expr = self._parse_or_expr()

        # Parse pipe commands
        while self._match(TokenType.PIPE):
            cmd = self._parse_pipe_command()
            query.commands.append(cmd)

        if self._current().type != TokenType.EOF:
            raise ParseError(
                f"Unexpected token {self._current().value!r}",
                self._current(),
            )

        return query

    def _extract_time_modifiers(self, query: Query) -> None:
        """Look for earliest=... and latest=... at the beginning of the query."""
        while True:
            tok = self._current()
            if tok.type == TokenType.FIELD and tok.value.lower() in ("earliest", "latest"):
                next_tok = self._peek(1)
                if next_tok.type == TokenType.EQ:
                    name = tok.value.lower()
                    self._advance()  # field name
                    self._advance()  # =
                    val_tok = self._advance()
                    val = val_tok.value
                    if name == "earliest":
                        query.earliest = val
                    else:
                        query.latest = val
                    continue
            break

    # -------------------------------------------------------------------
    # Expression parsing (precedence climbing)
    # -------------------------------------------------------------------

    def _parse_or_expr(self) -> ASTNode:
        left = self._parse_and_expr()
        while self._current().type == TokenType.OR:
            self._advance()
            right = self._parse_and_expr()
            left = BoolOp(op="OR", left=left, right=right)
        return left

    def _parse_and_expr(self) -> ASTNode:
        left = self._parse_not_expr()
        while self._current().type == TokenType.AND:
            self._advance()
            right = self._parse_not_expr()
            left = BoolOp(op="AND", left=left, right=right)
        return left

    def _parse_not_expr(self) -> ASTNode:
        if self._current().type == TokenType.NOT:
            self._advance()
            operand = self._parse_not_expr()
            return NotExpr(operand=operand)
        return self._parse_primary()

    def _parse_primary(self) -> ASTNode:
        tok = self._current()

        # Parenthesized expression
        if tok.type == TokenType.LPAREN:
            self._advance()
            expr = self._parse_or_expr()
            self._expect(TokenType.RPAREN)
            return expr

        # Field comparison
        if tok.type == TokenType.FIELD:
            return self._parse_comparison()

        raise ParseError(
            f"Expected field name or '(', got {tok.type.name} ({tok.value!r})",
            tok,
        )

    def _parse_comparison(self) -> Comparison:
        field_ref = self._parse_field_ref()
        op_tok = self._current()

        if op_tok.type not in _OPERATOR_TYPES:
            raise ParseError(
                f"Expected operator after field '{field_ref.name}', got {op_tok.type.name}",
                op_tok,
            )

        op = self._advance()
        operator = op.value

        # For IN / NOT IN, expect parenthesized value list
        if op.type in (TokenType.IN, TokenType.NOT_IN):
            value = self._parse_value_list()
        else:
            value = self._parse_value()

        return Comparison(field=field_ref, operator=operator, value=value)

    def _parse_field_ref(self) -> FieldRef:
        parts: list[str] = []
        tok = self._expect(TokenType.FIELD)
        parts.append(tok.value)
        while self._current().type == TokenType.DOT:
            self._advance()
            tok = self._expect(TokenType.FIELD)
            parts.append(tok.value)
        return FieldRef(parts=parts)

    def _parse_value(self) -> ASTNode:
        tok = self._current()
        if tok.type in (TokenType.STRING, TokenType.WILDCARD, TokenType.REGEX):
            self._advance()
            return Literal(value=tok.value, token=tok)
        if tok.type == TokenType.NUMBER:
            self._advance()
            val = float(tok.value) if "." in tok.value else int(tok.value)
            return Literal(value=val, token=tok)
        if tok.type == TokenType.FIELD:
            # Unquoted string value
            self._advance()
            return Literal(value=tok.value, token=tok)
        raise ParseError(f"Expected value, got {tok.type.name} ({tok.value!r})", tok)

    def _parse_value_list(self) -> ValueList:
        self._expect(TokenType.LPAREN)
        values: list[Literal] = []
        while self._current().type != TokenType.RPAREN:
            if values:
                self._expect(TokenType.COMMA)
            val = self._parse_value()
            if isinstance(val, Literal):
                values.append(val)
            else:
                raise ParseError("Expected literal value in list", self._current())
        self._expect(TokenType.RPAREN)
        return ValueList(values=values)

    # -------------------------------------------------------------------
    # Pipe command parsing
    # -------------------------------------------------------------------

    def _parse_pipe_command(self) -> PipeCommand:
        """Parse a pipe command after the | token.

        Collects the command name and all remaining tokens until the next pipe
        or EOF as raw arguments.
        """
        name_tok = self._current()
        if name_tok.type != TokenType.FIELD:
            raise ParseError(
                f"Expected command name after '|', got {name_tok.type.name}",
                name_tok,
            )
        self._advance()
        name = name_tok.value.lower()

        # Collect all remaining tokens as args until next PIPE or EOF
        args: list[str] = []
        raw_parts: list[str] = []
        while self._current().type not in (TokenType.PIPE, TokenType.EOF):
            tok = self._advance()
            args.append(tok.value)
            raw_parts.append(tok.value)

        return PipeCommand(
            name=name,
            args=args,
            raw_text=" ".join(raw_parts),
        )
