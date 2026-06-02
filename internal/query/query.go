// Package query implements Archer's findings query language — a practical
// subset of Lucene-style syntax evaluated over the in-memory finding slice.
//
// Grammar: field terms (type:Beacon), boolean AND/OR/NOT with implicit-AND
// between adjacent terms, grouping with (), quoted phrases, numeric
// comparisons (score:>=90) and ranges (score:[80 TO 100]), and leading/
// trailing wildcards on string fields. A bare term with no field is a
// case-insensitive substring match across the same fields the legacy Search
// box covered, preserving existing muscle memory.
package query

import (
	"fmt"
	"strings"
	"time"

	"github.com/BushidoCyb3r/Archer/internal/model"
)

// Query is a parsed, ready-to-evaluate query expression.
type Query struct {
	root node
}

// Parse compiles a query string into a Query. An empty or whitespace-only
// string parses to a Query that matches every finding.
func Parse(input string) (*Query, error) {
	toks, err := lex(input)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return &Query{root: matchAll{}}, nil
	}
	p := &parser{toks: toks}
	root, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if !p.atEnd() {
		return nil, fmt.Errorf("unexpected %q", p.peek().text)
	}
	return &Query{root: root}, nil
}

// Match reports whether f satisfies the query. opLoc is the operator's
// timezone, used to interpret bare date/datetime literals in ts: predicates;
// the finding's own Timestamp is always read as UTC.
func (q *Query) Match(f model.Finding, opLoc *time.Location) bool {
	if opLoc == nil {
		opLoc = time.UTC
	}
	return q.root.eval(f, opLoc)
}

// ---- AST ----

type node interface {
	eval(f model.Finding, opLoc *time.Location) bool
}

type matchAll struct{}

func (matchAll) eval(model.Finding, *time.Location) bool { return true }

type andNode struct{ left, right node }

func (n andNode) eval(f model.Finding, loc *time.Location) bool {
	return n.left.eval(f, loc) && n.right.eval(f, loc)
}

type orNode struct{ left, right node }

func (n orNode) eval(f model.Finding, loc *time.Location) bool {
	return n.left.eval(f, loc) || n.right.eval(f, loc)
}

type notNode struct{ inner node }

func (n notNode) eval(f model.Finding, loc *time.Location) bool {
	return !n.inner.eval(f, loc)
}

// ---- Lexer ----

type tokKind int

const (
	tokTerm tokKind = iota
	tokAnd
	tokOr
	tokNot
	tokLParen
	tokRParen
)

type token struct {
	kind tokKind
	text string // raw term text for tokTerm
}

// lex splits the input into tokens. A term token is a maximal run with no
// whitespace or parens, except that a double-quoted phrase and a bracketed
// range keep their internal spaces. Bare AND/OR/NOT (case-insensitive) are
// recognized as operators.
func lex(input string) ([]token, error) {
	var toks []token
	r := []rune(input)
	i := 0
	for i < len(r) {
		c := r[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, token{kind: tokLParen})
			i++
		case c == ')':
			toks = append(toks, token{kind: tokRParen})
			i++
		default:
			start := i
			var b strings.Builder
			for i < len(r) {
				c = r[i]
				if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '(' || c == ')' {
					break
				}
				if c == '"' {
					b.WriteRune(c)
					i++
					closed := false
					for i < len(r) {
						b.WriteRune(r[i])
						if r[i] == '"' {
							i++
							closed = true
							break
						}
						i++
					}
					if !closed {
						return nil, fmt.Errorf("unterminated quote at %d", start)
					}
					continue
				}
				if c == '[' {
					b.WriteRune(c)
					i++
					closed := false
					for i < len(r) {
						b.WriteRune(r[i])
						if r[i] == ']' {
							i++
							closed = true
							break
						}
						i++
					}
					if !closed {
						return nil, fmt.Errorf("unterminated range at %d", start)
					}
					continue
				}
				b.WriteRune(c)
				i++
			}
			text := b.String()
			switch strings.ToUpper(text) {
			case "AND":
				toks = append(toks, token{kind: tokAnd})
			case "OR":
				toks = append(toks, token{kind: tokOr})
			case "NOT":
				toks = append(toks, token{kind: tokNot})
			default:
				toks = append(toks, token{kind: tokTerm, text: text})
			}
		}
	}
	return toks, nil
}

// ---- Parser (recursive descent) ----
//
// expr    := orExpr
// orExpr  := andExpr (OR andExpr)*
// andExpr := unary ((AND)? unary)*
// unary   := NOT unary | primary
// primary := '(' expr ')' | TERM

type parser struct {
	toks []token
	pos  int
}

func (p *parser) atEnd() bool { return p.pos >= len(p.toks) }
func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *parser) parseExpr() (node, error) { return p.parseOr() }

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for !p.atEnd() && p.peek().kind == tokOr {
		p.next()
		if p.atEnd() {
			return nil, fmt.Errorf("trailing OR")
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for !p.atEnd() {
		k := p.peek().kind
		if k == tokAnd {
			p.next()
			if p.atEnd() {
				return nil, fmt.Errorf("trailing AND")
			}
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = andNode{left, right}
			continue
		}
		// Implicit AND: another unary starts here (term, NOT, or '(').
		if k == tokTerm || k == tokNot || k == tokLParen {
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = andNode{left, right}
			continue
		}
		break
	}
	return left, nil
}

func (p *parser) parseUnary() (node, error) {
	if p.atEnd() {
		return nil, fmt.Errorf("unexpected end of query")
	}
	if p.peek().kind == tokNot {
		p.next()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (node, error) {
	if p.atEnd() {
		return nil, fmt.Errorf("unexpected end of query")
	}
	t := p.peek()
	switch t.kind {
	case tokLParen:
		p.next()
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.atEnd() || p.peek().kind != tokRParen {
			return nil, fmt.Errorf("unbalanced parentheses")
		}
		p.next()
		return inner, nil
	case tokTerm:
		p.next()
		return parseTerm(t.text)
	case tokAnd, tokOr:
		return nil, fmt.Errorf("unexpected operator")
	default:
		return nil, fmt.Errorf("unexpected %q", t.text)
	}
}
