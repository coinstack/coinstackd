// Copyright (c) 2016 BLOCKO INC.
package sql

import "strings"

var stmt = map[string]bool{
	"ALTER":   true,
	"CREATE":  true,
	"DELETE":  true,
	"DROP":    true,
	"INSERT":  true,
	"REINDEX": true,
	"REPLACE": true,
	"SELECT":  true,
	"UPDATE":  true,
}

var readOnlyStmt = map[string]bool{
	"SELECT": true,
}

func IsPermittedSql(sql string) bool {
	keyword, endOffset := getKeyword(sql)
	if endOffset > -1 {
		if keyword == "CREATE" {
			switch keyword, _ = getKeyword(sql[endOffset:]); keyword {
			case "TRIGGER", "VIRTUAL", "TEMP", "TEMPORARY":
				return false
			default:
				return true
			}
		} else {
			_, ok := stmt[keyword]
			return ok
		}
	}
	return false
}

func IsPermittedReadOnlySql(sql string) bool {
	keyword, endOffset := getKeyword(sql)
	if endOffset > -1 {
		_, ok := readOnlyStmt[keyword]
		return ok
	}
	return false
}

func getKeyword(sql string) (string, int) {
	var inBlockComment bool
	var inLineComment bool
	startKeywordIndex := -1
	var endKeywordIndex int
	l := len(sql)

Loop:
	for i := 0; i < l; i++ {
		c := sql[i]
		switch c {
		case ' ', '\t':
			if startKeywordIndex > -1 {
				endKeywordIndex = i
				break Loop
			}
		case '\n':
			if inLineComment {
				inLineComment = false
			}
			if startKeywordIndex > -1 {
				endKeywordIndex = i
				break Loop
			}
		case '/':
			if startKeywordIndex > -1 {
				endKeywordIndex = i
				break Loop
			}
			if !inBlockComment && !inLineComment && i+1 < l {
				switch sql[i+1] {
				case '*':
					inBlockComment = true
					i++
				case '/':
					inLineComment = true
					i++
				}
			}
		case '*':
			if inBlockComment {
				if i+1 < l {
					if sql[i+1] == '/' {
						inBlockComment = false
						i++
					}
				}
			}
		default:
			if !inLineComment && !inBlockComment && startKeywordIndex == -1 {
				startKeywordIndex = i
			}
		}
	}

	if startKeywordIndex > -1 && endKeywordIndex > startKeywordIndex {
		keyword := sql[startKeywordIndex:endKeywordIndex]
		return strings.ToUpper(keyword), endKeywordIndex
	}

	return "", -1
}
