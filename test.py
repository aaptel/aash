#!/usr/bin/env python3
import os
import sys
import re
import subprocess as sp
import argparse
from pprint import pprint as P

PROG = './aash'
TIMEOUT = 1
OPTS = None

def main():
    ap = argparse.ArgumentParser(description="aash tester script")
    ap.add_argument("-v", "--verbose", action="count", default=0, help="show detailed output")
    ap.add_argument("-s", "--stop", action="store_true", help="stop on failure and show detailed output")
    ap.add_argument("-p", "--posix", default='sh', help="POSIX shell to use to compare outputs (sh, dash, ...)")
    ap.add_argument("-f", "--filter",  help="filter test names")
    ap.add_argument("-l", "--list", action="store_true", help="list tests")

    global OPTS
    OPTS = ap.parse_args()

    for k,v in globals().items():
        if k.startswith('test_') and hasattr(v, '__call__'):
            if OPTS.filter and OPTS.filter not in k:
                continue
            if OPTS.list:
                print(k)
                continue

            printcol('1', k)
            try:
                v()
            except TestException as e:
                reserr(e, end='')
            else:
                resok("OK", end='')
            finally:
                print('\n')

def test_background():
    err = 0
    err += run_script(
        '''echo start ; ( sleep 0; echo done ) &
        echo waiting ; wait
        echo finish''',
        'start\nwaiting\ndone\nfinish\n', '', 0)
    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_bool():
    err = 0
    err += run_script('true', '', '', 0)
    err += run_script('false', '', '', 1)

    err += run_script('! true', '', '', 1)
    err += run_script('! false', '', '', 0)

    err += run_script('true;false', '', '', 1)
    err += run_script('false;true', '', '', 0)

    err += run_script('true  || true',  '', '', 0)
    err += run_script('true  || false', '', '', 0)
    err += run_script('false || true',  '', '', 0)
    err += run_script('false || false', '', '', 1)

    err += run_script('true  && true',  '', '', 0)
    err += run_script('true  && false', '', '', 1)
    err += run_script('false && true',  '', '', 1)
    err += run_script('false && false', '', '', 1)

    err += run_script('! ( true  || true )', '', '', 1)
    err += run_script('! ( true  || false)', '', '', 1)
    err += run_script('! ( false || true )', '', '', 1)
    err += run_script('! ( false || false)', '', '', 0)

    err += run_script('! ( true  && true )', '', '', 1)
    err += run_script('! ( true  && false)', '', '', 0)
    err += run_script('! ( false && true )', '', '', 0)
    err += run_script('! ( false && false)', '', '', 0)

    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_pipe_redir():
    err = 0
    err += run_script('echo a', 'a\n', '', 0)
    err += run_script('echo a 1>&2', '', 'a\n', 0)
    err += run_script('echo a | grep a', 'a\n', '', 0)
    err += run_script('echo a 1>&2 | grep a', '', 'a\n', 1)
    err += run_script('echo b | grep a', '', '', 1)
    err += run_script('( echo aa; echo ab; echo bb) | grep a | grep b', 'ab\n', '', 0)
    err += run_script('( echo a 1>&2 ) 2>&1 | grep a', 'a\n', '', 0)
    err += run_script('echo a > /tmp/f; cat /tmp/f ;', 'a\n', '', 0)
    err += run_script('echo a > /tmp/f; cat < /tmp/f ;', 'a\n', '', 0)
    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_arg_expansion():
    err = 0
    err += run_arg_expansion(r''' a b c ''', ['a', 'b', 'c'])
    err += run_arg_expansion(r'''aa bb cc''', ['aa', 'bb', 'cc'])
    err += run_arg_expansion(r'''a   b   c''', ['a', 'b', 'c'])
    err += run_arg_expansion(r''' 'a b  c' ''', ['a b  c'])
    err += run_arg_expansion(r''' "a b c" ''', ['a b c'])
    err += run_arg_expansion(r''' "a b c" ''', ['a b c'])
    err += run_arg_expansion(r''' "a\ b c" ''', ['a b c'])
    err += run_arg_expansion(r''' 'a\ b c' ''', ['a b c'])
    err += run_arg_expansion(r''' a\ b ''', ['a b'])
    err += run_arg_expansion(r''' a" bc "\ d'ef ' ''', ['a bc  def '])
    err += run_arg_expansion(r"     ''      ", [''])
    err += run_arg_expansion(r"     '' ''   ", ['', ''])
    err += run_arg_expansion(r"     $undef       ", [])
    err += run_arg_expansion(r"     ''$undef     ", [''])
    err += run_arg_expansion(r"     ''$undef''   ", [''])
    err += run_arg_expansion(r"     ''''    ", [''])
    err += run_arg_expansion(r'     ""      ', [''])
    err += run_arg_expansion(r'     "" ""   ', ['', ''])
    err += run_arg_expansion(r'     """"    ', [''])

    err += run_arg_expansion(r"     ''      x", ['', 'x'])
    err += run_arg_expansion(r"     '' ''   x", ['', '', 'x'])
    err += run_arg_expansion(r"     $undef     x  ", ['x'])
    err += run_arg_expansion(r"     ''$undef   x  ", ['', 'x'])
    err += run_arg_expansion(r"     ''$undef'' x  ", ['', 'x'])
    err += run_arg_expansion(r"     ''''    x", ['', 'x'])
    err += run_arg_expansion(r'     ""      x', ['', 'x'])
    err += run_arg_expansion(r'     "" ""   x', ['', '', 'x'])
    err += run_arg_expansion(r'     """"    x', ['', 'x'])


    var = "var=foo; ./dump_argv"
    err += run_arg_expansion(r''' $var ''', ['foo'], pre=var)
    err += run_arg_expansion(r''' ${var} ''', ['foo'], pre=var)
    err += run_arg_expansion(r''' "${var}" ''', ['foo'], pre=var)
    err += run_arg_expansion(r''' " ${var} " ''', [' foo '], pre=var)
    err += run_arg_expansion(r''' ' $var ' ''', [' $var '], pre=var)
    err += run_arg_expansion(r''' ' ${var} ' ''', [' ${var} '], pre=var)
    var = "var='foo  bar'; ./dump_argv"
    err += run_arg_expansion(r''' $var ''', ['foo', 'bar'], pre=var)
    err += run_arg_expansion(r''' ${var} ''', ['foo', 'bar'], pre=var)
    err += run_arg_expansion(r''' "${var}" ''', ['foo  bar'], pre=var)
    err += run_arg_expansion(r''' " ${var} " ''', [' foo  bar '], pre=var)
    err += run_arg_expansion(r''' ' $var ' ''', [' $var '], pre=var)
    err += run_arg_expansion(r''' ' ${var} ' ''', [' ${var} '], pre=var)
    var = "var=; ./dump_argv"
    err += run_arg_expansion(r''' $var ''', [], pre=var)
    err += run_arg_expansion(r''' ${var} ''', [], pre=var)
    err += run_arg_expansion(r''' "${var}" ''', [''], pre=var)
    err += run_arg_expansion(r''' " ${var} " ''', ['  '], pre=var)
    err += run_arg_expansion(r''' ' $var ' ''', [' $var '], pre=var)
    err += run_arg_expansion(r''' ' ${var} ' ''', [' ${var} '], pre=var)
    var = "./dump_argv"
    err += run_arg_expansion(r''' $var ''', [], pre=var)
    err += run_arg_expansion(r''' ${var} ''', [], pre=var)
    err += run_arg_expansion(r''' "${var}" ''', [''], pre=var)
    err += run_arg_expansion(r''' " ${var} " ''', ['  '], pre=var)
    err += run_arg_expansion(r''' ' $var ' ''', [' $var '], pre=var)
    err += run_arg_expansion(r''' ' ${var} ' ''', [' ${var} '], pre=var)

    pre = 'function f(){ ./dump_argv $@ ; } ; f '
    err += run_arg_expansion(r'', [], pre=pre)
    err += run_arg_expansion(r''' a b c ''', ['a', 'b', 'c'], pre=pre)
    err += run_arg_expansion(r''' aa bb cc ''', ['aa', 'bb', 'cc'], pre=pre)
    err += run_arg_expansion(r''' "aa" "bb" "cc" ''', ['aa', 'bb', 'cc'], pre=pre)
    err += run_arg_expansion(r''' "aa bb" "cc" ''', ['aa', 'bb', 'cc'], pre=pre)
    pre = 'function f(){ ./dump_argv "$@" ; } ; f '
    err += run_arg_expansion(r'', [], pre=pre)
    err += run_arg_expansion(r''' a b c ''', ['a', 'b', 'c'], pre=pre)
    err += run_arg_expansion(r''' aa bb cc ''', ['aa', 'bb', 'cc'], pre=pre)
    err += run_arg_expansion(r''' "aa" "bb" "cc" ''', ['aa', 'bb', 'cc'], pre=pre)
    err += run_arg_expansion(r''' "aa bb" "cc" ''', ['aa bb', 'cc'], pre=pre)
    pre = 'function f(){ ./dump_argv "x$@y" ; } ; f '
    err += run_arg_expansion(r'', ['xy'], pre=pre)
    err += run_arg_expansion(r''' a b c ''', ['xa', 'b', 'cy'], pre=pre)
    err += run_arg_expansion(r''' aa bb cc ''', ['xaa', 'bb', 'ccy'], pre=pre)
    err += run_arg_expansion(r''' "aa" "bb" "cc" ''', ['xaa', 'bb', 'ccy'], pre=pre)
    err += run_arg_expansion(r''' "aa bb" "cc" ''', ['xaa bb', 'ccy'], pre=pre)

    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_subshell_expand():
    err = 0
    err += run_arg_expansion(r''' $(echo a) ''', ['a'])
    err += run_arg_expansion(r''' "$(echo a)" ''', ['a'])
    err += run_arg_expansion(r''' '$(echo a)' ''', ['$(echo a)'])
    err += run_arg_expansion(r''' x$(echo a)x ''', ['xax'])
    err += run_arg_expansion(r''' "x$(echo a)x" ''', ['xax'])
    err += run_arg_expansion(r''' $(echo a b) ''', ['a', 'b'])
    err += run_arg_expansion(r''' '$(echo a b)' ''', ['$(echo a b)'])
    err += run_arg_expansion(r''' x$(echo a b)x ''', ['xa', 'bx'])
    err += run_arg_expansion(r''' "$(echo a b)" ''', ['a b'])
    err += run_arg_expansion(r''' "x$(echo a b)x" ''', ['xa bx'])
    err += run_arg_expansion(r''' "x $(echo a b) x" ''', ['x a b x'])

    # nesting...
    err += run_arg_expansion(r''' $(echo a $(echo b)) ''', ['a','b'])
    err += run_arg_expansion(r''' "$(echo a $(echo b))" ''', ['a b'])
    err += run_arg_expansion(r''' "$(echo a '$(echo b)')" ''', ['a $(echo b)'])
    err += run_arg_expansion(r''' "$(echo a "$(echo b)")" ''', ['a b'])
    err += run_arg_expansion(r''' $(echo a "$(echo b)") ''', ['a', 'b'])
    err += run_arg_expansion(r''' $(echo a "$(echo a b)") ''', ['a', 'a', 'b'])
    err += run_arg_expansion(r''' $(echo a | grep a) ''', ['a'])
    err += run_arg_expansion(r''' $( (echo a;echo b)|grep a) ''', ['a'])

    # POSIX tells us $(( is start of arithmetic expression... ignore
    err += run_arg_expansion(r''' $((echo a;echo b)|grep a) ''', ['a'])

    # weird nesting and quotes...
    err += run_arg_expansion(r''' $( (echo a;echo b)|grep a && (echo a;echo $(echo b))|grep b) ''', ['a', 'b'])
    err += run_arg_expansion(r''' "$( echo "$(echo a)" )" ''', ['a'])
    err += run_arg_expansion(r''' "$( echo '$(echo a)' )" ''', ['$(echo a)'])

    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_vars():
    err = 0
    err += run_script('var="echo foo"; $var', 'foo\n', '', 0)
    err += run_script('var=a; echo $var; var=b; echo $var', 'a\nb\n', '', 0)
    err += run_script('var="$(echo a b)"; echo $var', 'a b\n', '', 0)
    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_reserved_words():
    err = 0
    reserved = 'for in do done while until if fi then else elif case esac function'.split()
    for w in reserved:
        err += run_script('echo %s'%w, '%s\n'%w, '', 0)
        err += run_script('%s=foo; echo $%s'%(w,w), 'foo\n', '', 0)
        err += run_script('%s=%s; echo $%s'%(w,w,w), '%s\n'%w, '', 0)
    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_for_loop():
    err = 0
    err += run_script('for i in a b c; do echo $i; done', 'a\nb\nc\n', '', 0)
    err += run_script('for i in a "b c"; do echo $i; done', 'a\nb c\n', '', 0)
    err += run_script('for i in a "b c"; do echo $i; echo x$i; done', 'a\nxa\nb c\nxb c\n', '', 0)
    err += run_script('v=foo; for i in a "$v c"; do echo $v$i; done', 'fooa\nfoofoo c\n', '', 0)
    err += run_script('for i in $(seq 10); do echo $i; done', ''.join(["%d\n"%(i+1) for i in range(10)]), '', 0)
    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_braces():
    err = 0
    # POSIX requires a ";" here but aash doesn't :)
    err += run_script('{ echo a }', 'a\n', '', 0)
    err += run_script('{ echo a; }', 'a\n', '', 0)
    err += run_script('{ { echo a; } }', 'a\n', '', 0)
    err += run_script('{ { echo a; } ; { echo b; } }', 'a\nb\n', '', 0)
    err += run_script('{ { echo a; } ; { echo b; } }', 'a\nb\n', '', 0)
    err += run_script('a=1 ; { a=2 ; } ; echo $a', '2\n', '', 0)
    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_functions():
    err = 0

    err += run_script('function foo() { echo a; }', '', '', 0)
    err += run_script('function foo() { echo a; } ; foo', 'a\n', '', 0)
    err += run_script('function foo() { echo $1; } ; foo a', 'a\n', '', 0)
    err += run_script('function foo() { echo $1; } ; foo "a b"', 'a b\n', '', 0)
    err += run_script('bar="a b"; function foo() { echo $1; } ; foo $bar', 'a\n', '', 0)
    err += run_script('function func1() { echo $1; func2; echo $1;} ; function func2() { echo $1; } ; func1 a',
                      'a\n\na\n', '', 0)
    err += run_script('function func1() { echo $1; func2 x; echo $1;} ; function func2() { echo $1; } ; func1 a',
                      'a\nx\na\n', '', 0)
    err += run_script('function func1() { echo $1 $2; func2; echo $1 $2;} ; function func2() { echo $1 $2; } ; func1 a b',
                      'a b\n\na b\n', '', 0)

    err += run_script('function foo() { echo $#; } ; foo ', '0\n', '', 0)
    err += run_script('function foo() { echo $#; } ; foo a', '1\n', '', 0)
    err += run_script('function foo() { echo $#; } ; foo a a', '2\n', '', 0)

    if err > 0:
        raise MismatchError("%d mismatches"%err)

def test_if():
    err = 0
    err += run_script('if true; then echo a; else echo b; fi', 'a\n', '', 0)
    err += run_script('if true; then echo a; echo a; else echo b; fi', 'a\na\n', '', 0)
    err += run_script('if false; then echo a; else echo b; fi', 'b\n', '', 0)
    err += run_script('if false; then echo a; else echo b; echo b; fi', 'b\nb\n', '', 0)
    err += run_script('if false; then echo a; elif false; then echo b; else echo c; fi', 'c\n', '', 0)
    if err > 0:
        raise MismatchError("%d mismatches"%err)

def run_script(script, exp_out, exp_err, exp_rc):
    r = run(script)
    rposix = run_posix(script)

    if OPTS.verbose >= 2:
        print('  ', '-'*70, '\n', r, sep='', end='')

    out = (r.scriptout, r.stderr, r.scriptrc)
    pox = (rposix.stdout, rposix.stderr, rposix.returncode)
    exp = (exp_out, exp_err, exp_rc)

    if pox != exp:
        warn("%-40s POSIX %s EXPECTED %s"%(script, pox, exp))
    if out != exp:
        err("%-40s GOT %s EXPECTED %s"%(script, out, exp))
        if OPTS.stop:
            print('  ', '-'*70, '\n', r, sep='', end='')
            exit(1)
        return 1
    if OPTS.verbose >= 1 and out == exp:
        ok("%-40s => %s"%(script, out))
    return 0

def run_arg_expansion(arg, expected, pre=None):
    if pre is None:
        pre = './dump_argv '
    r = run(pre+arg)
    out = re.findall(r'''^<(.*?)>$''', r.scriptout, flags=(re.M|re.S))

    if OPTS.verbose >= 2:
        print('  ', '-'*70, '\n', r, sep='', end='')

    rr = run_posix(pre+arg)
    posix = re.findall(r'''^<(.*?)>$''', rr.stdout, flags=(re.M|re.S))

    if posix != expected:
        if posix == out:
            err('%-40s => POSIX %s UPDATE EXPECTED! %s'%(arg, posix, expected))
            return 1
        warn('%-40s => POSIX %s EXPECTED %s'%(arg, posix, expected))

    if out != expected:
        err('%-40s => %s (expected %s)'%(arg, out, expected))
        if OPTS.stop:
            print('  ', '-'*70, '\n', r, sep='', end='')
            exit(1)
        return 1
    if OPTS.verbose >= 1 and out == expected:
        ok('%-40s => %s'%(arg, out))
    return 0

def run(script):
    try:
        r = sp.run([PROG, '--debug', '-c', script], timeout=TIMEOUT, encoding='utf-8', capture_output=True)
    except sp.TimeoutExpired as e:
        raise TimeoutError("process took over %ds"%TIMEOUT, script) from e
    if r.returncode < 0:
        raise SignalError('signaled %d'%(-r.returncode), script, r)
    if r.returncode > 0:
        raise ExitError('exit failure %d'%(r.returncode), script, r)
    if 'syntax error' in r.stdout or 'syntax error' in r.stderr:
        raise ParseError('parse error', script, r)
    return Result(script, r)

def run_posix(script):
    rr = sp.run(OPTS.posix, input=script, timeout=TIMEOUT, encoding='utf-8', capture_output=True)
    return rr

class Result:
    def __init__(self, script, sp_res):
        self.script = script
        self.returncode = sp_res.returncode
        self.stdout = sp_res.stdout
        self.stderr = sp_res.stderr
        m = re.search(
            '^=== RUNNING ===\n(.*)^RESULT = (\d+) \(exit code=(\d+)\)',
            self.stdout, flags=re.M|re.S)
        if not m:
            raise OutputError('no running section in output', sp_res)
        self.scriptout = m.group(1)
        self.scriptstatus = int(m.group(2))
        self.scriptrc = int(m.group(3))

    def __str__(self):
        s = '  Result rc=%d script_status=%d script_rc=%d\n'%(self.returncode, self.scriptstatus, self.scriptrc)
        s += wrap('  IN:   ', self.script)
        s += wrap('  AASH: ', self.stdout)
        s += wrap('  OUT:  ', self.scriptout)
        s += wrap('  \033[31mERR:  \033[0m', self.stderr)
        return s

class TestException(Exception):
    def __init__(self, message):
        super().__init__(message)
class SignalError(TestException):
    def __init__(self, message, script, result):
        super().__init__(message)
        self.script = script
        self.result = result
    def __str__(self):
        return "%s: %s\n%s\n%s"%(super().__str__(),self.script,self.result.stdout,self.result.stderr)
class ParseError(TestException):
    def __init__(self, message, script, result):
        super().__init__(message)
        self.script = script
        self.result = result
    def __str__(self):
        return "%s: %s\n%s\n%s"%(super().__str__(),self.script,self.result.stdout,self.result.stderr)
class OutputError(TestException):
    def __init__(self, message, script, result):
        super().__init__(message)
        self.result = result
    def __str__(self):
        return "%s: %s\n%s\n%s"%(super().__str__(),self.script,self.result.stdout,self.result.stderr)
class ExitError(TestException):
    def __init__(self, message, script, result):
        super().__init__(message)
        self.script = script
        self.result = result
    def __str__(self):
        return "%s: %s\n%s\n%s"%(super().__str__(),self.script,self.result.stdout,self.result.stderr)
class MismatchError(TestException):
    def __init__(self, message):
        super().__init__(message)
class TimeoutError(TestException):
    def __init__(self, message, script):
        super().__init__(message)
        self.script = script
    def __str__(self):
        return "%s: %s\n"%(super().__str__(),self.script)

# class Unbuffered(object):
#    def __init__(self, stream):
#        self.stream = stream
#    def write(self, data):
#        self.stream.write(data)
#        self.stream.flush()
#    def writelines(self, datas):
#        self.stream.writelines(datas)
#        self.stream.flush()
#    def __getattr__(self, attr):
#        return getattr(self.stream, attr)

# sys.stdout = Unbuffered(sys.stdout)

def wrap(prefix, s):
    if s == '' or s is None:
        return ''
    while len(s) > 0 and s[-1] == '\n':
        s = s[:-1]
    s = prefix + s.replace('\n', '\n'+prefix) + '\n'
    return s

def escnl(s):
    return '"'+s.replace('\n', '\\n')+'"'

def err(*args, end='\n'):
    printcol('31', '  FAIL:', *args, end=end)

def ok(*args, end='\n'):
    printcol('32', '  OK:  ', *args, end=end)

def reserr(*args, end='\n'):
    printcol('31;1', *args, end=end)

def warn(*args, end='\n'):
    printcol('33', '  WARN:', *args, end=end)

def resok(*args, end='\n'):
    printcol('32;1', *args, end=end)

def printcol(col, *args, end='\n'):
    print("\033[%sm"%col, end='')
    print(*args, end='\033[0m'+end)

if __name__ == '__main__':
    main()



#a bc  def
#POSIX ['a bc  def ']
#EXPED ['a bc  def ']
