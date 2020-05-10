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
    err += run_script('echo start; ( sleep 0; echo done ) & echo waiting ; wait ; echo finish',
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

    var = "var=foo;"
    err += run_arg_expansion(r''' $var ''', ['foo'], pre=var)
    err += run_arg_expansion(r''' ${var} ''', ['foo'], pre=var)
    err += run_arg_expansion(r''' "${var}" ''', ['foo'], pre=var)
    err += run_arg_expansion(r''' " ${var} " ''', [' foo '], pre=var)
    err += run_arg_expansion(r''' ' $var ' ''', [' $var '], pre=var)
    err += run_arg_expansion(r''' ' ${var} ' ''', [' ${var} '], pre=var)
    var = "var='foo  bar';"
    err += run_arg_expansion(r''' $var ''', ['foo', 'bar'], pre=var)
    err += run_arg_expansion(r''' ${var} ''', ['foo', 'bar'], pre=var)
    err += run_arg_expansion(r''' "${var}" ''', ['foo  bar'], pre=var)
    err += run_arg_expansion(r''' " ${var} " ''', [' foo  bar '], pre=var)
    err += run_arg_expansion(r''' ' $var ' ''', [' $var '], pre=var)
    err += run_arg_expansion(r''' ' ${var} ' ''', [' ${var} '], pre=var)

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

    # fork bomb bug?
    # err += run_arg_expansion(r''' $( (echo a;echo b) | grep a) ''', ['a'])

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

    if out != exp:
        err("%-40s GOT %s EXPECTED %s"%(script, out, exp))
        if OPTS.stop:
            print('  ', '-'*70, '\n', r, sep='', end='')
            exit(1)
        return 1
    if pox != exp:
        warn("%-40s POSIX %s EXPECTED %s"%(script, pox, exp))
    if OPTS.verbose >= 1 and out == exp:
        ok("%-40s => %s"%(script, out))
    return 0

def run_arg_expansion(arg, expected, pre=''):
    r = run(pre+'./dump_argv '+arg)
    out = re.findall(r'''^<(.*?)>$''', r.scriptout, flags=(re.M|re.S))

    if OPTS.verbose >= 2:
        print('  ', '-'*70, '\n', r, sep='', end='')

    rr = run_posix(pre+'./dump_argv '+arg)
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
        r = sp.run(PROG, input=script, timeout=1, encoding='utf-8', capture_output=True)
    except sp.TimeoutExpired as e:
        raise TimeoutError("process took over %ds"%TIMEOUT) from e
    if r.returncode < 0:
        raise SignalError('signaled %d'%(-r.returncode), r)
    if r.returncode > 0:
        raise ExitError('exit failure %d'%(r.returncode), r)
    if 'syntax error' in r.stdout or 'syntax error' in r.stderr:
        raise ParseError('parse error', script, r)
    return Result(script, r)

def run_posix(script):
    rr = sp.run('dash', input=script, timeout=6, encoding='utf-8', capture_output=True)
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
    def __init__(self, message, result):
        super().__init__(message)
        self.result = result
class ParseError(TestException):
    def __init__(self, message, script, result):
        super().__init__(message)
        self.script = script
        self.result = result
    def __str__(self):
        return "%s: %s\n%s"%(super().__str__(),self.script,self.result.stdout)
class OutputError(TestException):
    def __init__(self, message, result):
        super().__init__(message)
        self.result = result
class ExitError(TestException):
    def __init__(self, message, result):
        super().__init__(message)
        self.result = result
class MismatchError(TestException):
    def __init__(self, message):
        super().__init__(message)
class TimeoutError(TestException):
    def __init__(self, message):
        super().__init__(message)

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
