/**
  ISC License Copyright (c) 2004-2010 by Internet Systems Consortium, Inc.
  ("ISC")

  Copyright (c) 2025 by HoJeong Go <seia@outlook.kr>

  Permission to
  use, copy, modify, and /or distribute this software for any purpose with or
  without fee is hereby granted, provided that the above copyright notice and this
  permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND
  HoJeong Go DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL HoJeong Go
  BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
  DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
  CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// transform.mjs by HoJeong Go <seia@outlook.kr>
// -- A tiny ad-filtering pattern list transformer.
//
// This tiny script is specially designed for small projects like individual
// filter lists to easily perform "compilation" (such as hosts file),
// "formatting", and "optimisation".
//
// Usage: node transform.mjs in > out 2> err
// Please, find the cheatsheet below or refer to the `getOpts` function for all
// available options. Using `-d` or `--debug` flag to allow warnings to be printed
// to stderr.
//
// Transforming filter list into hosts file format
// > node transform.mjs list.txt -f=hosts > list.hosts 2> list.hosts.err
// -- Using strict mode with `-s` flag
//    By default, (a) path-level exception that targets exception including path
//    such as `@@||domain.tld/a.js` and (b) third-party constraint exception that
//    targets `||domain.tld^$3p` will register more hostnames to exceptions to
//    prevent false-positives. Still regexp filters won't be compiled on runtime
//    but this will help to prevent blocking top-level loads accidentally. If you
//    wish to block every case as you don't expect access, using `-s` flag will
//    disable those features.
//
// Checking and formatting filter list
// > node transform.mjs list.txt -f=list -c > list.formatted.txt 2> list.formatted.err
// -- Using auto-fix with `-a` flag
//    It will automatically apply fixes on all possible checks whenever possible.
//    The format error will be printed to stderr in the following format:
//    > Format error: line="   ||domain.tld^" rule="no-whitespaces"
//    >                     ^^^
//    It might be easier to use diff generators to see overall changes.

import fs from 'node:fs/promises';

class ProgramError extends Error {
  toString() {
    return this.name + ': ' + this.message;
  }
}

// cli option parser
class ParseError extends ProgramError {
  static expectValue(opt) {
    return new this(`The value is expected for the option "${opt}"!`);
  }

  static expectValueKinds(opt, kinds) {
    return new this(`"${val}" is not expected for the option "${opt}"! Possible values are ${kinds.map(function (kind) { return `"${kind}"` }).join(', ')}`);
  }

  name = 'ParseError';

  toString() {
    return this.name + ': ' + this.message;
  }
}

const FORMAT_LIST = 'list';
const FORMAT_DNR = 'declarative-net-request';
const FORMAT_HOSTS = 'hosts';
const FORMAT_JSON = 'json';

function getOpts() {
  const argvs = process.argv.slice(2);
  let filepath = '';
  let format = '';
  let strict = false;
  let debug = false;
  let check = false;
  let fix = false;
  // parse
  let delimIndex = -1;
  let opt = '';
  let val = '';
  for (const argv of argvs) {
    if (argv.charCodeAt(0) === 45 /* '-' */) {
      delimIndex = argv.indexOf('=');
      opt = argv.slice(argv.charCodeAt(1) === 45 ? 2 : 1, delimIndex === -1 ? argv.length : delimIndex);
      val = delimIndex === -1 ? undefined : argv.slice(delimIndex + 1);
      switch (opt) {
        case 'i':
        case 'input':
          if (val === undefined) {
            throw ParseError.expectValue(opt);
          }
          filepath = val;
          break;
        case 's':
        case 'strict':
          strict = true;
          break;
        case 'd':
        case 'debug':
          debug = true;
          break;
        case 'c':
        case 'check':
          check = true;
          break;
        case 'a':
        case 'fix':
          fix = true;
          break;
        case 'f':
        case 'format':
          if (
            val !== FORMAT_LIST &&
            val !== FORMAT_DNR &&
            val !== FORMAT_HOSTS &&
            val !== FORMAT_JSON
          ) {
            throw ParseError.expectValueKinds('format', [/* FORMAT_LIST, FORMAT_DNR, */ FORMAT_HOSTS, FORMAT_JSON]);
          }
          format = val;
          break;
        default:
          throw new ParseError(`"${opt}" is not a valid option!`);
      }
    } else {
      filepath = argv;
    }
  }
  return {
    filepath,
    strict,
    debug,
    format,
    check,
    fix,
  };
}

// adblocker filter parser
class SyntaxError extends ProgramError {
  constructor(message, pos) {
    super(message);
    this.pos = pos;
  }

  name = 'SyntaxError';
  pos = -1;
}

const FILTER_TYPE_OTHERS = 0;
const FILTER_TYPE_NETWORK = 1;
const FILTER_TYPE_COSMETIC = 2;

function isWhitespace(c) {
  // check whitespaces and [DEL]
  return c <= 32 || c === 127;
}

function parseCosmeticFilter(line, i) {
  const details = {
    type: FILTER_TYPE_COSMETIC,
    line,
    hostname: line.slice(0, i),
    selector: FORMAT_LIST,
    isException: false,
  };
  let c = 0;
  for (i = i + 1; i < line.length; i++) {
    c = line.charCodeAt(i);
    if (c === 64 /* '@' */) {
      details.isException = true;
    } else if (c === 35 /* '#' */) {
      i++;
      break;
    } else {
      throw new SyntaxError(`Expected "#" or "@" for cosmetic filter marker but saw "${line.charAt(i)}" at position "${i}"!`);
    }
  }
  details.selector = line.slice(i);
  return details;
}

function parseNetworkFilter(line) {
  const details = {
    type: FILTER_TYPE_NETWORK,
    pattern: '',
    line,
    modifiers: [],
    isException: false,
    matchSubdomains: false,
    matchBeginningOfAddress: false,
    matchEndOfAddress: false,
    markers: {
      pattern: [-1, -1],
      modifiers: [],
    },
  }
  let i = 0;
  let c = 0;
  let k = 0;
  // skip whitespaces
  for (let i = 0; i < line.length; i++) {
    if (isWhitespace(line.charCodeAt(i)) === false) {
      details.markers.pattern[0] = [i];
      break;
    }
  }
  // check exception
  if (line.charCodeAt(i) === 64 /* '@' */ && line.charCodeAt(i + 1) === 64) {
    details.isException = true;
    i += 2;
  }
  // check pipes
  if (line.charCodeAt(i) === 124 /* '|' */) {
    if (line.charCodeAt(++i) === 124) {
      details.matchSubdomains = true;
      i++;
    } else {
      details.matchBeginningOfAddress = true;
    }
  }
  // check if there is a char before eol
  for (; i < line.length; i++) {
    c = line.charCodeAt(i);
    if (c === 36 /* '$' */) { // find network filter modifier marker
      // lookahead for the nearest marker to decide the actual marker location
      for (k = i + 1; k < line.length; k++) {
        c = line.charCodeAt(k);
        if (c === 61 /* '=' */) {
          // once we get here, we can assume there'll be modifiers as `=` char needs to be encoded
          break;
        } else if (c === 36 /* '$' */) {
          // jump from `i` to `k`, so we can lookahead from there again
          i = k;
          break;
        }
      }
      // we got the position in `i`
      if (i !== k) {
        break;
      }
    }
  }
  // detect trailing pipe
  if (line.charCodeAt(i - 1) === 124 /* '|' */) {
    details.matchEndOfAddress = true;
  }
  // extract pattern
  details.markers.pattern[0] += details.matchBeginningOfAddress
    ? 1
    : details.matchSubdomains
      ? 2
      : 0;
  // drop network modifier from the url pattern
  details.markers.pattern[1] = i === line.length ? i : i - 1;
  details.pattern = line.slice(details.markers.pattern[0], details.markers.pattern[1]);
  // search modifiers
  for (k = ++i; i < line.length + 1; i++) {
    c = line.charCodeAt(i);
    // detect the value delimiter
    if (c === 61 /* '=' */) {
      details.modifiers.push([line.slice(k, i), null]);
      details.markers.modifiers.push([[k, i], null]);
      for (k = ++i; i < line.length + 1; i++) {
        c = line.charCodeAt(i);
        if (c === 92 /* '\\' */) {
          continue;
        }
        if (c === 44 /* ',' */ || isNaN(c)) {
          details.modifiers[details.modifiers.length - 1][1] = line.slice(k, i);
          details.markers.modifiers[details.modifiers.length - 1][1] = [k, i];
          k = i + 1;
          break;
        }
      }
    } else if (c === 44 /* ',' */) {
      details.modifiers.push([line.slice(k, i), null]);
      details.markers.modifiers.push([[k, i], null]);
      k = i + 1;
    } else if (isNaN(c) && i > k) { // detect the eol and push leftovers
      details.modifiers.push([line.slice(k, i), null]);
      details.markers.modifiers.push([[k, i], null]);
    }
  }
  return details;
}

function parseFilter(line) {
  if (line.length === 0) {
    return {
      type: FILTER_TYPE_OTHERS,
      line,
    }
  }
  let i = 0;
  let c = 0;
  for (; i < line.length; i++) {
    c = line.charCodeAt(i);
    // find fast exit paths
    if (
      c === 91 /* '[' */ ||
      c === 33 /* '!' */
    ) { // comment
      return { 
        type: FILTER_TYPE_OTHERS,
        line,
      };
    }
    // whatever comes fast decides the filter type
    if (
      c === 47 /* '/' */ || // path delimeter
      c === 58 /* ':' */ || // protocol delimeter
      c === 94 /* '^' */ || // separater character
      c === 64 /* '@' */ || // network exception
      c === 124 /* '|' */ // address match helpers
    ) {
      // continue on network filter parsing
      break;
    }
    // match cosmetic filter marker; out of url spec (# should be encoded)
    if (c === 35 /* '#' */) {
      return parseCosmeticFilter(line, i);
    }
  }
  return parseNetworkFilter(line);
}

// transformers
function isRegexpPattern(details) {
  return details.pattern.charCodeAt(0) === 47 /* '/' */ && details.pattern.charCodeAt(details.pattern.length - 1) === 47;
}

function isPathnamePattern(c) {
  return (
    c === 124 /* '|' */ ||
    c === 35 /* '#' */ ||
    c === 47 /* '/' */ ||
    c === 63 /* '?' */ ||
    c === 38 /* '&' */
  )
}

function isAlphabet(c) {
  // make it upper case
  if (c >= 97) {
    c -= 32;
  }
  return c >= 65 && c <= 90;
}

function isNumeric(c) {
  return c >= 48 && c <= 57;
}

function transformToHostnamePattern(details) {
  if (
    isRegexpPattern(details) || // regexp
    details.matchEndOfAddress || // match eoa
    details.matchBeginningOfAddress || // match boa
    details.pattern.length < 3 // generic or private
  ) {
    return null;
  }
  let c = details.pattern.charCodeAt(0);
  let o = -1;
  // validate beg
  if (isNumeric(c) === false && isAlphabet(c) === false) {
    return null;
  }
  // detect trailing sep pattern
  c = details.pattern.charCodeAt(details.pattern.length + o);
  if (c === 94 /* '^' */) {
    c = details.pattern.charCodeAt(details.pattern.length + --o);
  }
  // validate end
  if (isAlphabet(c) === false) {
    return null;
  }
  let hasDot = false;
  for (let i = 1; i < details.pattern.length + o; i++) {
    c = details.pattern.charCodeAt(i);
    if (isPathnamePattern(c) || c === 42 /* '*' */) {
      return null;
    } else if (c === 46 /* '.' */) {
      // detect repeated dots
      if (details.pattern.charCodeAt(i + 1) === 46) {
        return null;
      }
      hasDot = true;
    }
  }
  // detect hostnames without a tld
  if (hasDot === false) {
    return null;
  }
  // use `c` as beg and `o` as end
  c = 0;
  o = details.pattern.length;
  // drop trailing sep char
  if (details.pattern.charCodeAt(o - 1) === 94 /* '^' */) {
    o--;
  }
  return details.pattern.slice(c, o);
}

// compilers
function isThirdpartyConstraint(opt) {
  return opt === '3p' || opt === 'third-party';
}

function compileHosts(list, opts) {
  const exceptions = new Set();
  const hostnames = new Set();
  let details = null;
  let hostname = '';
  let i = -1;
  let l = -1;
  for (const line of list.split('\n')) {
    try {
      details = parseFilter(line);
      if (details.type !== FILTER_TYPE_NETWORK) {
        continue;
      }
      hostname = transformToHostnamePattern(details);
      if (details.isException) {
        // try detecting path level exception in loose mode
        if (opts.strict === false && hostname === null) {
          l = details.pattern.indexOf('/');
          if (l === -1) {
            continue;
          }
          // we lose the original pattern data but it's fine in hosts compliation
          details.pattern = details.pattern.slice(0, l);
          hostname = transformToHostnamePattern(details);
          if (hostname === null) {
            continue;
          }
          opts.debug && console.error(`Path-level exception set: hostname="${hostname}" line="${line}"`);
        }
        exceptions.add(hostname);
        hostnames.delete(hostname);
      } else if (hostname !== null) {
        if (opts.strict === false) {
          for (i = 0, l = details.modifiers.length; i < l; i++) {
            if (isThirdpartyConstraint(details.modifiers[i][0])) {
              exceptions.add(hostname);
              hostnames.delete(hostname);
              break;
            }
          }
          // check if triggered
          if (i !== l) {
            continue;
          }
        }
        hostnames.add(hostname);
      }
    } catch (e) {
      if (e instanceof SyntaxError) {
        console.error(`Invalid filter: line="${line}" e="${e}"`);
      } else {
        console.error(`Unknown error: e="${e}"`);
      }
    }
  }
  const output = [];
  for (const hostname of hostnames) {
    output.push('127.0.0.1 ' + hostname);
  }
  return output.join('\n');
}

function compileJson(list, _opts) {
  const filters = [];
  for (const line of list.split('\n')) {
    try {
      filters.push(parseFilter(line));
    } catch (e) {
      if (e instanceof SyntaxError) {
        console.error(`Invalid filter: line="${line}" e="${e}"`);
      } else {
        console.error(`Unknown error: e="${e}"`);
      }
    }
  }
  return JSON.stringify(filters);
}

// formatters
const DIFF_TYPE_DELETE = 0;
const DIFF_TYPE_CREATE = 1;
const FILTER_MODIFIER_TYPE_TABLE = [
  ['1p', 'first-party'],
  ['3p', 'third-party'],
  ['xhr', 'xmlhttprequest'],
];

function format(details) {
  const diffs = [];
  let i = -1;
  let c = -1;
  for (i = 0; i < details.line.length; i++) {
    c = details.line.charCodeAt(i);
    if (isWhitespace(c) === false) {
      break;
    }
  }
  if (i !== 0) {
    diffs.push(['no-whitespaces', DIFF_TYPE_DELETE, 0, i]);
  }
  for (i = details.line.length - 1; i > -1; i--) {
    c = details.line.charCodeAt(i);
    if (isWhitespace(c) === false) {
      break;
    }
  }
  if (i !== details.line.length - 1) {
    diffs.push(['no-whitespaces', DIFF_TYPE_DELETE, i, details.line.length - i]);
  }
  if (details.type === FILTER_TYPE_NETWORK) {
    let opt = '';
    let val = '';
    let marker = null;
    for (c = 0; c < details.modifiers.length; c++) {
      opt = details.modifiers[c][0];
      val = details.modifiers[c][1];
      marker = details.markers.modifiers[c];
      i = opt.trimStart().length;
      if (opt.length !== i) {
        diffs.push(['no-modifier-whitespaces', DIFF_TYPE_DELETE, marker[0][0], opt.length - i]);
      }
      i = opt.trimEnd().length;
      if (opt.length !== i) {
        diffs.push(['no-modifier-whitespaces', DIFF_TYPE_DELETE, marker[0][1] - (opt.length - i), opt.length - i]);
      }
      for (const [alias, name] of FILTER_MODIFIER_TYPE_TABLE) {
        if (opt.trim() === alias) {
          diffs.push(['full-modifier-name', DIFF_TYPE_DELETE, marker[0][0], marker[0][1] - marker[0][0]]);
          diffs.push(['full-modifier-name', DIFF_TYPE_CREATE, marker[0][0], name]);
          break;
        }
      }
      if (val === null) {
        continue;
      }
      i = val.trimStart().length;
      if (val.length !== i) {
        diffs.push(['no-modifier-value-whitespaces', DIFF_TYPE_DELETE, marker[1][0], val.length - i]);
      }
      i = val.trimEnd().length;
      if (val.length !== i) {
        diffs.push(['no-modifier-value-whitespaces', DIFF_TYPE_DELETE, marker[1][1] - (val.length - i), val.length - i]);
      }
    }
  }
  return diffs;
}

function fix(line, diffs) {
  let i = 0;
  let k = 0;
  let l = diffs.length;
  for (; i < l; i++) {
    if (diffs[i][1] === DIFF_TYPE_DELETE) {
      line = line.slice(0, diffs[i][2]) + line.slice(diffs[i][2] + diffs[i][3]);
      for (k = i + 1; k < l; k++) {
        if (diffs[k][1] === DIFF_TYPE_DELETE) {
          // check the affected range overlap;
          // (current diff index + current diff range) > another diff index
          if (diffs[i][2] + diffs[i][3] > diffs[k][2]) {
            if (diffs[k][2] > diffs[i][2]) {
              diffs[k][2] -= diffs[k][2] - diffs[i][2];
            }
            diffs[k][3] -= diffs[i][3];
            continue;
          }
        }
        if (diffs[k][2] > diffs[i][2]) {
          diffs[k][2] -= diffs[i][3];
        }
      }
    } else if (diffs[i][1] === DIFF_TYPE_CREATE) {
      line = line.slice(0, diffs[i][2]) + diffs[i][3] + line.slice(diffs[i][2]);
      for (k = i; k < l; k++) {
        diffs[k][2] += diffs[i][3].length;
        if (diffs[k][1] === DIFF_TYPE_DELETE) {
          diffs[k][3] += diffs[i][3].length;
        }
      }
    }
  }
  return line;
}

// program
function check(list) {
  const lines = list.split('\n');
  let details = null;
  let diffs = [];
  let message = '';
  for (let i = 0; i < lines.length; i++) {
    details = parseFilter(lines[i]);
    diffs = format(details);
    for (const diff of diffs) {
      message = `Format error: line="${lines[i]}" rule="${diff[0]}"\n`;
      if (diff[1] === DIFF_TYPE_DELETE) {
        message += ' '.repeat(20 /* message prefix */ + diff[2])
          + '^'.repeat(diff[3]);
      } else {
        message += ' '.repeat(20 /* message prefix */ + diff[2])
          + '^'
          + ' '.repeat(lines[i].length - diff[2] + 1)
          + `use="${diff[3]}"`;
      }
      console.error(message);
    }
    lines[i] = fix(lines[i], diffs);
  }
  return lines.join('\n');
}

async function program() {
  const opts = getOpts();
  let list = await fs.readFile(opts.filepath, 'utf8');
  let out = '';
  if (opts.check) {
    out = check(list);
    if (opts.fix) {
      list = out;
    }
  }
  switch (opts.format) {
    case FORMAT_HOSTS:
      out = compileHosts(list, opts);
      break;
    case FORMAT_JSON:
      out = compileJson(list);
      break;
    case FORMAT_DNR:
      break;
    case FORMAT_LIST:
      break;
  }
  console.log(out);
}

void program();
