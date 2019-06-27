/******/ (function(modules) { // webpackBootstrap
/******/ 	// install a JSONP callback for chunk loading
/******/ 	function webpackJsonpCallback(data) {
/******/ 		var chunkIds = data[0];
/******/ 		var moreModules = data[1];
/******/
/******/
/******/ 		// add "moreModules" to the modules object,
/******/ 		// then flag all "chunkIds" as loaded and fire callback
/******/ 		var moduleId, chunkId, i = 0, resolves = [];
/******/ 		for(;i < chunkIds.length; i++) {
/******/ 			chunkId = chunkIds[i];
/******/ 			if(installedChunks[chunkId]) {
/******/ 				resolves.push(installedChunks[chunkId][0]);
/******/ 			}
/******/ 			installedChunks[chunkId] = 0;
/******/ 		}
/******/ 		for(moduleId in moreModules) {
/******/ 			if(Object.prototype.hasOwnProperty.call(moreModules, moduleId)) {
/******/ 				modules[moduleId] = moreModules[moduleId];
/******/ 			}
/******/ 		}
/******/ 		if(parentJsonpFunction) parentJsonpFunction(data);
/******/
/******/ 		while(resolves.length) {
/******/ 			resolves.shift()();
/******/ 		}
/******/
/******/ 	};
/******/
/******/
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// object to store loaded CSS chunks
/******/ 	var installedCssChunks = {
/******/ 		"main": 0
/******/ 	}
/******/
/******/ 	// object to store loaded and loading chunks
/******/ 	// undefined = chunk not loaded, null = chunk preloaded/prefetched
/******/ 	// Promise = chunk loading, 0 = chunk loaded
/******/ 	var installedChunks = {
/******/ 		"main": 0
/******/ 	};
/******/
/******/
/******/
/******/ 	// script path function
/******/ 	function jsonpScriptSrc(chunkId) {
/******/ 		return __webpack_require__.p + "" + ({}[chunkId]||chunkId) + ".bundle.js"
/******/ 	}
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/ 	// This file contains only the entry chunk.
/******/ 	// The chunk loading function for additional chunks
/******/ 	__webpack_require__.e = function requireEnsure(chunkId) {
/******/ 		var promises = [];
/******/
/******/
/******/ 		// mini-css-extract-plugin CSS loading
/******/ 		var cssChunks = {"1":1,"2":1};
/******/ 		if(installedCssChunks[chunkId]) promises.push(installedCssChunks[chunkId]);
/******/ 		else if(installedCssChunks[chunkId] !== 0 && cssChunks[chunkId]) {
/******/ 			promises.push(installedCssChunks[chunkId] = new Promise(function(resolve, reject) {
/******/ 				var href = "" + chunkId + ".bundle.css";
/******/ 				var fullhref = __webpack_require__.p + href;
/******/ 				var existingLinkTags = document.getElementsByTagName("link");
/******/ 				for(var i = 0; i < existingLinkTags.length; i++) {
/******/ 					var tag = existingLinkTags[i];
/******/ 					var dataHref = tag.getAttribute("data-href") || tag.getAttribute("href");
/******/ 					if(tag.rel === "stylesheet" && (dataHref === href || dataHref === fullhref)) return resolve();
/******/ 				}
/******/ 				var existingStyleTags = document.getElementsByTagName("style");
/******/ 				for(var i = 0; i < existingStyleTags.length; i++) {
/******/ 					var tag = existingStyleTags[i];
/******/ 					var dataHref = tag.getAttribute("data-href");
/******/ 					if(dataHref === href || dataHref === fullhref) return resolve();
/******/ 				}
/******/ 				var linkTag = document.createElement("link");
/******/ 				linkTag.rel = "stylesheet";
/******/ 				linkTag.type = "text/css";
/******/ 				linkTag.onload = resolve;
/******/ 				linkTag.onerror = function(event) {
/******/ 					var request = event && event.target && event.target.src || fullhref;
/******/ 					var err = new Error("Loading CSS chunk " + chunkId + " failed.\n(" + request + ")");
/******/ 					err.code = "CSS_CHUNK_LOAD_FAILED";
/******/ 					err.request = request;
/******/ 					delete installedCssChunks[chunkId]
/******/ 					linkTag.parentNode.removeChild(linkTag)
/******/ 					reject(err);
/******/ 				};
/******/ 				linkTag.href = fullhref;
/******/
/******/ 				var head = document.getElementsByTagName("head")[0];
/******/ 				head.appendChild(linkTag);
/******/ 			}).then(function() {
/******/ 				installedCssChunks[chunkId] = 0;
/******/ 			}));
/******/ 		}
/******/
/******/ 		// JSONP chunk loading for javascript
/******/
/******/ 		var installedChunkData = installedChunks[chunkId];
/******/ 		if(installedChunkData !== 0) { // 0 means "already installed".
/******/
/******/ 			// a Promise means "currently loading".
/******/ 			if(installedChunkData) {
/******/ 				promises.push(installedChunkData[2]);
/******/ 			} else {
/******/ 				// setup Promise in chunk cache
/******/ 				var promise = new Promise(function(resolve, reject) {
/******/ 					installedChunkData = installedChunks[chunkId] = [resolve, reject];
/******/ 				});
/******/ 				promises.push(installedChunkData[2] = promise);
/******/
/******/ 				// start chunk loading
/******/ 				var script = document.createElement('script');
/******/ 				var onScriptComplete;
/******/
/******/ 				script.charset = 'utf-8';
/******/ 				script.timeout = 120;
/******/ 				if (__webpack_require__.nc) {
/******/ 					script.setAttribute("nonce", __webpack_require__.nc);
/******/ 				}
/******/ 				script.src = jsonpScriptSrc(chunkId);
/******/
/******/ 				// create error before stack unwound to get useful stacktrace later
/******/ 				var error = new Error();
/******/ 				onScriptComplete = function (event) {
/******/ 					// avoid mem leaks in IE.
/******/ 					script.onerror = script.onload = null;
/******/ 					clearTimeout(timeout);
/******/ 					var chunk = installedChunks[chunkId];
/******/ 					if(chunk !== 0) {
/******/ 						if(chunk) {
/******/ 							var errorType = event && (event.type === 'load' ? 'missing' : event.type);
/******/ 							var realSrc = event && event.target && event.target.src;
/******/ 							error.message = 'Loading chunk ' + chunkId + ' failed.\n(' + errorType + ': ' + realSrc + ')';
/******/ 							error.name = 'ChunkLoadError';
/******/ 							error.type = errorType;
/******/ 							error.request = realSrc;
/******/ 							chunk[1](error);
/******/ 						}
/******/ 						installedChunks[chunkId] = undefined;
/******/ 					}
/******/ 				};
/******/ 				var timeout = setTimeout(function(){
/******/ 					onScriptComplete({ type: 'timeout', target: script });
/******/ 				}, 120000);
/******/ 				script.onerror = script.onload = onScriptComplete;
/******/ 				document.head.appendChild(script);
/******/ 			}
/******/ 		}
/******/ 		return Promise.all(promises);
/******/ 	};
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/ 	// on error function for async loading
/******/ 	__webpack_require__.oe = function(err) { console.error(err); throw err; };
/******/
/******/ 	var jsonpArray = window["webpackJsonp"] = window["webpackJsonp"] || [];
/******/ 	var oldJsonpFunction = jsonpArray.push.bind(jsonpArray);
/******/ 	jsonpArray.push = webpackJsonpCallback;
/******/ 	jsonpArray = jsonpArray.slice();
/******/ 	for(var i = 0; i < jsonpArray.length; i++) webpackJsonpCallback(jsonpArray[i]);
/******/ 	var parentJsonpFunction = oldJsonpFunction;
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = "./src/index.js");
/******/ })
/************************************************************************/
/******/ ({

/***/ "./node_modules/@babel/runtime/helpers/esm/extends.js":
/*!************************************************************!*\
  !*** ./node_modules/@babel/runtime/helpers/esm/extends.js ***!
  \************************************************************/
/*! exports provided: default */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function() { return _extends; });
function _extends() {
  _extends = Object.assign || function (target) {
    for (var i = 1; i < arguments.length; i++) {
      var source = arguments[i];

      for (var key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
          target[key] = source[key];
        }
      }
    }

    return target;
  };

  return _extends.apply(this, arguments);
}

/***/ }),

/***/ "./node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js":
/*!**********************************************************************************!*\
  !*** ./node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js ***!
  \**********************************************************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Copyright 2015, Yahoo! Inc.
 * Copyrights licensed under the New BSD License. See the accompanying LICENSE file for terms.
 */
var ReactIs = __webpack_require__(/*! react-is */ "./node_modules/react-is/index.js");
var REACT_STATICS = {
    childContextTypes: true,
    contextType: true,
    contextTypes: true,
    defaultProps: true,
    displayName: true,
    getDefaultProps: true,
    getDerivedStateFromError: true,
    getDerivedStateFromProps: true,
    mixins: true,
    propTypes: true,
    type: true
};

var KNOWN_STATICS = {
    name: true,
    length: true,
    prototype: true,
    caller: true,
    callee: true,
    arguments: true,
    arity: true
};

var FORWARD_REF_STATICS = {
    '$$typeof': true,
    render: true,
    defaultProps: true,
    displayName: true,
    propTypes: true
};

var MEMO_STATICS = {
    '$$typeof': true,
    compare: true,
    defaultProps: true,
    displayName: true,
    propTypes: true,
    type: true
};

var TYPE_STATICS = {};
TYPE_STATICS[ReactIs.ForwardRef] = FORWARD_REF_STATICS;

function getStatics(component) {
    if (ReactIs.isMemo(component)) {
        return MEMO_STATICS;
    }
    return TYPE_STATICS[component['$$typeof']] || REACT_STATICS;
}

var defineProperty = Object.defineProperty;
var getOwnPropertyNames = Object.getOwnPropertyNames;
var getOwnPropertySymbols = Object.getOwnPropertySymbols;
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var getPrototypeOf = Object.getPrototypeOf;
var objectPrototype = Object.prototype;

function hoistNonReactStatics(targetComponent, sourceComponent, blacklist) {
    if (typeof sourceComponent !== 'string') {
        // don't hoist over string (html) components

        if (objectPrototype) {
            var inheritedComponent = getPrototypeOf(sourceComponent);
            if (inheritedComponent && inheritedComponent !== objectPrototype) {
                hoistNonReactStatics(targetComponent, inheritedComponent, blacklist);
            }
        }

        var keys = getOwnPropertyNames(sourceComponent);

        if (getOwnPropertySymbols) {
            keys = keys.concat(getOwnPropertySymbols(sourceComponent));
        }

        var targetStatics = getStatics(targetComponent);
        var sourceStatics = getStatics(sourceComponent);

        for (var i = 0; i < keys.length; ++i) {
            var key = keys[i];
            if (!KNOWN_STATICS[key] && !(blacklist && blacklist[key]) && !(sourceStatics && sourceStatics[key]) && !(targetStatics && targetStatics[key])) {
                var descriptor = getOwnPropertyDescriptor(sourceComponent, key);
                try {
                    // Avoid failures from read-only properties
                    defineProperty(targetComponent, key, descriptor);
                } catch (e) {}
            }
        }

        return targetComponent;
    }

    return targetComponent;
}

module.exports = hoistNonReactStatics;


/***/ }),

/***/ "./node_modules/invariant/browser.js":
/*!*******************************************!*\
  !*** ./node_modules/invariant/browser.js ***!
  \*******************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/**
 * Copyright (c) 2013-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */



/**
 * Use invariant() to assert state which your program assumes to be true.
 *
 * Provide sprintf-style format (only %s is supported) and arguments
 * to provide information about what broke and what you were
 * expecting.
 *
 * The invariant message will be stripped in production, but the invariant
 * will remain to ensure logic does not differ in production.
 */

var invariant = function(condition, format, a, b, c, d, e, f) {
  if (false) {}

  if (!condition) {
    var error;
    if (format === undefined) {
      error = new Error(
        'Minified exception occurred; use the non-minified dev environment ' +
        'for the full error message and additional helpful warnings.'
      );
    } else {
      var args = [a, b, c, d, e, f];
      var argIndex = 0;
      error = new Error(
        format.replace(/%s/g, function() { return args[argIndex++]; })
      );
      error.name = 'Invariant Violation';
    }

    error.framesToPop = 1; // we don't care about invariant's own frame
    throw error;
  }
};

module.exports = invariant;


/***/ }),

/***/ "./node_modules/path-to-regexp/index.js":
/*!**********************************************!*\
  !*** ./node_modules/path-to-regexp/index.js ***!
  \**********************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

var isarray = __webpack_require__(/*! isarray */ "./node_modules/path-to-regexp/node_modules/isarray/index.js")

/**
 * Expose `pathToRegexp`.
 */
module.exports = pathToRegexp
module.exports.parse = parse
module.exports.compile = compile
module.exports.tokensToFunction = tokensToFunction
module.exports.tokensToRegExp = tokensToRegExp

/**
 * The main path matching regexp utility.
 *
 * @type {RegExp}
 */
var PATH_REGEXP = new RegExp([
  // Match escaped characters that would otherwise appear in future matches.
  // This allows the user to escape special characters that won't transform.
  '(\\\\.)',
  // Match Express-style parameters and un-named parameters with a prefix
  // and optional suffixes. Matches appear as:
  //
  // "/:test(\\d+)?" => ["/", "test", "\d+", undefined, "?", undefined]
  // "/route(\\d+)"  => [undefined, undefined, undefined, "\d+", undefined, undefined]
  // "/*"            => ["/", undefined, undefined, undefined, undefined, "*"]
  '([\\/.])?(?:(?:\\:(\\w+)(?:\\(((?:\\\\.|[^\\\\()])+)\\))?|\\(((?:\\\\.|[^\\\\()])+)\\))([+*?])?|(\\*))'
].join('|'), 'g')

/**
 * Parse a string for the raw tokens.
 *
 * @param  {string}  str
 * @param  {Object=} options
 * @return {!Array}
 */
function parse (str, options) {
  var tokens = []
  var key = 0
  var index = 0
  var path = ''
  var defaultDelimiter = options && options.delimiter || '/'
  var res

  while ((res = PATH_REGEXP.exec(str)) != null) {
    var m = res[0]
    var escaped = res[1]
    var offset = res.index
    path += str.slice(index, offset)
    index = offset + m.length

    // Ignore already escaped sequences.
    if (escaped) {
      path += escaped[1]
      continue
    }

    var next = str[index]
    var prefix = res[2]
    var name = res[3]
    var capture = res[4]
    var group = res[5]
    var modifier = res[6]
    var asterisk = res[7]

    // Push the current path onto the tokens.
    if (path) {
      tokens.push(path)
      path = ''
    }

    var partial = prefix != null && next != null && next !== prefix
    var repeat = modifier === '+' || modifier === '*'
    var optional = modifier === '?' || modifier === '*'
    var delimiter = res[2] || defaultDelimiter
    var pattern = capture || group

    tokens.push({
      name: name || key++,
      prefix: prefix || '',
      delimiter: delimiter,
      optional: optional,
      repeat: repeat,
      partial: partial,
      asterisk: !!asterisk,
      pattern: pattern ? escapeGroup(pattern) : (asterisk ? '.*' : '[^' + escapeString(delimiter) + ']+?')
    })
  }

  // Match any characters still remaining.
  if (index < str.length) {
    path += str.substr(index)
  }

  // If the path exists, push it onto the end.
  if (path) {
    tokens.push(path)
  }

  return tokens
}

/**
 * Compile a string to a template function for the path.
 *
 * @param  {string}             str
 * @param  {Object=}            options
 * @return {!function(Object=, Object=)}
 */
function compile (str, options) {
  return tokensToFunction(parse(str, options))
}

/**
 * Prettier encoding of URI path segments.
 *
 * @param  {string}
 * @return {string}
 */
function encodeURIComponentPretty (str) {
  return encodeURI(str).replace(/[\/?#]/g, function (c) {
    return '%' + c.charCodeAt(0).toString(16).toUpperCase()
  })
}

/**
 * Encode the asterisk parameter. Similar to `pretty`, but allows slashes.
 *
 * @param  {string}
 * @return {string}
 */
function encodeAsterisk (str) {
  return encodeURI(str).replace(/[?#]/g, function (c) {
    return '%' + c.charCodeAt(0).toString(16).toUpperCase()
  })
}

/**
 * Expose a method for transforming tokens into the path function.
 */
function tokensToFunction (tokens) {
  // Compile all the tokens into regexps.
  var matches = new Array(tokens.length)

  // Compile all the patterns before compilation.
  for (var i = 0; i < tokens.length; i++) {
    if (typeof tokens[i] === 'object') {
      matches[i] = new RegExp('^(?:' + tokens[i].pattern + ')$')
    }
  }

  return function (obj, opts) {
    var path = ''
    var data = obj || {}
    var options = opts || {}
    var encode = options.pretty ? encodeURIComponentPretty : encodeURIComponent

    for (var i = 0; i < tokens.length; i++) {
      var token = tokens[i]

      if (typeof token === 'string') {
        path += token

        continue
      }

      var value = data[token.name]
      var segment

      if (value == null) {
        if (token.optional) {
          // Prepend partial segment prefixes.
          if (token.partial) {
            path += token.prefix
          }

          continue
        } else {
          throw new TypeError('Expected "' + token.name + '" to be defined')
        }
      }

      if (isarray(value)) {
        if (!token.repeat) {
          throw new TypeError('Expected "' + token.name + '" to not repeat, but received `' + JSON.stringify(value) + '`')
        }

        if (value.length === 0) {
          if (token.optional) {
            continue
          } else {
            throw new TypeError('Expected "' + token.name + '" to not be empty')
          }
        }

        for (var j = 0; j < value.length; j++) {
          segment = encode(value[j])

          if (!matches[i].test(segment)) {
            throw new TypeError('Expected all "' + token.name + '" to match "' + token.pattern + '", but received `' + JSON.stringify(segment) + '`')
          }

          path += (j === 0 ? token.prefix : token.delimiter) + segment
        }

        continue
      }

      segment = token.asterisk ? encodeAsterisk(value) : encode(value)

      if (!matches[i].test(segment)) {
        throw new TypeError('Expected "' + token.name + '" to match "' + token.pattern + '", but received "' + segment + '"')
      }

      path += token.prefix + segment
    }

    return path
  }
}

/**
 * Escape a regular expression string.
 *
 * @param  {string} str
 * @return {string}
 */
function escapeString (str) {
  return str.replace(/([.+*?=^!:${}()[\]|\/\\])/g, '\\$1')
}

/**
 * Escape the capturing group by escaping special characters and meaning.
 *
 * @param  {string} group
 * @return {string}
 */
function escapeGroup (group) {
  return group.replace(/([=!:$\/()])/g, '\\$1')
}

/**
 * Attach the keys as a property of the regexp.
 *
 * @param  {!RegExp} re
 * @param  {Array}   keys
 * @return {!RegExp}
 */
function attachKeys (re, keys) {
  re.keys = keys
  return re
}

/**
 * Get the flags for a regexp from the options.
 *
 * @param  {Object} options
 * @return {string}
 */
function flags (options) {
  return options.sensitive ? '' : 'i'
}

/**
 * Pull out keys from a regexp.
 *
 * @param  {!RegExp} path
 * @param  {!Array}  keys
 * @return {!RegExp}
 */
function regexpToRegexp (path, keys) {
  // Use a negative lookahead to match only capturing groups.
  var groups = path.source.match(/\((?!\?)/g)

  if (groups) {
    for (var i = 0; i < groups.length; i++) {
      keys.push({
        name: i,
        prefix: null,
        delimiter: null,
        optional: false,
        repeat: false,
        partial: false,
        asterisk: false,
        pattern: null
      })
    }
  }

  return attachKeys(path, keys)
}

/**
 * Transform an array into a regexp.
 *
 * @param  {!Array}  path
 * @param  {Array}   keys
 * @param  {!Object} options
 * @return {!RegExp}
 */
function arrayToRegexp (path, keys, options) {
  var parts = []

  for (var i = 0; i < path.length; i++) {
    parts.push(pathToRegexp(path[i], keys, options).source)
  }

  var regexp = new RegExp('(?:' + parts.join('|') + ')', flags(options))

  return attachKeys(regexp, keys)
}

/**
 * Create a path regexp from string input.
 *
 * @param  {string}  path
 * @param  {!Array}  keys
 * @param  {!Object} options
 * @return {!RegExp}
 */
function stringToRegexp (path, keys, options) {
  return tokensToRegExp(parse(path, options), keys, options)
}

/**
 * Expose a function for taking tokens and returning a RegExp.
 *
 * @param  {!Array}          tokens
 * @param  {(Array|Object)=} keys
 * @param  {Object=}         options
 * @return {!RegExp}
 */
function tokensToRegExp (tokens, keys, options) {
  if (!isarray(keys)) {
    options = /** @type {!Object} */ (keys || options)
    keys = []
  }

  options = options || {}

  var strict = options.strict
  var end = options.end !== false
  var route = ''

  // Iterate over the tokens and create our regexp string.
  for (var i = 0; i < tokens.length; i++) {
    var token = tokens[i]

    if (typeof token === 'string') {
      route += escapeString(token)
    } else {
      var prefix = escapeString(token.prefix)
      var capture = '(?:' + token.pattern + ')'

      keys.push(token)

      if (token.repeat) {
        capture += '(?:' + prefix + capture + ')*'
      }

      if (token.optional) {
        if (!token.partial) {
          capture = '(?:' + prefix + '(' + capture + '))?'
        } else {
          capture = prefix + '(' + capture + ')?'
        }
      } else {
        capture = prefix + '(' + capture + ')'
      }

      route += capture
    }
  }

  var delimiter = escapeString(options.delimiter || '/')
  var endsWithDelimiter = route.slice(-delimiter.length) === delimiter

  // In non-strict mode we allow a slash at the end of match. If the path to
  // match already ends with a slash, we remove it for consistency. The slash
  // is valid at the end of a path match, not in the middle. This is important
  // in non-ending mode, where "/test/" shouldn't match "/test//route".
  if (!strict) {
    route = (endsWithDelimiter ? route.slice(0, -delimiter.length) : route) + '(?:' + delimiter + '(?=$))?'
  }

  if (end) {
    route += '$'
  } else {
    // In non-ending mode, we need the capturing groups to match as much as
    // possible by using a positive lookahead to the end or next path segment.
    route += strict && endsWithDelimiter ? '' : '(?=' + delimiter + '|$)'
  }

  return attachKeys(new RegExp('^' + route, flags(options)), keys)
}

/**
 * Normalize the given path string, returning a regular expression.
 *
 * An empty array can be passed in for the keys, which will hold the
 * placeholder key descriptions. For example, using `/user/:id`, `keys` will
 * contain `[{ name: 'id', delimiter: '/', optional: false, repeat: false }]`.
 *
 * @param  {(string|RegExp|Array)} path
 * @param  {(Array|Object)=}       keys
 * @param  {Object=}               options
 * @return {!RegExp}
 */
function pathToRegexp (path, keys, options) {
  if (!isarray(keys)) {
    options = /** @type {!Object} */ (keys || options)
    keys = []
  }

  options = options || {}

  if (path instanceof RegExp) {
    return regexpToRegexp(path, /** @type {!Array} */ (keys))
  }

  if (isarray(path)) {
    return arrayToRegexp(/** @type {!Array} */ (path), /** @type {!Array} */ (keys), options)
  }

  return stringToRegexp(/** @type {string} */ (path), /** @type {!Array} */ (keys), options)
}


/***/ }),

/***/ "./node_modules/path-to-regexp/node_modules/isarray/index.js":
/*!*******************************************************************!*\
  !*** ./node_modules/path-to-regexp/node_modules/isarray/index.js ***!
  \*******************************************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports) {

module.exports = Array.isArray || function (arr) {
  return Object.prototype.toString.call(arr) == '[object Array]';
};


/***/ }),

/***/ "./node_modules/preact/compat/dist/compat.module.js":
/*!**********************************************************************!*\
  !*** ./node_modules/preact/compat/dist/compat.module.js + 2 modules ***!
  \**********************************************************************/
/*! exports provided: createContext, createRef, Fragment, Component, default, version, Children, render, hydrate, unmountComponentAtNode, createPortal, createElement, createFactory, cloneElement, isValidElement, findDOMNode, PureComponent, memo, forwardRef, unstable_batchedUpdates, Suspense, lazy, useState, useReducer, useEffect, useLayoutEffect, useRef, useImperativeHandle, useMemo, useCallback, useContext, useDebugValue */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
var hooks_module_namespaceObject = {};
__webpack_require__.r(hooks_module_namespaceObject);
__webpack_require__.d(hooks_module_namespaceObject, "useState", function() { return hooks_module_e; });
__webpack_require__.d(hooks_module_namespaceObject, "useReducer", function() { return hooks_module_a; });
__webpack_require__.d(hooks_module_namespaceObject, "useEffect", function() { return hooks_module_v; });
__webpack_require__.d(hooks_module_namespaceObject, "useLayoutEffect", function() { return hooks_module_p; });
__webpack_require__.d(hooks_module_namespaceObject, "useRef", function() { return hooks_module_d; });
__webpack_require__.d(hooks_module_namespaceObject, "useImperativeHandle", function() { return hooks_module_l; });
__webpack_require__.d(hooks_module_namespaceObject, "useMemo", function() { return hooks_module_m; });
__webpack_require__.d(hooks_module_namespaceObject, "useCallback", function() { return hooks_module_s; });
__webpack_require__.d(hooks_module_namespaceObject, "useContext", function() { return hooks_module_y; });
__webpack_require__.d(hooks_module_namespaceObject, "useDebugValue", function() { return hooks_module_; });

// CONCATENATED MODULE: ./node_modules/preact/dist/preact.module.js
var preact_module_n,l,preact_module_u,preact_module_t,preact_module_i,preact_module_r,f={},preact_module_e=[],preact_module_o=/acit|ex(?:s|g|n|p|$)|rph|grid|ows|mnc|ntw|ine[ch]|zoo|^ord|^--/i;function c(n,l){for(var u in l)n[u]=l[u];return n}function s(n){var l=n.parentNode;l&&l.removeChild(n)}function a(n,l,u){var t,i,r,f,e=arguments;if(l=c({},l),arguments.length>3)for(u=[u],t=3;t<arguments.length;t++)u.push(e[t]);if(null!=u&&(l.children=u),null!=n&&null!=n.defaultProps)for(i in n.defaultProps)void 0===l[i]&&(l[i]=n.defaultProps[i]);return f=l.key,null!=(r=l.ref)&&delete l.ref,null!=f&&delete l.key,h(n,l,f,r)}function h(l,u,t,i){var r={type:l,props:u,key:t,ref:i,__k:null,__p:null,__b:0,__e:null,l:null,__c:null,constructor:void 0};return preact_module_n.vnode&&preact_module_n.vnode(r),r}function v(){return{}}function p(n){return n.children}function y(n){if(null==n||"boolean"==typeof n)return null;if("string"==typeof n||"number"==typeof n)return h(null,n,null,null);if(null!=n.__e||null!=n.__c){var l=h(n.type,n.props,n.key,null);return l.__e=n.__e,l}return n}function d(n,l){this.props=n,this.context=l}function m(n,l){if(null==l)return n.__p?m(n.__p,n.__p.__k.indexOf(n)+1):null;for(var u;l<n.__k.length;l++)if(null!=(u=n.__k[l]))return"function"!=typeof u.type?u.__e:m(u,0);return"function"==typeof n.type?m(n):null}function w(n){var l,u;if(null!=(n=n.__p)&&null!=n.__c){for(n.__e=n.__c.base=null,l=0;l<n.__k.length;l++)if(null!=(u=n.__k[l])&&null!=u.__e){n.__e=n.__c.base=u.__e;break}return w(n)}}function b(t){!t.__d&&(t.__d=!0)&&1===l.push(t)&&(preact_module_n.debounceRendering||preact_module_u)(k)}function k(){var n;for(l.sort(function(n,l){return l.__v.__b-n.__v.__b});n=l.pop();)n.__d&&n.forceUpdate(!1)}function g(n,l,u,t,i,r,o,c){var a,h,v,p,d,m,w,b,k=l.__k||_(l.props.children,l.__k=[],y,!0),g=u&&u.__k||preact_module_e,x=g.length;if(c==f)if(c=null,null!=r)c=r[0];else for(h=0;!c&&h<x;h++)c=g[h]&&g[h].__e;for(h=0;h<k.length;h++)if(null!=(a=k[h]=y(k[h]))){if(a.__p=l,a.__b=l.__b+1,null===(p=g[h])||p&&a.key==p.key&&a.type===p.type)g[h]=void 0;else for(v=0;v<x;v++){if((p=g[v])&&a.key==p.key&&a.type===p.type){g[v]=void 0;break}p=null}if(d=N(n,a,p=p||f,t,i,r,o,null,c),(v=a.ref)&&p.ref!=v&&(b||(b=[])).push(v,a.__c||d),null!=d){if(null==w&&(w=d),null!=a.l)d=a.l,a.l=null;else if(r==p||d!=c||null==d.parentNode)n:if(null==c||c.parentNode!==n)n.appendChild(d);else{for(m=c,v=0;(m=m.nextSibling)&&v<x;v+=2)if(m==d)break n;n.insertBefore(d,c)}c=d.nextSibling,"function"==typeof l.type&&(l.l=d)}}if(l.__e=w,null!=r&&"function"!=typeof l.type)for(h=r.length;h--;)null!=r[h]&&s(r[h]);for(h=x;h--;)null!=g[h]&&O(g[h],l);if(b)for(h=0;h<b.length;h++)A(b[h],b[++h],l)}function _(n,l,u,t){if(null==l&&(l=[]),null==n||"boolean"==typeof n)t&&l.push(null);else if(Array.isArray(n))for(var i=0;i<n.length;i++)_(n[i],l,u,t);else l.push(u?u(n):n);return l}function x(n,l,u,t){var i,r,f=Object.keys(l).sort();for(i=0;i<f.length;i++)"children"===(r=f[i])||"key"===r||u&&("value"===r||"checked"===r?n:u)[r]===l[r]||C(n,r,l[r],u[r],t);for(i in u)"children"===i||"key"===i||i in l||C(n,i,null,u[i],t)}function C(n,l,u,r,e){var s,a,h,v;if("style"===(l=e?"className"===l?"class":l:"class"===l?"className":l))for(a in s=c(c({},r),u))(u||f)[a]!==(r||f)[a]&&n.style.setProperty("-"===a[0]&&"-"===a[1]?a:a.replace(preact_module_t,"-$&"),u&&a in u?"number"==typeof s[a]&&!1===preact_module_o.test(a)?s[a]+"px":s[a]:"");else if("o"===l[0]&&"n"===l[1])h=l!==(l=l.replace(/Capture$/,"")),v=l.toLowerCase(),l=(v in n?v:l).slice(2),u?(r||n.addEventListener(l,P,h),(n.u||(n.u={}))[l]=u):n.removeEventListener(l,P,h);else if("list"!==l&&"tagName"!==l&&!e&&l in n)if(n.length&&"value"==l)for(l=n.length;l--;)n.options[l].selected=n.options[l].value==u;else n[l]=null==u?"":u;else"function"!=typeof u&&"dangerouslySetInnerHTML"!==l&&(l!==(l=l.replace(/^xlink:?/,""))?null==u||!1===u?n.removeAttributeNS(preact_module_i,l.toLowerCase()):n.setAttributeNS(preact_module_i,l.toLowerCase(),u):null==u||!1===u?n.removeAttribute(l):n.setAttribute(l,u))}function P(l){return this.u[l.type](preact_module_n.event?preact_module_n.event(l):l)}function N(l,u,t,i,r,f,e,o,s){var a,h,v,m,w,b,k,x,C,P,N=u.type;if(void 0!==u.constructor)return null;(a=preact_module_n.__b)&&a(u);try{n:if("function"==typeof N){if(x=u.props,C=(a=N.contextType)&&i[a.__c],P=a?C?C.props.value:a.__p:i,t.__c?k=(h=u.__c=t.__c).__p=h.__E:(N.prototype&&N.prototype.render?u.__c=h=new N(x,P):(u.__c=h=new d(x,P),h.constructor=N,h.render=T),C&&C.sub(h),h.props=x,h.state||(h.state={}),h.context=P,h.__n=i,v=h.__d=!0,h.__h=[]),null==h.__s&&(h.__s=h.state),null!=N.getDerivedStateFromProps&&c(h.__s==h.state?h.__s=c({},h.__s):h.__s,N.getDerivedStateFromProps(x,h.__s)),v)null==N.getDerivedStateFromProps&&null!=h.componentWillMount&&h.componentWillMount(),null!=h.componentDidMount&&e.push(h);else{if(null==N.getDerivedStateFromProps&&null==o&&null!=h.componentWillReceiveProps&&h.componentWillReceiveProps(x,P),!o&&null!=h.shouldComponentUpdate&&!1===h.shouldComponentUpdate(x,h.__s,P)){h.props=x,h.state=h.__s,h.__d=!1,h.__v=u,u.__e=t.__e,u.__k=t.__k;break n}null!=h.componentWillUpdate&&h.componentWillUpdate(x,h.__s,P)}m=h.props,w=h.state,h.context=P,h.props=x,h.state=h.__s,(a=preact_module_n.__r)&&a(u),h.__d=!1,h.__v=u,h.__P=l;try{_(null!=(a=h.render(h.props,h.state,h.context))&&a.type==p&&null==a.key?a.props.children:a,u.__k=[],y,!0)}catch(l){if((a=preact_module_n.__E)&&a(l,u,t))break n;throw l}for(null!=h.getChildContext&&(i=c(c({},i),h.getChildContext())),v||null==h.getSnapshotBeforeUpdate||(b=h.getSnapshotBeforeUpdate(m,w)),g(l,u,t,i,r,f,e,s),h.base=u.__e;a=h.__h.pop();)a.call(h);v||null==m||null==h.componentDidUpdate||h.componentDidUpdate(m,w,b),k&&(h.__E=h.__p=null)}else u.__e=j(t.__e,u,t,i,r,f,e);(a=preact_module_n.diffed)&&a(u)}catch(n){z(n,u.__p)}return u.__e}function $(l,u){for(var t;t=l.pop();)try{t.componentDidMount()}catch(n){z(n,t.__v.__p)}preact_module_n.__c&&preact_module_n.__c(u)}function j(n,l,u,t,i,r,o){var c,s,a,h,v=u.props,p=l.props;if(i="svg"===l.type||i,null==n&&null!=r)for(c=0;c<r.length;c++)if(null!=(s=r[c])&&(null===l.type?3===s.nodeType:s.localName===l.type)){n=s,r[c]=null;break}if(null==n){if(null===l.type)return document.createTextNode(p);n=i?document.createElementNS("http://www.w3.org/2000/svg",l.type):document.createElement(l.type),r=null}return null===l.type?v!==p&&(n.data=p):l!==u&&(null!=r&&(r=preact_module_e.slice.call(n.childNodes)),a=(v=u.props||f).dangerouslySetInnerHTML,((h=p.dangerouslySetInnerHTML)||a)&&null==r&&(h&&a&&h.__html==a.__html||(n.innerHTML=h&&h.__html||"")),p.multiple&&(n.multiple=p.multiple),g(n,l,u,t,"foreignObject"!==l.type&&i,r,o,f),x(n,p,v,i)),n}function A(n,l,u){try{"function"==typeof n?n(l):n.current=l}catch(n){z(n,u)}}function O(l,u,t){var i,r,f;if(preact_module_n.unmount&&preact_module_n.unmount(l),(i=l.ref)&&A(i,null,u),t||"function"==typeof l.type||(t=null!=(r=l.__e)),l.__e=l.l=null,null!=(i=l.__c)){if(i.componentWillUnmount)try{i.componentWillUnmount()}catch(n){z(n,u)}i.base=i.__P=null}if(i=l.__k)for(f=0;f<i.length;f++)i[f]&&O(i[f],u,t);null!=r&&s(r)}function T(n,l,u){return this.constructor(n,u)}function z(l,u){var t;for(preact_module_n.__e&&preact_module_n.__e(l,u);u;u=u.__p)if((t=u.__c)&&!t.__p)try{if(t.constructor&&null!=t.constructor.getDerivedStateFromError)t.setState(t.constructor.getDerivedStateFromError(l));else{if(null==t.componentDidCatch)continue;t.componentDidCatch(l)}return b(t.__E=t)}catch(n){l=n}throw l}function D(l,u,t){var i,r;preact_module_n.__p&&preact_module_n.__p(l,u),i=u.__k,l=a(p,null,[l]),r=[],N(u,t?l:u.__k=l,i||f,f,void 0!==u.ownerSVGElement,t?[t]:i?null:preact_module_e.slice.call(u.childNodes),r,!1,t||f),$(r,l)}function H(n,l){l.__k=null,D(n,l)}function I(n,l){return l=c(c({},n.props),l),arguments.length>2&&(l.children=preact_module_e.slice.call(arguments,2)),h(n.type,l,l.key||n.key,l.ref||n.ref)}function L(n){var l={},u={__c:"__cC"+preact_module_r++,__p:n,Consumer:function(n,l){return n.children(l)},Provider:function(n){var t,i=this;return this.getChildContext||(t=[],this.getChildContext=function(){return l[u.__c]=i,l},this.shouldComponentUpdate=function(n){t.some(function(l){l.__P&&(l.context=n.value,b(l))})},this.sub=function(n){t.push(n);var l=n.componentWillUnmount;n.componentWillUnmount=function(){t.splice(t.indexOf(n),1),l&&l.call(n)}}),n.children}};return u.Consumer.contextType=u,u}preact_module_n={},d.prototype.setState=function(n,l){var u=this.__s!==this.state&&this.__s||(this.__s=c({},this.state));("function"!=typeof n||(n=n(u,this.props)))&&c(u,n),null!=n&&this.__v&&(l&&this.__h.push(l),b(this))},d.prototype.forceUpdate=function(n){var l,u,t,i=this.__v,r=this.__v.__e,f=this.__P;f&&(l=!1!==n,u=[],t=N(f,i,c({},i),this.__n,void 0!==f.ownerSVGElement,null,u,l,null==r?m(i):r),$(u,i),t!=r&&w(i)),n&&n()},d.prototype.render=p,l=[],preact_module_u="function"==typeof Promise?Promise.prototype.then.bind(Promise.resolve()):setTimeout,preact_module_t=/[A-Z]/g,preact_module_i="http://www.w3.org/1999/xlink",preact_module_r=0;
//# sourceMappingURL=preact.module.js.map

// CONCATENATED MODULE: ./node_modules/preact/hooks/dist/hooks.module.js
var hooks_module_t,hooks_module_r,hooks_module_u=[],hooks_module_f=preact_module_n.__r;preact_module_n.__r=function(n){hooks_module_f&&hooks_module_f(n),hooks_module_t=0,(hooks_module_r=n.__c).__H&&(hooks_module_r.__H.t=q(hooks_module_r.__H.t))};var hooks_module_i=preact_module_n.diffed;preact_module_n.diffed=function(n){hooks_module_i&&hooks_module_i(n);var t=n.__c;if(t){var r=t.__H;r&&(r.u=q(r.u))}};var hooks_module_o=preact_module_n.unmount;function hooks_module_c(t){preact_module_n.__h&&preact_module_n.__h(hooks_module_r);var u=hooks_module_r.__H||(hooks_module_r.__H={i:[],t:[],u:[]});return t>=u.i.length&&u.i.push({}),u.i[t]}function hooks_module_e(n){return hooks_module_a(hooks_module_L,n)}function hooks_module_a(n,u,f){var i=hooks_module_c(hooks_module_t++);return i.__c||(i.__c=hooks_module_r,i.o=[f?f(u):hooks_module_L(null,u),function(t){var r=n(i.o[0],t);i.o[0]!==r&&(i.o[0]=r,i.__c.setState({}))}]),i.o}function hooks_module_v(n,u){var f=hooks_module_c(hooks_module_t++);F(f.v,u)&&(f.o=n,f.v=u,hooks_module_r.__H.t.push(f),hooks_module_g(hooks_module_r))}function hooks_module_p(n,u){var f=hooks_module_c(hooks_module_t++);F(f.v,u)&&(f.o=n,f.v=u,hooks_module_r.__H.u.push(f))}function hooks_module_d(n){return hooks_module_m(function(){return{current:n}},[])}function hooks_module_l(n,r,u){var f=hooks_module_c(hooks_module_t++);F(f.v,u)&&(f.v=u,n&&(n.current=r()))}function hooks_module_m(n,r){var u=hooks_module_c(hooks_module_t++);return F(u.v,r)?(u.v=r,u.p=n,u.o=n()):u.o}function hooks_module_s(n,t){return hooks_module_m(function(){return n},t)}function hooks_module_y(n){var u=hooks_module_r.context[n.__c];if(!u)return n.__p;var f=hooks_module_c(hooks_module_t++);return null==f.o&&(f.o=!0,u.sub(hooks_module_r)),u.props.value}function hooks_module_(t,r){preact_module_n.useDebugValue&&preact_module_n.useDebugValue(r?r(t):t)}preact_module_n.unmount=function(n){hooks_module_o&&hooks_module_o(n);var t=n.__c;if(t){var r=t.__H;r&&r.i.forEach(function(n){return n.l&&n.l()})}};var hooks_module_g=function(){};function hooks_module_w(){hooks_module_u.some(function(n){n.m=!1,n.__P&&(n.__H.t=q(n.__H.t))}),hooks_module_u=[]}function E(){setTimeout(hooks_module_w)}function q(n){return n.forEach(hooks_module_x),n.forEach(hooks_module_A),[]}function hooks_module_x(n){n.l&&n.l()}function hooks_module_A(n){var t=n.o();"function"==typeof t&&(n.l=t)}function F(n,t){return!n||t.some(function(t,r){return t!==n[r]})}function hooks_module_L(n,t){return"function"==typeof t?t(n):t}"undefined"!=typeof window&&(hooks_module_g=function(t){!t.m&&(t.m=!0)&&1===hooks_module_u.push(t)&&(preact_module_n.requestAnimationFrame?preact_module_n.requestAnimationFrame(hooks_module_w):requestAnimationFrame(E))});
//# sourceMappingURL=hooks.module.js.map

// CONCATENATED MODULE: ./node_modules/preact/compat/dist/compat.module.js
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "version", function() { return compat_module_p; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Children", function() { return compat_module_F; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "render", function() { return compat_module_C; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "hydrate", function() { return compat_module_C; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "unmountComponentAtNode", function() { return compat_module_; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "createPortal", function() { return compat_module_E; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "createElement", function() { return compat_module_N; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "createFactory", function() { return compat_module_x; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "cloneElement", function() { return S; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "isValidElement", function() { return compat_module_O; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "findDOMNode", function() { return M; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "PureComponent", function() { return compat_module_P; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "memo", function() { return U; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "forwardRef", function() { return Z; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "unstable_batchedUpdates", function() { return compat_module_L; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "Suspense", function() { return V; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "lazy", function() { return compat_module_$; });
/* concated harmony reexport useState */__webpack_require__.d(__webpack_exports__, "useState", function() { return hooks_module_e; });
/* concated harmony reexport useReducer */__webpack_require__.d(__webpack_exports__, "useReducer", function() { return hooks_module_a; });
/* concated harmony reexport useEffect */__webpack_require__.d(__webpack_exports__, "useEffect", function() { return hooks_module_v; });
/* concated harmony reexport useLayoutEffect */__webpack_require__.d(__webpack_exports__, "useLayoutEffect", function() { return hooks_module_p; });
/* concated harmony reexport useRef */__webpack_require__.d(__webpack_exports__, "useRef", function() { return hooks_module_d; });
/* concated harmony reexport useImperativeHandle */__webpack_require__.d(__webpack_exports__, "useImperativeHandle", function() { return hooks_module_l; });
/* concated harmony reexport useMemo */__webpack_require__.d(__webpack_exports__, "useMemo", function() { return hooks_module_m; });
/* concated harmony reexport useCallback */__webpack_require__.d(__webpack_exports__, "useCallback", function() { return hooks_module_s; });
/* concated harmony reexport useContext */__webpack_require__.d(__webpack_exports__, "useContext", function() { return hooks_module_y; });
/* concated harmony reexport useDebugValue */__webpack_require__.d(__webpack_exports__, "useDebugValue", function() { return hooks_module_; });
/* concated harmony reexport createContext */__webpack_require__.d(__webpack_exports__, "createContext", function() { return L; });
/* concated harmony reexport createRef */__webpack_require__.d(__webpack_exports__, "createRef", function() { return v; });
/* concated harmony reexport Fragment */__webpack_require__.d(__webpack_exports__, "Fragment", function() { return p; });
/* concated harmony reexport Component */__webpack_require__.d(__webpack_exports__, "Component", function() { return d; });
function compat_module_d(n,t){for(var r in t)n[r]=t[r];return n}function compat_module_h(){this.t=[]}(compat_module_h.prototype=new d).o=function(n){var t=this;t.t.push(n);var r=function(){t.t[t.t.indexOf(n)]=t.t[t.t.length-1],t.t.pop(),0==t.t.length&&(O(t.props.fallback),t.__v.__e=null,t.__v.__k=t.state.i,t.setState({i:null}))};null==t.state.i&&(t.setState({i:t.__v.__k}),function n(t){for(var r=0;r<t.length;r++){var e=t[r];null!=e&&("function"!=typeof e.type&&e.__e?(i=void 0,(i=(o=e.__e).parentNode)&&i.removeChild(o)):e.__k&&n(e.__k))}var o,i}(t.__v.__k),t.__v.__k=[]),n.then(r,r)},compat_module_h.prototype.render=function(n,t){return t.i?n.fallback:n.children};var compat_module_p="16.8.0",compat_module_m="undefined"!=typeof Symbol&&Symbol.for&&Symbol.for("react.element")||60103,compat_module_y=/^(?:accent|alignment|arabic|baseline|cap|clip|color|fill|flood|font|glyph|horiz|marker|overline|paint|stop|strikethrough|stroke|text|underline|unicode|units|v|vector|vert|word|writing|x)[A-Z]/,compat_module_b=preact_module_n.event;preact_module_n.event=function(n){return compat_module_b&&(n=compat_module_b(n)),n.persist=function(){},n.nativeEvent=n};var compat_module_g=preact_module_n.__E;function compat_module_x(n){return compat_module_N.bind(null,n)}function compat_module_C(n,t,r){return D(n,t),"function"==typeof r&&r(),n?n.__c:null}preact_module_n.__E=function(n,t,r){return compat_module_g&&compat_module_g(n,t,r)||function(n,t,r){if(n.then)for(var e,o=t;o;o=o.__p)if((e=o.__c)&&e.o)return r&&(t.__e=r.__e,t.__k=r.__k),e.o(n),!0;return!1}(n,t,r)};var compat_module_w=function(){};function compat_module_k(n){var t=a(compat_module_w,{context:this.context},n.vnode),r=n.container;return n.container!==this.container&&(H("",r),this.container=r),compat_module_C(t,r),this.componentWillUnmount=function(){compat_module_C(null,r)},null}function compat_module_E(n,t){return a(compat_module_k,{vnode:n,container:t})}compat_module_w.prototype.getChildContext=function(){return this.props.context},compat_module_w.prototype.render=function(n){return n.children};var compat_module_A=function(n,t){return n?_(n).map(t):null},compat_module_F={map:compat_module_A,forEach:compat_module_A,count:function(n){return n?_(n).length:0},only:function(n){if(1!==(n=_(n)).length)throw new Error("Children.only() expects only one child.");return n[0]},toArray:_};function compat_module_N(){for(var n=[],t=arguments.length;t--;)n[t]=arguments[t];var r=a.apply(void 0,n),e=r.type,o=r.props;return"function"!=typeof e&&(o.defaultValue&&(o.value||0===o.value||(o.value=o.defaultValue),delete o.defaultValue),Array.isArray(o.value)&&o.multiple&&"select"===e&&(_(o.children).forEach(function(n){-1!=o.value.indexOf(n.props.value)&&(n.props.selected=!0)}),delete o.value),function(n,t){var r,e,o;for(o in t)if(r=compat_module_y.test(o))break;if(r)for(o in e=n.props={},t)e[compat_module_y.test(o)?o.replace(/([A-Z0-9])/,"-$1").toLowerCase():o]=t[o]}(r,o)),r.preactCompatNormalized=!1,R(r)}function R(n){return n.preactCompatNormalized=!0,function(n){var t=n.props;(t.class||t.className)&&(compat_module_j.enumerable="className"in t,t.className&&(t.class=t.className),Object.defineProperty(t,"className",compat_module_j))}(n),n}function S(n){if(!compat_module_O(n))return n;var t=R(I.apply(null,arguments));return t.$$typeof=compat_module_m,t}function compat_module_O(n){return!!n&&n.$$typeof===compat_module_m}function compat_module_(n){return!!n.__k&&(D(null,n),!0)}var compat_module_j={configurable:!0,get:function(){return this.class}};function compat_module_z(n,t){for(var r in n)if(!(r in t))return!0;for(var e in t)if(n[e]!==t[e])return!0;return!1}function M(n){return n&&(n.base||1===n.nodeType&&n)||null}var compat_module_P=function(n){function t(t){n.call(this,t),this.isPureReactComponent=!0}return n&&(t.__proto__=n),(t.prototype=Object.create(n&&n.prototype)).constructor=t,t.prototype.shouldComponentUpdate=function(n,t){return compat_module_z(this.props,n)||compat_module_z(this.state,t)},t}(d);function U(n,t){function r(n){var r=this.props.ref,e=r==n.ref;return e||(r.call?r(null):r.current=null),(t?!t(this.props,n):compat_module_z(this.props,n))||!e}function e(t){return this.shouldComponentUpdate=r,a(n,compat_module_d({},t))}return e.displayName="Memo("+(n.displayName||n.name)+")",e.u=!0,e}function W(n,t){Object.defineProperty(n.prototype,"UNSAFE_"+t,{configurable:!0,get:function(){return this[t]},set:function(n){this[t]=n}})}function Z(n){function t(t){var r=t.ref;return delete t.ref,n(t,r)}return t.u=!0,t.displayName="ForwardRef("+(n.displayName||n.name)+")",t}d.prototype.isReactComponent={},W(d,"componentWillMount"),W(d,"componentWillReceiveProps"),W(d,"componentWillUpdate");var compat_module_D=preact_module_n.vnode;function compat_module_L(n,t){n(t)}preact_module_n.vnode=function(n){n.$$typeof=compat_module_m,function(t){var r=n.type,e=n.props;if(e&&"string"==typeof r){var o={};for(var i in e)o[i.toLowerCase()]=i;if(o.ondoubleclick&&(e.ondblclick=e[o.ondoubleclick],delete e[o.ondoubleclick]),o.onbeforeinput&&(e.onbeforeinput=e[o.onbeforeinput],delete e[o.onbeforeinput]),o.onchange&&("textarea"===r||"input"===r.toLowerCase()&&!/^fil|che|rad/i.test(e.type))){var u=o.oninput||"oninput";e[u]||(e[u]=e[o.onchange],delete e[o.onchange])}}}();var t=n.type;t&&t.u&&n.ref&&(n.props.ref=n.ref,n.ref=null),compat_module_D&&compat_module_D(n)};var V=compat_module_h,compat_module_$=function(n){var t,e,o;function i(i){if(t||(t=n()).then(function(n){e=n.default},function(n){o=n}),o)throw o;if(!e)throw t;return a(e,i)}return i.displayName="Lazy",i};/* harmony default export */ var compat_module = __webpack_exports__["default"] = (compat_module_d({version:"16.8.0",Children:compat_module_F,render:compat_module_C,hydrate:compat_module_C,unmountComponentAtNode:compat_module_,createPortal:compat_module_E,createElement:compat_module_N,createContext:L,createFactory:compat_module_x,cloneElement:S,createRef:v,Fragment:p,isValidElement:compat_module_O,findDOMNode:M,Component:d,PureComponent:compat_module_P,memo:U,forwardRef:Z,unstable_batchedUpdates:compat_module_L},hooks_module_namespaceObject));
//# sourceMappingURL=compat.module.js.map


/***/ }),

/***/ "./node_modules/prop-types/factoryWithThrowingShims.js":
/*!*************************************************************!*\
  !*** ./node_modules/prop-types/factoryWithThrowingShims.js ***!
  \*************************************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/**
 * Copyright (c) 2013-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */



var ReactPropTypesSecret = __webpack_require__(/*! ./lib/ReactPropTypesSecret */ "./node_modules/prop-types/lib/ReactPropTypesSecret.js");

function emptyFunction() {}
function emptyFunctionWithReset() {}
emptyFunctionWithReset.resetWarningCache = emptyFunction;

module.exports = function() {
  function shim(props, propName, componentName, location, propFullName, secret) {
    if (secret === ReactPropTypesSecret) {
      // It is still safe when called from React.
      return;
    }
    var err = new Error(
      'Calling PropTypes validators directly is not supported by the `prop-types` package. ' +
      'Use PropTypes.checkPropTypes() to call them. ' +
      'Read more at http://fb.me/use-check-prop-types'
    );
    err.name = 'Invariant Violation';
    throw err;
  };
  shim.isRequired = shim;
  function getShim() {
    return shim;
  };
  // Important!
  // Keep this list in sync with production version in `./factoryWithTypeCheckers.js`.
  var ReactPropTypes = {
    array: shim,
    bool: shim,
    func: shim,
    number: shim,
    object: shim,
    string: shim,
    symbol: shim,

    any: shim,
    arrayOf: getShim,
    element: shim,
    elementType: shim,
    instanceOf: getShim,
    node: shim,
    objectOf: getShim,
    oneOf: getShim,
    oneOfType: getShim,
    shape: getShim,
    exact: getShim,

    checkPropTypes: emptyFunctionWithReset,
    resetWarningCache: emptyFunction
  };

  ReactPropTypes.PropTypes = ReactPropTypes;

  return ReactPropTypes;
};


/***/ }),

/***/ "./node_modules/prop-types/index.js":
/*!******************************************!*\
  !*** ./node_modules/prop-types/index.js ***!
  \******************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

/**
 * Copyright (c) 2013-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

if (false) { var throwOnDirectAccess, ReactIs; } else {
  // By explicitly using `prop-types` you are opting into new production behavior.
  // http://fb.me/prop-types-in-prod
  module.exports = __webpack_require__(/*! ./factoryWithThrowingShims */ "./node_modules/prop-types/factoryWithThrowingShims.js")();
}


/***/ }),

/***/ "./node_modules/prop-types/lib/ReactPropTypesSecret.js":
/*!*************************************************************!*\
  !*** ./node_modules/prop-types/lib/ReactPropTypesSecret.js ***!
  \*************************************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/**
 * Copyright (c) 2013-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */



var ReactPropTypesSecret = 'SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED';

module.exports = ReactPropTypesSecret;


/***/ }),

/***/ "./node_modules/react-is/cjs/react-is.production.min.js":
/*!**************************************************************!*\
  !*** ./node_modules/react-is/cjs/react-is.production.min.js ***!
  \**************************************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/** @license React v16.8.6
 * react-is.production.min.js
 *
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

Object.defineProperty(exports,"__esModule",{value:!0});
var b="function"===typeof Symbol&&Symbol.for,c=b?Symbol.for("react.element"):60103,d=b?Symbol.for("react.portal"):60106,e=b?Symbol.for("react.fragment"):60107,f=b?Symbol.for("react.strict_mode"):60108,g=b?Symbol.for("react.profiler"):60114,h=b?Symbol.for("react.provider"):60109,k=b?Symbol.for("react.context"):60110,l=b?Symbol.for("react.async_mode"):60111,m=b?Symbol.for("react.concurrent_mode"):60111,n=b?Symbol.for("react.forward_ref"):60112,p=b?Symbol.for("react.suspense"):60113,q=b?Symbol.for("react.memo"):
60115,r=b?Symbol.for("react.lazy"):60116;function t(a){if("object"===typeof a&&null!==a){var u=a.$$typeof;switch(u){case c:switch(a=a.type,a){case l:case m:case e:case g:case f:case p:return a;default:switch(a=a&&a.$$typeof,a){case k:case n:case h:return a;default:return u}}case r:case q:case d:return u}}}function v(a){return t(a)===m}exports.typeOf=t;exports.AsyncMode=l;exports.ConcurrentMode=m;exports.ContextConsumer=k;exports.ContextProvider=h;exports.Element=c;exports.ForwardRef=n;
exports.Fragment=e;exports.Lazy=r;exports.Memo=q;exports.Portal=d;exports.Profiler=g;exports.StrictMode=f;exports.Suspense=p;exports.isValidElementType=function(a){return"string"===typeof a||"function"===typeof a||a===e||a===m||a===g||a===f||a===p||"object"===typeof a&&null!==a&&(a.$$typeof===r||a.$$typeof===q||a.$$typeof===h||a.$$typeof===k||a.$$typeof===n)};exports.isAsyncMode=function(a){return v(a)||t(a)===l};exports.isConcurrentMode=v;exports.isContextConsumer=function(a){return t(a)===k};
exports.isContextProvider=function(a){return t(a)===h};exports.isElement=function(a){return"object"===typeof a&&null!==a&&a.$$typeof===c};exports.isForwardRef=function(a){return t(a)===n};exports.isFragment=function(a){return t(a)===e};exports.isLazy=function(a){return t(a)===r};exports.isMemo=function(a){return t(a)===q};exports.isPortal=function(a){return t(a)===d};exports.isProfiler=function(a){return t(a)===g};exports.isStrictMode=function(a){return t(a)===f};
exports.isSuspense=function(a){return t(a)===p};


/***/ }),

/***/ "./node_modules/react-is/index.js":
/*!****************************************!*\
  !*** ./node_modules/react-is/index.js ***!
  \****************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


if (true) {
  module.exports = __webpack_require__(/*! ./cjs/react-is.production.min.js */ "./node_modules/react-is/cjs/react-is.production.min.js");
} else {}


/***/ }),

/***/ "./node_modules/react-router-dom/es/index.js":
/*!****************************************************************!*\
  !*** ./node_modules/react-router-dom/es/index.js + 29 modules ***!
  \****************************************************************/
/*! exports provided: BrowserRouter, HashRouter, Link, MemoryRouter, NavLink, Prompt, Redirect, Route, Router, StaticRouter, Switch, generatePath, matchPath, withRouter */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/@babel/runtime/helpers/esm/extends.js because of ./src/index.js */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/invariant/browser.js (<- Module is not an ECMAScript module) */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/path-to-regexp/index.js (<- Module is not an ECMAScript module) */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/preact/compat/dist/compat.module.js because of ./src/index.js */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/prop-types/index.js (<- Module is not an ECMAScript module) */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/react-router/node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js (<- Module is not an ECMAScript module) */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/warning/warning.js (<- Module is not an ECMAScript module) */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);

// EXTERNAL MODULE: ./node_modules/warning/warning.js
var warning = __webpack_require__("./node_modules/warning/warning.js");
var warning_default = /*#__PURE__*/__webpack_require__.n(warning);

// EXTERNAL MODULE: ./node_modules/preact/compat/dist/compat.module.js + 2 modules
var compat_module = __webpack_require__("./node_modules/preact/compat/dist/compat.module.js");

// EXTERNAL MODULE: ./node_modules/prop-types/index.js
var prop_types = __webpack_require__("./node_modules/prop-types/index.js");
var prop_types_default = /*#__PURE__*/__webpack_require__.n(prop_types);

// EXTERNAL MODULE: ./node_modules/@babel/runtime/helpers/esm/extends.js
var esm_extends = __webpack_require__("./node_modules/@babel/runtime/helpers/esm/extends.js");

// CONCATENATED MODULE: ./node_modules/resolve-pathname/index.js
function isAbsolute(pathname) {
  return pathname.charAt(0) === '/';
}

// About 1.5x faster than the two-arg version of Array#splice()
function spliceOne(list, index) {
  for (var i = index, k = i + 1, n = list.length; k < n; i += 1, k += 1) {
    list[i] = list[k];
  }

  list.pop();
}

// This implementation is based heavily on node's url.parse
function resolvePathname(to) {
  var from = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : '';

  var toParts = to && to.split('/') || [];
  var fromParts = from && from.split('/') || [];

  var isToAbs = to && isAbsolute(to);
  var isFromAbs = from && isAbsolute(from);
  var mustEndAbs = isToAbs || isFromAbs;

  if (to && isAbsolute(to)) {
    // to is absolute
    fromParts = toParts;
  } else if (toParts.length) {
    // to is relative, drop the filename
    fromParts.pop();
    fromParts = fromParts.concat(toParts);
  }

  if (!fromParts.length) return '/';

  var hasTrailingSlash = void 0;
  if (fromParts.length) {
    var last = fromParts[fromParts.length - 1];
    hasTrailingSlash = last === '.' || last === '..' || last === '';
  } else {
    hasTrailingSlash = false;
  }

  var up = 0;
  for (var i = fromParts.length; i >= 0; i--) {
    var part = fromParts[i];

    if (part === '.') {
      spliceOne(fromParts, i);
    } else if (part === '..') {
      spliceOne(fromParts, i);
      up++;
    } else if (up) {
      spliceOne(fromParts, i);
      up--;
    }
  }

  if (!mustEndAbs) for (; up--; up) {
    fromParts.unshift('..');
  }if (mustEndAbs && fromParts[0] !== '' && (!fromParts[0] || !isAbsolute(fromParts[0]))) fromParts.unshift('');

  var result = fromParts.join('/');

  if (hasTrailingSlash && result.substr(-1) !== '/') result += '/';

  return result;
}

/* harmony default export */ var resolve_pathname = (resolvePathname);
// CONCATENATED MODULE: ./node_modules/value-equal/index.js
var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

function valueEqual(a, b) {
  if (a === b) return true;

  if (a == null || b == null) return false;

  if (Array.isArray(a)) {
    return Array.isArray(b) && a.length === b.length && a.every(function (item, index) {
      return valueEqual(item, b[index]);
    });
  }

  var aType = typeof a === 'undefined' ? 'undefined' : _typeof(a);
  var bType = typeof b === 'undefined' ? 'undefined' : _typeof(b);

  if (aType !== bType) return false;

  if (aType === 'object') {
    var aValue = a.valueOf();
    var bValue = b.valueOf();

    if (aValue !== a || bValue !== b) return valueEqual(aValue, bValue);

    var aKeys = Object.keys(a);
    var bKeys = Object.keys(b);

    if (aKeys.length !== bKeys.length) return false;

    return aKeys.every(function (key) {
      return valueEqual(a[key], b[key]);
    });
  }

  return false;
}

/* harmony default export */ var value_equal = (valueEqual);
// CONCATENATED MODULE: ./node_modules/tiny-warning/dist/tiny-warning.esm.js
var isProduction = "production" === 'production';
function tiny_warning_esm_warning(condition, message) {
  if (!isProduction) {
    if (condition) {
      return;
    }

    var text = "Warning: " + message;

    if (typeof console !== 'undefined') {
      console.warn(text);
    }

    try {
      throw Error(text);
    } catch (x) {}
  }
}

/* harmony default export */ var tiny_warning_esm = (tiny_warning_esm_warning);

// CONCATENATED MODULE: ./node_modules/tiny-invariant/dist/tiny-invariant.esm.js
var tiny_invariant_esm_isProduction = "production" === 'production';
var prefix = 'Invariant failed';
function invariant(condition, message) {
  if (condition) {
    return;
  }

  if (tiny_invariant_esm_isProduction) {
    throw new Error(prefix);
  } else {
    throw new Error(prefix + ": " + (message || ''));
  }
}

/* harmony default export */ var tiny_invariant_esm = (invariant);

// CONCATENATED MODULE: ./node_modules/history/esm/history.js






function addLeadingSlash(path) {
  return path.charAt(0) === '/' ? path : '/' + path;
}
function stripLeadingSlash(path) {
  return path.charAt(0) === '/' ? path.substr(1) : path;
}
function hasBasename(path, prefix) {
  return new RegExp('^' + prefix + '(\\/|\\?|#|$)', 'i').test(path);
}
function stripBasename(path, prefix) {
  return hasBasename(path, prefix) ? path.substr(prefix.length) : path;
}
function stripTrailingSlash(path) {
  return path.charAt(path.length - 1) === '/' ? path.slice(0, -1) : path;
}
function parsePath(path) {
  var pathname = path || '/';
  var search = '';
  var hash = '';
  var hashIndex = pathname.indexOf('#');

  if (hashIndex !== -1) {
    hash = pathname.substr(hashIndex);
    pathname = pathname.substr(0, hashIndex);
  }

  var searchIndex = pathname.indexOf('?');

  if (searchIndex !== -1) {
    search = pathname.substr(searchIndex);
    pathname = pathname.substr(0, searchIndex);
  }

  return {
    pathname: pathname,
    search: search === '?' ? '' : search,
    hash: hash === '#' ? '' : hash
  };
}
function createPath(location) {
  var pathname = location.pathname,
      search = location.search,
      hash = location.hash;
  var path = pathname || '/';
  if (search && search !== '?') path += search.charAt(0) === '?' ? search : "?" + search;
  if (hash && hash !== '#') path += hash.charAt(0) === '#' ? hash : "#" + hash;
  return path;
}

function createLocation(path, state, key, currentLocation) {
  var location;

  if (typeof path === 'string') {
    // Two-arg form: push(path, state)
    location = parsePath(path);
    location.state = state;
  } else {
    // One-arg form: push(location)
    location = Object(esm_extends["default"])({}, path);
    if (location.pathname === undefined) location.pathname = '';

    if (location.search) {
      if (location.search.charAt(0) !== '?') location.search = '?' + location.search;
    } else {
      location.search = '';
    }

    if (location.hash) {
      if (location.hash.charAt(0) !== '#') location.hash = '#' + location.hash;
    } else {
      location.hash = '';
    }

    if (state !== undefined && location.state === undefined) location.state = state;
  }

  try {
    location.pathname = decodeURI(location.pathname);
  } catch (e) {
    if (e instanceof URIError) {
      throw new URIError('Pathname "' + location.pathname + '" could not be decoded. ' + 'This is likely caused by an invalid percent-encoding.');
    } else {
      throw e;
    }
  }

  if (key) location.key = key;

  if (currentLocation) {
    // Resolve incomplete/relative pathname relative to current location.
    if (!location.pathname) {
      location.pathname = currentLocation.pathname;
    } else if (location.pathname.charAt(0) !== '/') {
      location.pathname = resolve_pathname(location.pathname, currentLocation.pathname);
    }
  } else {
    // When there is no prior location and pathname is empty, set it to /
    if (!location.pathname) {
      location.pathname = '/';
    }
  }

  return location;
}
function locationsAreEqual(a, b) {
  return a.pathname === b.pathname && a.search === b.search && a.hash === b.hash && a.key === b.key && value_equal(a.state, b.state);
}

function createTransitionManager() {
  var prompt = null;

  function setPrompt(nextPrompt) {
     false ? undefined : void 0;
    prompt = nextPrompt;
    return function () {
      if (prompt === nextPrompt) prompt = null;
    };
  }

  function confirmTransitionTo(location, action, getUserConfirmation, callback) {
    // TODO: If another transition starts while we're still confirming
    // the previous one, we may end up in a weird state. Figure out the
    // best way to handle this.
    if (prompt != null) {
      var result = typeof prompt === 'function' ? prompt(location, action) : prompt;

      if (typeof result === 'string') {
        if (typeof getUserConfirmation === 'function') {
          getUserConfirmation(result, callback);
        } else {
           false ? undefined : void 0;
          callback(true);
        }
      } else {
        // Return false from a transition hook to cancel the transition.
        callback(result !== false);
      }
    } else {
      callback(true);
    }
  }

  var listeners = [];

  function appendListener(fn) {
    var isActive = true;

    function listener() {
      if (isActive) fn.apply(void 0, arguments);
    }

    listeners.push(listener);
    return function () {
      isActive = false;
      listeners = listeners.filter(function (item) {
        return item !== listener;
      });
    };
  }

  function notifyListeners() {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    listeners.forEach(function (listener) {
      return listener.apply(void 0, args);
    });
  }

  return {
    setPrompt: setPrompt,
    confirmTransitionTo: confirmTransitionTo,
    appendListener: appendListener,
    notifyListeners: notifyListeners
  };
}

var canUseDOM = !!(typeof window !== 'undefined' && window.document && window.document.createElement);
function getConfirmation(message, callback) {
  callback(window.confirm(message)); // eslint-disable-line no-alert
}
/**
 * Returns true if the HTML5 history API is supported. Taken from Modernizr.
 *
 * https://github.com/Modernizr/Modernizr/blob/master/LICENSE
 * https://github.com/Modernizr/Modernizr/blob/master/feature-detects/history.js
 * changed to avoid false negatives for Windows Phones: https://github.com/reactjs/react-router/issues/586
 */

function supportsHistory() {
  var ua = window.navigator.userAgent;
  if ((ua.indexOf('Android 2.') !== -1 || ua.indexOf('Android 4.0') !== -1) && ua.indexOf('Mobile Safari') !== -1 && ua.indexOf('Chrome') === -1 && ua.indexOf('Windows Phone') === -1) return false;
  return window.history && 'pushState' in window.history;
}
/**
 * Returns true if browser fires popstate on hash change.
 * IE10 and IE11 do not.
 */

function supportsPopStateOnHashChange() {
  return window.navigator.userAgent.indexOf('Trident') === -1;
}
/**
 * Returns false if using go(n) with hash history causes a full page reload.
 */

function supportsGoWithoutReloadUsingHash() {
  return window.navigator.userAgent.indexOf('Firefox') === -1;
}
/**
 * Returns true if a given popstate event is an extraneous WebKit event.
 * Accounts for the fact that Chrome on iOS fires real popstate events
 * containing undefined state when pressing the back button.
 */

function isExtraneousPopstateEvent(event) {
  event.state === undefined && navigator.userAgent.indexOf('CriOS') === -1;
}

var PopStateEvent = 'popstate';
var HashChangeEvent = 'hashchange';

function getHistoryState() {
  try {
    return window.history.state || {};
  } catch (e) {
    // IE 11 sometimes throws when accessing window.history.state
    // See https://github.com/ReactTraining/history/pull/289
    return {};
  }
}
/**
 * Creates a history object that uses the HTML5 history API including
 * pushState, replaceState, and the popstate event.
 */


function createBrowserHistory(props) {
  if (props === void 0) {
    props = {};
  }

  !canUseDOM ?  false ? undefined : tiny_invariant_esm(false) : void 0;
  var globalHistory = window.history;
  var canUseHistory = supportsHistory();
  var needsHashChangeListener = !supportsPopStateOnHashChange();
  var _props = props,
      _props$forceRefresh = _props.forceRefresh,
      forceRefresh = _props$forceRefresh === void 0 ? false : _props$forceRefresh,
      _props$getUserConfirm = _props.getUserConfirmation,
      getUserConfirmation = _props$getUserConfirm === void 0 ? getConfirmation : _props$getUserConfirm,
      _props$keyLength = _props.keyLength,
      keyLength = _props$keyLength === void 0 ? 6 : _props$keyLength;
  var basename = props.basename ? stripTrailingSlash(addLeadingSlash(props.basename)) : '';

  function getDOMLocation(historyState) {
    var _ref = historyState || {},
        key = _ref.key,
        state = _ref.state;

    var _window$location = window.location,
        pathname = _window$location.pathname,
        search = _window$location.search,
        hash = _window$location.hash;
    var path = pathname + search + hash;
     false ? undefined : void 0;
    if (basename) path = stripBasename(path, basename);
    return createLocation(path, state, key);
  }

  function createKey() {
    return Math.random().toString(36).substr(2, keyLength);
  }

  var transitionManager = createTransitionManager();

  function setState(nextState) {
    Object(esm_extends["default"])(history, nextState);

    history.length = globalHistory.length;
    transitionManager.notifyListeners(history.location, history.action);
  }

  function handlePopState(event) {
    // Ignore extraneous popstate events in WebKit.
    if (isExtraneousPopstateEvent(event)) return;
    handlePop(getDOMLocation(event.state));
  }

  function handleHashChange() {
    handlePop(getDOMLocation(getHistoryState()));
  }

  var forceNextPop = false;

  function handlePop(location) {
    if (forceNextPop) {
      forceNextPop = false;
      setState();
    } else {
      var action = 'POP';
      transitionManager.confirmTransitionTo(location, action, getUserConfirmation, function (ok) {
        if (ok) {
          setState({
            action: action,
            location: location
          });
        } else {
          revertPop(location);
        }
      });
    }
  }

  function revertPop(fromLocation) {
    var toLocation = history.location; // TODO: We could probably make this more reliable by
    // keeping a list of keys we've seen in sessionStorage.
    // Instead, we just default to 0 for keys we don't know.

    var toIndex = allKeys.indexOf(toLocation.key);
    if (toIndex === -1) toIndex = 0;
    var fromIndex = allKeys.indexOf(fromLocation.key);
    if (fromIndex === -1) fromIndex = 0;
    var delta = toIndex - fromIndex;

    if (delta) {
      forceNextPop = true;
      go(delta);
    }
  }

  var initialLocation = getDOMLocation(getHistoryState());
  var allKeys = [initialLocation.key]; // Public interface

  function createHref(location) {
    return basename + createPath(location);
  }

  function push(path, state) {
     false ? undefined : void 0;
    var action = 'PUSH';
    var location = createLocation(path, state, createKey(), history.location);
    transitionManager.confirmTransitionTo(location, action, getUserConfirmation, function (ok) {
      if (!ok) return;
      var href = createHref(location);
      var key = location.key,
          state = location.state;

      if (canUseHistory) {
        globalHistory.pushState({
          key: key,
          state: state
        }, null, href);

        if (forceRefresh) {
          window.location.href = href;
        } else {
          var prevIndex = allKeys.indexOf(history.location.key);
          var nextKeys = allKeys.slice(0, prevIndex === -1 ? 0 : prevIndex + 1);
          nextKeys.push(location.key);
          allKeys = nextKeys;
          setState({
            action: action,
            location: location
          });
        }
      } else {
         false ? undefined : void 0;
        window.location.href = href;
      }
    });
  }

  function replace(path, state) {
     false ? undefined : void 0;
    var action = 'REPLACE';
    var location = createLocation(path, state, createKey(), history.location);
    transitionManager.confirmTransitionTo(location, action, getUserConfirmation, function (ok) {
      if (!ok) return;
      var href = createHref(location);
      var key = location.key,
          state = location.state;

      if (canUseHistory) {
        globalHistory.replaceState({
          key: key,
          state: state
        }, null, href);

        if (forceRefresh) {
          window.location.replace(href);
        } else {
          var prevIndex = allKeys.indexOf(history.location.key);
          if (prevIndex !== -1) allKeys[prevIndex] = location.key;
          setState({
            action: action,
            location: location
          });
        }
      } else {
         false ? undefined : void 0;
        window.location.replace(href);
      }
    });
  }

  function go(n) {
    globalHistory.go(n);
  }

  function goBack() {
    go(-1);
  }

  function goForward() {
    go(1);
  }

  var listenerCount = 0;

  function checkDOMListeners(delta) {
    listenerCount += delta;

    if (listenerCount === 1 && delta === 1) {
      window.addEventListener(PopStateEvent, handlePopState);
      if (needsHashChangeListener) window.addEventListener(HashChangeEvent, handleHashChange);
    } else if (listenerCount === 0) {
      window.removeEventListener(PopStateEvent, handlePopState);
      if (needsHashChangeListener) window.removeEventListener(HashChangeEvent, handleHashChange);
    }
  }

  var isBlocked = false;

  function block(prompt) {
    if (prompt === void 0) {
      prompt = false;
    }

    var unblock = transitionManager.setPrompt(prompt);

    if (!isBlocked) {
      checkDOMListeners(1);
      isBlocked = true;
    }

    return function () {
      if (isBlocked) {
        isBlocked = false;
        checkDOMListeners(-1);
      }

      return unblock();
    };
  }

  function listen(listener) {
    var unlisten = transitionManager.appendListener(listener);
    checkDOMListeners(1);
    return function () {
      checkDOMListeners(-1);
      unlisten();
    };
  }

  var history = {
    length: globalHistory.length,
    action: 'POP',
    location: initialLocation,
    createHref: createHref,
    push: push,
    replace: replace,
    go: go,
    goBack: goBack,
    goForward: goForward,
    block: block,
    listen: listen
  };
  return history;
}

var HashChangeEvent$1 = 'hashchange';
var HashPathCoders = {
  hashbang: {
    encodePath: function encodePath(path) {
      return path.charAt(0) === '!' ? path : '!/' + stripLeadingSlash(path);
    },
    decodePath: function decodePath(path) {
      return path.charAt(0) === '!' ? path.substr(1) : path;
    }
  },
  noslash: {
    encodePath: stripLeadingSlash,
    decodePath: addLeadingSlash
  },
  slash: {
    encodePath: addLeadingSlash,
    decodePath: addLeadingSlash
  }
};

function getHashPath() {
  // We can't use window.location.hash here because it's not
  // consistent across browsers - Firefox will pre-decode it!
  var href = window.location.href;
  var hashIndex = href.indexOf('#');
  return hashIndex === -1 ? '' : href.substring(hashIndex + 1);
}

function pushHashPath(path) {
  window.location.hash = path;
}

function replaceHashPath(path) {
  var hashIndex = window.location.href.indexOf('#');
  window.location.replace(window.location.href.slice(0, hashIndex >= 0 ? hashIndex : 0) + '#' + path);
}

function createHashHistory(props) {
  if (props === void 0) {
    props = {};
  }

  !canUseDOM ?  false ? undefined : tiny_invariant_esm(false) : void 0;
  var globalHistory = window.history;
  var canGoWithoutReload = supportsGoWithoutReloadUsingHash();
  var _props = props,
      _props$getUserConfirm = _props.getUserConfirmation,
      getUserConfirmation = _props$getUserConfirm === void 0 ? getConfirmation : _props$getUserConfirm,
      _props$hashType = _props.hashType,
      hashType = _props$hashType === void 0 ? 'slash' : _props$hashType;
  var basename = props.basename ? stripTrailingSlash(addLeadingSlash(props.basename)) : '';
  var _HashPathCoders$hashT = HashPathCoders[hashType],
      encodePath = _HashPathCoders$hashT.encodePath,
      decodePath = _HashPathCoders$hashT.decodePath;

  function getDOMLocation() {
    var path = decodePath(getHashPath());
     false ? undefined : void 0;
    if (basename) path = stripBasename(path, basename);
    return createLocation(path);
  }

  var transitionManager = createTransitionManager();

  function setState(nextState) {
    Object(esm_extends["default"])(history, nextState);

    history.length = globalHistory.length;
    transitionManager.notifyListeners(history.location, history.action);
  }

  var forceNextPop = false;
  var ignorePath = null;

  function handleHashChange() {
    var path = getHashPath();
    var encodedPath = encodePath(path);

    if (path !== encodedPath) {
      // Ensure we always have a properly-encoded hash.
      replaceHashPath(encodedPath);
    } else {
      var location = getDOMLocation();
      var prevLocation = history.location;
      if (!forceNextPop && locationsAreEqual(prevLocation, location)) return; // A hashchange doesn't always == location change.

      if (ignorePath === createPath(location)) return; // Ignore this change; we already setState in push/replace.

      ignorePath = null;
      handlePop(location);
    }
  }

  function handlePop(location) {
    if (forceNextPop) {
      forceNextPop = false;
      setState();
    } else {
      var action = 'POP';
      transitionManager.confirmTransitionTo(location, action, getUserConfirmation, function (ok) {
        if (ok) {
          setState({
            action: action,
            location: location
          });
        } else {
          revertPop(location);
        }
      });
    }
  }

  function revertPop(fromLocation) {
    var toLocation = history.location; // TODO: We could probably make this more reliable by
    // keeping a list of paths we've seen in sessionStorage.
    // Instead, we just default to 0 for paths we don't know.

    var toIndex = allPaths.lastIndexOf(createPath(toLocation));
    if (toIndex === -1) toIndex = 0;
    var fromIndex = allPaths.lastIndexOf(createPath(fromLocation));
    if (fromIndex === -1) fromIndex = 0;
    var delta = toIndex - fromIndex;

    if (delta) {
      forceNextPop = true;
      go(delta);
    }
  } // Ensure the hash is encoded properly before doing anything else.


  var path = getHashPath();
  var encodedPath = encodePath(path);
  if (path !== encodedPath) replaceHashPath(encodedPath);
  var initialLocation = getDOMLocation();
  var allPaths = [createPath(initialLocation)]; // Public interface

  function createHref(location) {
    return '#' + encodePath(basename + createPath(location));
  }

  function push(path, state) {
     false ? undefined : void 0;
    var action = 'PUSH';
    var location = createLocation(path, undefined, undefined, history.location);
    transitionManager.confirmTransitionTo(location, action, getUserConfirmation, function (ok) {
      if (!ok) return;
      var path = createPath(location);
      var encodedPath = encodePath(basename + path);
      var hashChanged = getHashPath() !== encodedPath;

      if (hashChanged) {
        // We cannot tell if a hashchange was caused by a PUSH, so we'd
        // rather setState here and ignore the hashchange. The caveat here
        // is that other hash histories in the page will consider it a POP.
        ignorePath = path;
        pushHashPath(encodedPath);
        var prevIndex = allPaths.lastIndexOf(createPath(history.location));
        var nextPaths = allPaths.slice(0, prevIndex === -1 ? 0 : prevIndex + 1);
        nextPaths.push(path);
        allPaths = nextPaths;
        setState({
          action: action,
          location: location
        });
      } else {
         false ? undefined : void 0;
        setState();
      }
    });
  }

  function replace(path, state) {
     false ? undefined : void 0;
    var action = 'REPLACE';
    var location = createLocation(path, undefined, undefined, history.location);
    transitionManager.confirmTransitionTo(location, action, getUserConfirmation, function (ok) {
      if (!ok) return;
      var path = createPath(location);
      var encodedPath = encodePath(basename + path);
      var hashChanged = getHashPath() !== encodedPath;

      if (hashChanged) {
        // We cannot tell if a hashchange was caused by a REPLACE, so we'd
        // rather setState here and ignore the hashchange. The caveat here
        // is that other hash histories in the page will consider it a POP.
        ignorePath = path;
        replaceHashPath(encodedPath);
      }

      var prevIndex = allPaths.indexOf(createPath(history.location));
      if (prevIndex !== -1) allPaths[prevIndex] = path;
      setState({
        action: action,
        location: location
      });
    });
  }

  function go(n) {
     false ? undefined : void 0;
    globalHistory.go(n);
  }

  function goBack() {
    go(-1);
  }

  function goForward() {
    go(1);
  }

  var listenerCount = 0;

  function checkDOMListeners(delta) {
    listenerCount += delta;

    if (listenerCount === 1 && delta === 1) {
      window.addEventListener(HashChangeEvent$1, handleHashChange);
    } else if (listenerCount === 0) {
      window.removeEventListener(HashChangeEvent$1, handleHashChange);
    }
  }

  var isBlocked = false;

  function block(prompt) {
    if (prompt === void 0) {
      prompt = false;
    }

    var unblock = transitionManager.setPrompt(prompt);

    if (!isBlocked) {
      checkDOMListeners(1);
      isBlocked = true;
    }

    return function () {
      if (isBlocked) {
        isBlocked = false;
        checkDOMListeners(-1);
      }

      return unblock();
    };
  }

  function listen(listener) {
    var unlisten = transitionManager.appendListener(listener);
    checkDOMListeners(1);
    return function () {
      checkDOMListeners(-1);
      unlisten();
    };
  }

  var history = {
    length: globalHistory.length,
    action: 'POP',
    location: initialLocation,
    createHref: createHref,
    push: push,
    replace: replace,
    go: go,
    goBack: goBack,
    goForward: goForward,
    block: block,
    listen: listen
  };
  return history;
}

function clamp(n, lowerBound, upperBound) {
  return Math.min(Math.max(n, lowerBound), upperBound);
}
/**
 * Creates a history object that stores locations in memory.
 */


function createMemoryHistory(props) {
  if (props === void 0) {
    props = {};
  }

  var _props = props,
      getUserConfirmation = _props.getUserConfirmation,
      _props$initialEntries = _props.initialEntries,
      initialEntries = _props$initialEntries === void 0 ? ['/'] : _props$initialEntries,
      _props$initialIndex = _props.initialIndex,
      initialIndex = _props$initialIndex === void 0 ? 0 : _props$initialIndex,
      _props$keyLength = _props.keyLength,
      keyLength = _props$keyLength === void 0 ? 6 : _props$keyLength;
  var transitionManager = createTransitionManager();

  function setState(nextState) {
    Object(esm_extends["default"])(history, nextState);

    history.length = history.entries.length;
    transitionManager.notifyListeners(history.location, history.action);
  }

  function createKey() {
    return Math.random().toString(36).substr(2, keyLength);
  }

  var index = clamp(initialIndex, 0, initialEntries.length - 1);
  var entries = initialEntries.map(function (entry) {
    return typeof entry === 'string' ? createLocation(entry, undefined, createKey()) : createLocation(entry, undefined, entry.key || createKey());
  }); // Public interface

  var createHref = createPath;

  function push(path, state) {
     false ? undefined : void 0;
    var action = 'PUSH';
    var location = createLocation(path, state, createKey(), history.location);
    transitionManager.confirmTransitionTo(location, action, getUserConfirmation, function (ok) {
      if (!ok) return;
      var prevIndex = history.index;
      var nextIndex = prevIndex + 1;
      var nextEntries = history.entries.slice(0);

      if (nextEntries.length > nextIndex) {
        nextEntries.splice(nextIndex, nextEntries.length - nextIndex, location);
      } else {
        nextEntries.push(location);
      }

      setState({
        action: action,
        location: location,
        index: nextIndex,
        entries: nextEntries
      });
    });
  }

  function replace(path, state) {
     false ? undefined : void 0;
    var action = 'REPLACE';
    var location = createLocation(path, state, createKey(), history.location);
    transitionManager.confirmTransitionTo(location, action, getUserConfirmation, function (ok) {
      if (!ok) return;
      history.entries[history.index] = location;
      setState({
        action: action,
        location: location
      });
    });
  }

  function go(n) {
    var nextIndex = clamp(history.index + n, 0, history.entries.length - 1);
    var action = 'POP';
    var location = history.entries[nextIndex];
    transitionManager.confirmTransitionTo(location, action, getUserConfirmation, function (ok) {
      if (ok) {
        setState({
          action: action,
          location: location,
          index: nextIndex
        });
      } else {
        // Mimic the behavior of DOM histories by
        // causing a render after a cancelled POP.
        setState();
      }
    });
  }

  function goBack() {
    go(-1);
  }

  function goForward() {
    go(1);
  }

  function canGo(n) {
    var nextIndex = history.index + n;
    return nextIndex >= 0 && nextIndex < history.entries.length;
  }

  function block(prompt) {
    if (prompt === void 0) {
      prompt = false;
    }

    return transitionManager.setPrompt(prompt);
  }

  function listen(listener) {
    return transitionManager.appendListener(listener);
  }

  var history = {
    length: entries.length,
    action: 'POP',
    location: entries[index],
    index: index,
    entries: entries,
    createHref: createHref,
    push: push,
    replace: replace,
    go: go,
    goBack: goBack,
    goForward: goForward,
    canGo: canGo,
    block: block,
    listen: listen
  };
  return history;
}



// EXTERNAL MODULE: ./node_modules/invariant/browser.js
var browser = __webpack_require__("./node_modules/invariant/browser.js");
var browser_default = /*#__PURE__*/__webpack_require__.n(browser);

// CONCATENATED MODULE: ./node_modules/react-router/es/Router.js
var _extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }






/**
 * The public API for putting history on context.
 */

var Router_Router = function (_React$Component) {
  _inherits(Router, _React$Component);

  function Router() {
    var _temp, _this, _ret;

    _classCallCheck(this, Router);

    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    return _ret = (_temp = (_this = _possibleConstructorReturn(this, _React$Component.call.apply(_React$Component, [this].concat(args))), _this), _this.state = {
      match: _this.computeMatch(_this.props.history.location.pathname)
    }, _temp), _possibleConstructorReturn(_this, _ret);
  }

  Router.prototype.getChildContext = function getChildContext() {
    return {
      router: _extends({}, this.context.router, {
        history: this.props.history,
        route: {
          location: this.props.history.location,
          match: this.state.match
        }
      })
    };
  };

  Router.prototype.computeMatch = function computeMatch(pathname) {
    return {
      path: "/",
      url: "/",
      params: {},
      isExact: pathname === "/"
    };
  };

  Router.prototype.componentWillMount = function componentWillMount() {
    var _this2 = this;

    var _props = this.props,
        children = _props.children,
        history = _props.history;


    browser_default()(children == null || compat_module["default"].Children.count(children) === 1, "A <Router> may have only one child element");

    // Do this here so we can setState when a <Redirect> changes the
    // location in componentWillMount. This happens e.g. when doing
    // server rendering using a <StaticRouter>.
    this.unlisten = history.listen(function () {
      _this2.setState({
        match: _this2.computeMatch(history.location.pathname)
      });
    });
  };

  Router.prototype.componentWillReceiveProps = function componentWillReceiveProps(nextProps) {
    warning_default()(this.props.history === nextProps.history, "You cannot change <Router history>");
  };

  Router.prototype.componentWillUnmount = function componentWillUnmount() {
    this.unlisten();
  };

  Router.prototype.render = function render() {
    var children = this.props.children;

    return children ? compat_module["default"].Children.only(children) : null;
  };

  return Router;
}(compat_module["default"].Component);

Router_Router.propTypes = {
  history: prop_types_default.a.object.isRequired,
  children: prop_types_default.a.node
};
Router_Router.contextTypes = {
  router: prop_types_default.a.object
};
Router_Router.childContextTypes = {
  router: prop_types_default.a.object.isRequired
};


/* harmony default export */ var es_Router = (Router_Router);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/Router.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_Router = (es_Router);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/BrowserRouter.js
function BrowserRouter_classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function BrowserRouter_possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function BrowserRouter_inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }







/**
 * The public API for a <Router> that uses HTML5 history.
 */

var BrowserRouter_BrowserRouter = function (_React$Component) {
  BrowserRouter_inherits(BrowserRouter, _React$Component);

  function BrowserRouter() {
    var _temp, _this, _ret;

    BrowserRouter_classCallCheck(this, BrowserRouter);

    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    return _ret = (_temp = (_this = BrowserRouter_possibleConstructorReturn(this, _React$Component.call.apply(_React$Component, [this].concat(args))), _this), _this.history = createBrowserHistory(_this.props), _temp), BrowserRouter_possibleConstructorReturn(_this, _ret);
  }

  BrowserRouter.prototype.componentWillMount = function componentWillMount() {
    warning_default()(!this.props.history, "<BrowserRouter> ignores the history prop. To use a custom history, " + "use `import { Router }` instead of `import { BrowserRouter as Router }`.");
  };

  BrowserRouter.prototype.render = function render() {
    return compat_module["default"].createElement(react_router_dom_es_Router, { history: this.history, children: this.props.children });
  };

  return BrowserRouter;
}(compat_module["default"].Component);

BrowserRouter_BrowserRouter.propTypes = {
  basename: prop_types_default.a.string,
  forceRefresh: prop_types_default.a.bool,
  getUserConfirmation: prop_types_default.a.func,
  keyLength: prop_types_default.a.number,
  children: prop_types_default.a.node
};


/* harmony default export */ var es_BrowserRouter = (BrowserRouter_BrowserRouter);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/HashRouter.js
function HashRouter_classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function HashRouter_possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function HashRouter_inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }







/**
 * The public API for a <Router> that uses window.location.hash.
 */

var HashRouter_HashRouter = function (_React$Component) {
  HashRouter_inherits(HashRouter, _React$Component);

  function HashRouter() {
    var _temp, _this, _ret;

    HashRouter_classCallCheck(this, HashRouter);

    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    return _ret = (_temp = (_this = HashRouter_possibleConstructorReturn(this, _React$Component.call.apply(_React$Component, [this].concat(args))), _this), _this.history = createHashHistory(_this.props), _temp), HashRouter_possibleConstructorReturn(_this, _ret);
  }

  HashRouter.prototype.componentWillMount = function componentWillMount() {
    warning_default()(!this.props.history, "<HashRouter> ignores the history prop. To use a custom history, " + "use `import { Router }` instead of `import { HashRouter as Router }`.");
  };

  HashRouter.prototype.render = function render() {
    return compat_module["default"].createElement(react_router_dom_es_Router, { history: this.history, children: this.props.children });
  };

  return HashRouter;
}(compat_module["default"].Component);

HashRouter_HashRouter.propTypes = {
  basename: prop_types_default.a.string,
  getUserConfirmation: prop_types_default.a.func,
  hashType: prop_types_default.a.oneOf(["hashbang", "noslash", "slash"]),
  children: prop_types_default.a.node
};


/* harmony default export */ var es_HashRouter = (HashRouter_HashRouter);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/Link.js
var Link_extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

function _objectWithoutProperties(obj, keys) { var target = {}; for (var i in obj) { if (keys.indexOf(i) >= 0) continue; if (!Object.prototype.hasOwnProperty.call(obj, i)) continue; target[i] = obj[i]; } return target; }

function Link_classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function Link_possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function Link_inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }






var isModifiedEvent = function isModifiedEvent(event) {
  return !!(event.metaKey || event.altKey || event.ctrlKey || event.shiftKey);
};

/**
 * The public API for rendering a history-aware <a>.
 */

var Link_Link = function (_React$Component) {
  Link_inherits(Link, _React$Component);

  function Link() {
    var _temp, _this, _ret;

    Link_classCallCheck(this, Link);

    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    return _ret = (_temp = (_this = Link_possibleConstructorReturn(this, _React$Component.call.apply(_React$Component, [this].concat(args))), _this), _this.handleClick = function (event) {
      if (_this.props.onClick) _this.props.onClick(event);

      if (!event.defaultPrevented && // onClick prevented default
      event.button === 0 && // ignore everything but left clicks
      !_this.props.target && // let browser handle "target=_blank" etc.
      !isModifiedEvent(event) // ignore clicks with modifier keys
      ) {
          event.preventDefault();

          var history = _this.context.router.history;
          var _this$props = _this.props,
              replace = _this$props.replace,
              to = _this$props.to;


          if (replace) {
            history.replace(to);
          } else {
            history.push(to);
          }
        }
    }, _temp), Link_possibleConstructorReturn(_this, _ret);
  }

  Link.prototype.render = function render() {
    var _props = this.props,
        replace = _props.replace,
        to = _props.to,
        innerRef = _props.innerRef,
        props = _objectWithoutProperties(_props, ["replace", "to", "innerRef"]); // eslint-disable-line no-unused-vars

    browser_default()(this.context.router, "You should not use <Link> outside a <Router>");

    browser_default()(to !== undefined, 'You must specify the "to" property');

    var history = this.context.router.history;

    var location = typeof to === "string" ? createLocation(to, null, null, history.location) : to;

    var href = history.createHref(location);
    return compat_module["default"].createElement("a", Link_extends({}, props, { onClick: this.handleClick, href: href, ref: innerRef }));
  };

  return Link;
}(compat_module["default"].Component);

Link_Link.propTypes = {
  onClick: prop_types_default.a.func,
  target: prop_types_default.a.string,
  replace: prop_types_default.a.bool,
  to: prop_types_default.a.oneOfType([prop_types_default.a.string, prop_types_default.a.object]).isRequired,
  innerRef: prop_types_default.a.oneOfType([prop_types_default.a.string, prop_types_default.a.func])
};
Link_Link.defaultProps = {
  replace: false
};
Link_Link.contextTypes = {
  router: prop_types_default.a.shape({
    history: prop_types_default.a.shape({
      push: prop_types_default.a.func.isRequired,
      replace: prop_types_default.a.func.isRequired,
      createHref: prop_types_default.a.func.isRequired
    }).isRequired
  }).isRequired
};


/* harmony default export */ var es_Link = (Link_Link);
// CONCATENATED MODULE: ./node_modules/react-router/es/MemoryRouter.js
function MemoryRouter_classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function MemoryRouter_possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function MemoryRouter_inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }







/**
 * The public API for a <Router> that stores location in memory.
 */

var MemoryRouter_MemoryRouter = function (_React$Component) {
  MemoryRouter_inherits(MemoryRouter, _React$Component);

  function MemoryRouter() {
    var _temp, _this, _ret;

    MemoryRouter_classCallCheck(this, MemoryRouter);

    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    return _ret = (_temp = (_this = MemoryRouter_possibleConstructorReturn(this, _React$Component.call.apply(_React$Component, [this].concat(args))), _this), _this.history = createMemoryHistory(_this.props), _temp), MemoryRouter_possibleConstructorReturn(_this, _ret);
  }

  MemoryRouter.prototype.componentWillMount = function componentWillMount() {
    warning_default()(!this.props.history, "<MemoryRouter> ignores the history prop. To use a custom history, " + "use `import { Router }` instead of `import { MemoryRouter as Router }`.");
  };

  MemoryRouter.prototype.render = function render() {
    return compat_module["default"].createElement(es_Router, { history: this.history, children: this.props.children });
  };

  return MemoryRouter;
}(compat_module["default"].Component);

MemoryRouter_MemoryRouter.propTypes = {
  initialEntries: prop_types_default.a.array,
  initialIndex: prop_types_default.a.number,
  getUserConfirmation: prop_types_default.a.func,
  keyLength: prop_types_default.a.number,
  children: prop_types_default.a.node
};


/* harmony default export */ var es_MemoryRouter = (MemoryRouter_MemoryRouter);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/MemoryRouter.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_MemoryRouter = (es_MemoryRouter);
// EXTERNAL MODULE: ./node_modules/path-to-regexp/index.js
var path_to_regexp = __webpack_require__("./node_modules/path-to-regexp/index.js");
var path_to_regexp_default = /*#__PURE__*/__webpack_require__.n(path_to_regexp);

// CONCATENATED MODULE: ./node_modules/react-router/es/matchPath.js


var patternCache = {};
var cacheLimit = 10000;
var cacheCount = 0;

var matchPath_compilePath = function compilePath(pattern, options) {
  var cacheKey = "" + options.end + options.strict + options.sensitive;
  var cache = patternCache[cacheKey] || (patternCache[cacheKey] = {});

  if (cache[pattern]) return cache[pattern];

  var keys = [];
  var re = path_to_regexp_default()(pattern, keys, options);
  var compiledPattern = { re: re, keys: keys };

  if (cacheCount < cacheLimit) {
    cache[pattern] = compiledPattern;
    cacheCount++;
  }

  return compiledPattern;
};

/**
 * Public API for matching a URL pathname to a path pattern.
 */
var matchPath = function matchPath(pathname) {
  var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
  var parent = arguments[2];

  if (typeof options === "string") options = { path: options };

  var _options = options,
      path = _options.path,
      _options$exact = _options.exact,
      exact = _options$exact === undefined ? false : _options$exact,
      _options$strict = _options.strict,
      strict = _options$strict === undefined ? false : _options$strict,
      _options$sensitive = _options.sensitive,
      sensitive = _options$sensitive === undefined ? false : _options$sensitive;


  if (path == null) return parent;

  var _compilePath = matchPath_compilePath(path, { end: exact, strict: strict, sensitive: sensitive }),
      re = _compilePath.re,
      keys = _compilePath.keys;

  var match = re.exec(pathname);

  if (!match) return null;

  var url = match[0],
      values = match.slice(1);

  var isExact = pathname === url;

  if (exact && !isExact) return null;

  return {
    path: path, // the path pattern used to match
    url: path === "/" && url === "" ? "/" : url, // the matched portion of the URL
    isExact: isExact, // whether or not we matched exactly
    params: keys.reduce(function (memo, key, index) {
      memo[key.name] = values[index];
      return memo;
    }, {})
  };
};

/* harmony default export */ var es_matchPath = (matchPath);
// CONCATENATED MODULE: ./node_modules/react-router/es/Route.js
var Route_extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

function Route_classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function Route_possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function Route_inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }







var Route_isEmptyChildren = function isEmptyChildren(children) {
  return compat_module["default"].Children.count(children) === 0;
};

/**
 * The public API for matching a single path and rendering.
 */

var Route_Route = function (_React$Component) {
  Route_inherits(Route, _React$Component);

  function Route() {
    var _temp, _this, _ret;

    Route_classCallCheck(this, Route);

    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    return _ret = (_temp = (_this = Route_possibleConstructorReturn(this, _React$Component.call.apply(_React$Component, [this].concat(args))), _this), _this.state = {
      match: _this.computeMatch(_this.props, _this.context.router)
    }, _temp), Route_possibleConstructorReturn(_this, _ret);
  }

  Route.prototype.getChildContext = function getChildContext() {
    return {
      router: Route_extends({}, this.context.router, {
        route: {
          location: this.props.location || this.context.router.route.location,
          match: this.state.match
        }
      })
    };
  };

  Route.prototype.computeMatch = function computeMatch(_ref, router) {
    var computedMatch = _ref.computedMatch,
        location = _ref.location,
        path = _ref.path,
        strict = _ref.strict,
        exact = _ref.exact,
        sensitive = _ref.sensitive;

    if (computedMatch) return computedMatch; // <Switch> already computed the match for us

    browser_default()(router, "You should not use <Route> or withRouter() outside a <Router>");

    var route = router.route;

    var pathname = (location || route.location).pathname;

    return es_matchPath(pathname, { path: path, strict: strict, exact: exact, sensitive: sensitive }, route.match);
  };

  Route.prototype.componentWillMount = function componentWillMount() {
    warning_default()(!(this.props.component && this.props.render), "You should not use <Route component> and <Route render> in the same route; <Route render> will be ignored");

    warning_default()(!(this.props.component && this.props.children && !Route_isEmptyChildren(this.props.children)), "You should not use <Route component> and <Route children> in the same route; <Route children> will be ignored");

    warning_default()(!(this.props.render && this.props.children && !Route_isEmptyChildren(this.props.children)), "You should not use <Route render> and <Route children> in the same route; <Route children> will be ignored");
  };

  Route.prototype.componentWillReceiveProps = function componentWillReceiveProps(nextProps, nextContext) {
    warning_default()(!(nextProps.location && !this.props.location), '<Route> elements should not change from uncontrolled to controlled (or vice versa). You initially used no "location" prop and then provided one on a subsequent render.');

    warning_default()(!(!nextProps.location && this.props.location), '<Route> elements should not change from controlled to uncontrolled (or vice versa). You provided a "location" prop initially but omitted it on a subsequent render.');

    this.setState({
      match: this.computeMatch(nextProps, nextContext.router)
    });
  };

  Route.prototype.render = function render() {
    var match = this.state.match;
    var _props = this.props,
        children = _props.children,
        component = _props.component,
        render = _props.render;
    var _context$router = this.context.router,
        history = _context$router.history,
        route = _context$router.route,
        staticContext = _context$router.staticContext;

    var location = this.props.location || route.location;
    var props = { match: match, location: location, history: history, staticContext: staticContext };

    if (component) return match ? compat_module["default"].createElement(component, props) : null;

    if (render) return match ? render(props) : null;

    if (typeof children === "function") return children(props);

    if (children && !Route_isEmptyChildren(children)) return compat_module["default"].Children.only(children);

    return null;
  };

  return Route;
}(compat_module["default"].Component);

Route_Route.propTypes = {
  computedMatch: prop_types_default.a.object, // private, from <Switch>
  path: prop_types_default.a.string,
  exact: prop_types_default.a.bool,
  strict: prop_types_default.a.bool,
  sensitive: prop_types_default.a.bool,
  component: prop_types_default.a.func,
  render: prop_types_default.a.func,
  children: prop_types_default.a.oneOfType([prop_types_default.a.func, prop_types_default.a.node]),
  location: prop_types_default.a.object
};
Route_Route.contextTypes = {
  router: prop_types_default.a.shape({
    history: prop_types_default.a.object.isRequired,
    route: prop_types_default.a.object.isRequired,
    staticContext: prop_types_default.a.object
  })
};
Route_Route.childContextTypes = {
  router: prop_types_default.a.object.isRequired
};


/* harmony default export */ var es_Route = (Route_Route);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/Route.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_Route = (es_Route);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/NavLink.js
var NavLink_extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

var NavLink_typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

function NavLink_objectWithoutProperties(obj, keys) { var target = {}; for (var i in obj) { if (keys.indexOf(i) >= 0) continue; if (!Object.prototype.hasOwnProperty.call(obj, i)) continue; target[i] = obj[i]; } return target; }






/**
 * A <Link> wrapper that knows if it's "active" or not.
 */
var NavLink_NavLink = function NavLink(_ref) {
  var to = _ref.to,
      exact = _ref.exact,
      strict = _ref.strict,
      location = _ref.location,
      activeClassName = _ref.activeClassName,
      className = _ref.className,
      activeStyle = _ref.activeStyle,
      style = _ref.style,
      getIsActive = _ref.isActive,
      ariaCurrent = _ref["aria-current"],
      rest = NavLink_objectWithoutProperties(_ref, ["to", "exact", "strict", "location", "activeClassName", "className", "activeStyle", "style", "isActive", "aria-current"]);

  var path = (typeof to === "undefined" ? "undefined" : NavLink_typeof(to)) === "object" ? to.pathname : to;

  // Regex taken from: https://github.com/pillarjs/path-to-regexp/blob/master/index.js#L202
  var escapedPath = path && path.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");

  return compat_module["default"].createElement(react_router_dom_es_Route, {
    path: escapedPath,
    exact: exact,
    strict: strict,
    location: location,
    children: function children(_ref2) {
      var location = _ref2.location,
          match = _ref2.match;

      var isActive = !!(getIsActive ? getIsActive(match, location) : match);

      return compat_module["default"].createElement(es_Link, NavLink_extends({
        to: to,
        className: isActive ? [className, activeClassName].filter(function (i) {
          return i;
        }).join(" ") : className,
        style: isActive ? NavLink_extends({}, style, activeStyle) : style,
        "aria-current": isActive && ariaCurrent || null
      }, rest));
    }
  });
};

NavLink_NavLink.propTypes = {
  to: es_Link.propTypes.to,
  exact: prop_types_default.a.bool,
  strict: prop_types_default.a.bool,
  location: prop_types_default.a.object,
  activeClassName: prop_types_default.a.string,
  className: prop_types_default.a.string,
  activeStyle: prop_types_default.a.object,
  style: prop_types_default.a.object,
  isActive: prop_types_default.a.func,
  "aria-current": prop_types_default.a.oneOf(["page", "step", "location", "date", "time", "true"])
};

NavLink_NavLink.defaultProps = {
  activeClassName: "active",
  "aria-current": "page"
};

/* harmony default export */ var es_NavLink = (NavLink_NavLink);
// CONCATENATED MODULE: ./node_modules/react-router/es/Prompt.js
function Prompt_classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function Prompt_possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function Prompt_inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }





/**
 * The public API for prompting the user before navigating away
 * from a screen with a component.
 */

var Prompt_Prompt = function (_React$Component) {
  Prompt_inherits(Prompt, _React$Component);

  function Prompt() {
    Prompt_classCallCheck(this, Prompt);

    return Prompt_possibleConstructorReturn(this, _React$Component.apply(this, arguments));
  }

  Prompt.prototype.enable = function enable(message) {
    if (this.unblock) this.unblock();

    this.unblock = this.context.router.history.block(message);
  };

  Prompt.prototype.disable = function disable() {
    if (this.unblock) {
      this.unblock();
      this.unblock = null;
    }
  };

  Prompt.prototype.componentWillMount = function componentWillMount() {
    browser_default()(this.context.router, "You should not use <Prompt> outside a <Router>");

    if (this.props.when) this.enable(this.props.message);
  };

  Prompt.prototype.componentWillReceiveProps = function componentWillReceiveProps(nextProps) {
    if (nextProps.when) {
      if (!this.props.when || this.props.message !== nextProps.message) this.enable(nextProps.message);
    } else {
      this.disable();
    }
  };

  Prompt.prototype.componentWillUnmount = function componentWillUnmount() {
    this.disable();
  };

  Prompt.prototype.render = function render() {
    return null;
  };

  return Prompt;
}(compat_module["default"].Component);

Prompt_Prompt.propTypes = {
  when: prop_types_default.a.bool,
  message: prop_types_default.a.oneOfType([prop_types_default.a.func, prop_types_default.a.string]).isRequired
};
Prompt_Prompt.defaultProps = {
  when: true
};
Prompt_Prompt.contextTypes = {
  router: prop_types_default.a.shape({
    history: prop_types_default.a.shape({
      block: prop_types_default.a.func.isRequired
    }).isRequired
  }).isRequired
};


/* harmony default export */ var es_Prompt = (Prompt_Prompt);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/Prompt.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_Prompt = (es_Prompt);
// CONCATENATED MODULE: ./node_modules/react-router/es/generatePath.js


var generatePath_patternCache = {};
var generatePath_cacheLimit = 10000;
var generatePath_cacheCount = 0;

var generatePath_compileGenerator = function compileGenerator(pattern) {
  var cacheKey = pattern;
  var cache = generatePath_patternCache[cacheKey] || (generatePath_patternCache[cacheKey] = {});

  if (cache[pattern]) return cache[pattern];

  var compiledGenerator = path_to_regexp_default.a.compile(pattern);

  if (generatePath_cacheCount < generatePath_cacheLimit) {
    cache[pattern] = compiledGenerator;
    generatePath_cacheCount++;
  }

  return compiledGenerator;
};

/**
 * Public API for generating a URL pathname from a pattern and parameters.
 */
var generatePath = function generatePath() {
  var pattern = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "/";
  var params = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

  if (pattern === "/") {
    return pattern;
  }
  var generator = generatePath_compileGenerator(pattern);
  return generator(params, { pretty: true });
};

/* harmony default export */ var es_generatePath = (generatePath);
// CONCATENATED MODULE: ./node_modules/react-router/es/Redirect.js
var Redirect_extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

function Redirect_classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function Redirect_possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function Redirect_inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }








/**
 * The public API for updating the location programmatically
 * with a component.
 */

var Redirect_Redirect = function (_React$Component) {
  Redirect_inherits(Redirect, _React$Component);

  function Redirect() {
    Redirect_classCallCheck(this, Redirect);

    return Redirect_possibleConstructorReturn(this, _React$Component.apply(this, arguments));
  }

  Redirect.prototype.isStatic = function isStatic() {
    return this.context.router && this.context.router.staticContext;
  };

  Redirect.prototype.componentWillMount = function componentWillMount() {
    browser_default()(this.context.router, "You should not use <Redirect> outside a <Router>");

    if (this.isStatic()) this.perform();
  };

  Redirect.prototype.componentDidMount = function componentDidMount() {
    if (!this.isStatic()) this.perform();
  };

  Redirect.prototype.componentDidUpdate = function componentDidUpdate(prevProps) {
    var prevTo = createLocation(prevProps.to);
    var nextTo = createLocation(this.props.to);

    if (locationsAreEqual(prevTo, nextTo)) {
      warning_default()(false, "You tried to redirect to the same route you're currently on: " + ("\"" + nextTo.pathname + nextTo.search + "\""));
      return;
    }

    this.perform();
  };

  Redirect.prototype.computeTo = function computeTo(_ref) {
    var computedMatch = _ref.computedMatch,
        to = _ref.to;

    if (computedMatch) {
      if (typeof to === "string") {
        return es_generatePath(to, computedMatch.params);
      } else {
        return Redirect_extends({}, to, {
          pathname: es_generatePath(to.pathname, computedMatch.params)
        });
      }
    }

    return to;
  };

  Redirect.prototype.perform = function perform() {
    var history = this.context.router.history;
    var push = this.props.push;

    var to = this.computeTo(this.props);

    if (push) {
      history.push(to);
    } else {
      history.replace(to);
    }
  };

  Redirect.prototype.render = function render() {
    return null;
  };

  return Redirect;
}(compat_module["default"].Component);

Redirect_Redirect.propTypes = {
  computedMatch: prop_types_default.a.object, // private, from <Switch>
  push: prop_types_default.a.bool,
  from: prop_types_default.a.string,
  to: prop_types_default.a.oneOfType([prop_types_default.a.string, prop_types_default.a.object]).isRequired
};
Redirect_Redirect.defaultProps = {
  push: false
};
Redirect_Redirect.contextTypes = {
  router: prop_types_default.a.shape({
    history: prop_types_default.a.shape({
      push: prop_types_default.a.func.isRequired,
      replace: prop_types_default.a.func.isRequired
    }).isRequired,
    staticContext: prop_types_default.a.object
  }).isRequired
};


/* harmony default export */ var es_Redirect = (Redirect_Redirect);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/Redirect.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_Redirect = (es_Redirect);
// CONCATENATED MODULE: ./node_modules/react-router/es/StaticRouter.js
var StaticRouter_extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

function StaticRouter_objectWithoutProperties(obj, keys) { var target = {}; for (var i in obj) { if (keys.indexOf(i) >= 0) continue; if (!Object.prototype.hasOwnProperty.call(obj, i)) continue; target[i] = obj[i]; } return target; }

function StaticRouter_classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function StaticRouter_possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function StaticRouter_inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }








var StaticRouter_addLeadingSlash = function addLeadingSlash(path) {
  return path.charAt(0) === "/" ? path : "/" + path;
};

var addBasename = function addBasename(basename, location) {
  if (!basename) return location;

  return StaticRouter_extends({}, location, {
    pathname: StaticRouter_addLeadingSlash(basename) + location.pathname
  });
};

var StaticRouter_stripBasename = function stripBasename(basename, location) {
  if (!basename) return location;

  var base = StaticRouter_addLeadingSlash(basename);

  if (location.pathname.indexOf(base) !== 0) return location;

  return StaticRouter_extends({}, location, {
    pathname: location.pathname.substr(base.length)
  });
};

var StaticRouter_createURL = function createURL(location) {
  return typeof location === "string" ? location : createPath(location);
};

var StaticRouter_staticHandler = function staticHandler(methodName) {
  return function () {
    browser_default()(false, "You cannot %s with <StaticRouter>", methodName);
  };
};

var noop = function noop() {};

/**
 * The public top-level API for a "static" <Router>, so-called because it
 * can't actually change the current location. Instead, it just records
 * location changes in a context object. Useful mainly in testing and
 * server-rendering scenarios.
 */

var StaticRouter_StaticRouter = function (_React$Component) {
  StaticRouter_inherits(StaticRouter, _React$Component);

  function StaticRouter() {
    var _temp, _this, _ret;

    StaticRouter_classCallCheck(this, StaticRouter);

    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    return _ret = (_temp = (_this = StaticRouter_possibleConstructorReturn(this, _React$Component.call.apply(_React$Component, [this].concat(args))), _this), _this.createHref = function (path) {
      return StaticRouter_addLeadingSlash(_this.props.basename + StaticRouter_createURL(path));
    }, _this.handlePush = function (location) {
      var _this$props = _this.props,
          basename = _this$props.basename,
          context = _this$props.context;

      context.action = "PUSH";
      context.location = addBasename(basename, createLocation(location));
      context.url = StaticRouter_createURL(context.location);
    }, _this.handleReplace = function (location) {
      var _this$props2 = _this.props,
          basename = _this$props2.basename,
          context = _this$props2.context;

      context.action = "REPLACE";
      context.location = addBasename(basename, createLocation(location));
      context.url = StaticRouter_createURL(context.location);
    }, _this.handleListen = function () {
      return noop;
    }, _this.handleBlock = function () {
      return noop;
    }, _temp), StaticRouter_possibleConstructorReturn(_this, _ret);
  }

  StaticRouter.prototype.getChildContext = function getChildContext() {
    return {
      router: {
        staticContext: this.props.context
      }
    };
  };

  StaticRouter.prototype.componentWillMount = function componentWillMount() {
    warning_default()(!this.props.history, "<StaticRouter> ignores the history prop. To use a custom history, " + "use `import { Router }` instead of `import { StaticRouter as Router }`.");
  };

  StaticRouter.prototype.render = function render() {
    var _props = this.props,
        basename = _props.basename,
        context = _props.context,
        location = _props.location,
        props = StaticRouter_objectWithoutProperties(_props, ["basename", "context", "location"]);

    var history = {
      createHref: this.createHref,
      action: "POP",
      location: StaticRouter_stripBasename(basename, createLocation(location)),
      push: this.handlePush,
      replace: this.handleReplace,
      go: StaticRouter_staticHandler("go"),
      goBack: StaticRouter_staticHandler("goBack"),
      goForward: StaticRouter_staticHandler("goForward"),
      listen: this.handleListen,
      block: this.handleBlock
    };

    return compat_module["default"].createElement(es_Router, StaticRouter_extends({}, props, { history: history }));
  };

  return StaticRouter;
}(compat_module["default"].Component);

StaticRouter_StaticRouter.propTypes = {
  basename: prop_types_default.a.string,
  context: prop_types_default.a.object.isRequired,
  location: prop_types_default.a.oneOfType([prop_types_default.a.string, prop_types_default.a.object])
};
StaticRouter_StaticRouter.defaultProps = {
  basename: "",
  location: "/"
};
StaticRouter_StaticRouter.childContextTypes = {
  router: prop_types_default.a.object.isRequired
};


/* harmony default export */ var es_StaticRouter = (StaticRouter_StaticRouter);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/StaticRouter.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_StaticRouter = (es_StaticRouter);
// CONCATENATED MODULE: ./node_modules/react-router/es/Switch.js
function Switch_classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function Switch_possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function Switch_inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }







/**
 * The public API for rendering the first <Route> that matches.
 */

var Switch_Switch = function (_React$Component) {
  Switch_inherits(Switch, _React$Component);

  function Switch() {
    Switch_classCallCheck(this, Switch);

    return Switch_possibleConstructorReturn(this, _React$Component.apply(this, arguments));
  }

  Switch.prototype.componentWillMount = function componentWillMount() {
    browser_default()(this.context.router, "You should not use <Switch> outside a <Router>");
  };

  Switch.prototype.componentWillReceiveProps = function componentWillReceiveProps(nextProps) {
    warning_default()(!(nextProps.location && !this.props.location), '<Switch> elements should not change from uncontrolled to controlled (or vice versa). You initially used no "location" prop and then provided one on a subsequent render.');

    warning_default()(!(!nextProps.location && this.props.location), '<Switch> elements should not change from controlled to uncontrolled (or vice versa). You provided a "location" prop initially but omitted it on a subsequent render.');
  };

  Switch.prototype.render = function render() {
    var route = this.context.router.route;
    var children = this.props.children;

    var location = this.props.location || route.location;

    var match = void 0,
        child = void 0;
    compat_module["default"].Children.forEach(children, function (element) {
      if (match == null && compat_module["default"].isValidElement(element)) {
        var _element$props = element.props,
            pathProp = _element$props.path,
            exact = _element$props.exact,
            strict = _element$props.strict,
            sensitive = _element$props.sensitive,
            from = _element$props.from;

        var path = pathProp || from;

        child = element;
        match = es_matchPath(location.pathname, { path: path, exact: exact, strict: strict, sensitive: sensitive }, route.match);
      }
    });

    return match ? compat_module["default"].cloneElement(child, { location: location, computedMatch: match }) : null;
  };

  return Switch;
}(compat_module["default"].Component);

Switch_Switch.contextTypes = {
  router: prop_types_default.a.shape({
    route: prop_types_default.a.object.isRequired
  }).isRequired
};
Switch_Switch.propTypes = {
  children: prop_types_default.a.node,
  location: prop_types_default.a.object
};


/* harmony default export */ var es_Switch = (Switch_Switch);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/Switch.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_Switch = (es_Switch);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/generatePath.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_generatePath = (es_generatePath);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/matchPath.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_matchPath = (es_matchPath);
// EXTERNAL MODULE: ./node_modules/react-router/node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js
var hoist_non_react_statics_cjs = __webpack_require__("./node_modules/react-router/node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js");
var hoist_non_react_statics_cjs_default = /*#__PURE__*/__webpack_require__.n(hoist_non_react_statics_cjs);

// CONCATENATED MODULE: ./node_modules/react-router/es/withRouter.js
var withRouter_extends = Object.assign || function (target) { for (var i = 1; i < arguments.length; i++) { var source = arguments[i]; for (var key in source) { if (Object.prototype.hasOwnProperty.call(source, key)) { target[key] = source[key]; } } } return target; };

function withRouter_objectWithoutProperties(obj, keys) { var target = {}; for (var i in obj) { if (keys.indexOf(i) >= 0) continue; if (!Object.prototype.hasOwnProperty.call(obj, i)) continue; target[i] = obj[i]; } return target; }






/**
 * A public higher-order component to access the imperative API
 */
var withRouter_withRouter = function withRouter(Component) {
  var C = function C(props) {
    var wrappedComponentRef = props.wrappedComponentRef,
        remainingProps = withRouter_objectWithoutProperties(props, ["wrappedComponentRef"]);

    return compat_module["default"].createElement(es_Route, {
      children: function children(routeComponentProps) {
        return compat_module["default"].createElement(Component, withRouter_extends({}, remainingProps, routeComponentProps, {
          ref: wrappedComponentRef
        }));
      }
    });
  };

  C.displayName = "withRouter(" + (Component.displayName || Component.name) + ")";
  C.WrappedComponent = Component;
  C.propTypes = {
    wrappedComponentRef: prop_types_default.a.func
  };

  return hoist_non_react_statics_cjs_default()(C, Component);
};

/* harmony default export */ var es_withRouter = (withRouter_withRouter);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/withRouter.js
// Written in this round about way for babel-transform-imports


/* harmony default export */ var react_router_dom_es_withRouter = (es_withRouter);
// CONCATENATED MODULE: ./node_modules/react-router-dom/es/index.js
/* concated harmony reexport BrowserRouter */__webpack_require__.d(__webpack_exports__, "BrowserRouter", function() { return es_BrowserRouter; });
/* concated harmony reexport HashRouter */__webpack_require__.d(__webpack_exports__, "HashRouter", function() { return es_HashRouter; });
/* concated harmony reexport Link */__webpack_require__.d(__webpack_exports__, "Link", function() { return es_Link; });
/* concated harmony reexport MemoryRouter */__webpack_require__.d(__webpack_exports__, "MemoryRouter", function() { return react_router_dom_es_MemoryRouter; });
/* concated harmony reexport NavLink */__webpack_require__.d(__webpack_exports__, "NavLink", function() { return es_NavLink; });
/* concated harmony reexport Prompt */__webpack_require__.d(__webpack_exports__, "Prompt", function() { return react_router_dom_es_Prompt; });
/* concated harmony reexport Redirect */__webpack_require__.d(__webpack_exports__, "Redirect", function() { return react_router_dom_es_Redirect; });
/* concated harmony reexport Route */__webpack_require__.d(__webpack_exports__, "Route", function() { return react_router_dom_es_Route; });
/* concated harmony reexport Router */__webpack_require__.d(__webpack_exports__, "Router", function() { return react_router_dom_es_Router; });
/* concated harmony reexport StaticRouter */__webpack_require__.d(__webpack_exports__, "StaticRouter", function() { return react_router_dom_es_StaticRouter; });
/* concated harmony reexport Switch */__webpack_require__.d(__webpack_exports__, "Switch", function() { return react_router_dom_es_Switch; });
/* concated harmony reexport generatePath */__webpack_require__.d(__webpack_exports__, "generatePath", function() { return react_router_dom_es_generatePath; });
/* concated harmony reexport matchPath */__webpack_require__.d(__webpack_exports__, "matchPath", function() { return react_router_dom_es_matchPath; });
/* concated harmony reexport withRouter */__webpack_require__.d(__webpack_exports__, "withRouter", function() { return react_router_dom_es_withRouter; });





























/***/ }),

/***/ "./node_modules/react-router/node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js":
/*!************************************************************************************************************!*\
  !*** ./node_modules/react-router/node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js ***!
  \************************************************************************************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Copyright 2015, Yahoo! Inc.
 * Copyrights licensed under the New BSD License. See the accompanying LICENSE file for terms.
 */
var REACT_STATICS = {
    childContextTypes: true,
    contextTypes: true,
    defaultProps: true,
    displayName: true,
    getDefaultProps: true,
    getDerivedStateFromProps: true,
    mixins: true,
    propTypes: true,
    type: true
};

var KNOWN_STATICS = {
    name: true,
    length: true,
    prototype: true,
    caller: true,
    callee: true,
    arguments: true,
    arity: true
};

var defineProperty = Object.defineProperty;
var getOwnPropertyNames = Object.getOwnPropertyNames;
var getOwnPropertySymbols = Object.getOwnPropertySymbols;
var getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
var getPrototypeOf = Object.getPrototypeOf;
var objectPrototype = getPrototypeOf && getPrototypeOf(Object);

function hoistNonReactStatics(targetComponent, sourceComponent, blacklist) {
    if (typeof sourceComponent !== 'string') { // don't hoist over string (html) components

        if (objectPrototype) {
            var inheritedComponent = getPrototypeOf(sourceComponent);
            if (inheritedComponent && inheritedComponent !== objectPrototype) {
                hoistNonReactStatics(targetComponent, inheritedComponent, blacklist);
            }
        }

        var keys = getOwnPropertyNames(sourceComponent);

        if (getOwnPropertySymbols) {
            keys = keys.concat(getOwnPropertySymbols(sourceComponent));
        }

        for (var i = 0; i < keys.length; ++i) {
            var key = keys[i];
            if (!REACT_STATICS[key] && !KNOWN_STATICS[key] && (!blacklist || !blacklist[key])) {
                var descriptor = getOwnPropertyDescriptor(sourceComponent, key);
                try { // Avoid failures from read-only properties
                    defineProperty(targetComponent, key, descriptor);
                } catch (e) {}
            }
        }

        return targetComponent;
    }

    return targetComponent;
}

module.exports = hoistNonReactStatics;


/***/ }),

/***/ "./node_modules/warning/warning.js":
/*!*****************************************!*\
  !*** ./node_modules/warning/warning.js ***!
  \*****************************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/**
 * Copyright (c) 2014-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */



/**
 * Similar to invariant but only logs a warning if the condition is not met.
 * This can be used to log issues in development environments in critical
 * paths. Removing the logging code for production environments will keep the
 * same logic and follow the same code paths.
 */

var __DEV__ = "production" !== 'production';

var warning = function() {};

if (__DEV__) {
  var printWarning = function printWarning(format, args) {
    var len = arguments.length;
    args = new Array(len > 1 ? len - 1 : 0);
    for (var key = 1; key < len; key++) {
      args[key - 1] = arguments[key];
    }
    var argIndex = 0;
    var message = 'Warning: ' +
      format.replace(/%s/g, function() {
        return args[argIndex++];
      });
    if (typeof console !== 'undefined') {
      console.error(message);
    }
    try {
      // --- Welcome to debugging React ---
      // This error was thrown as a convenience so that you can use this stack
      // to find the callsite that caused this warning to fire.
      throw new Error(message);
    } catch (x) {}
  }

  warning = function(condition, format, args) {
    var len = arguments.length;
    args = new Array(len > 2 ? len - 2 : 0);
    for (var key = 2; key < len; key++) {
      args[key - 2] = arguments[key];
    }
    if (format === undefined) {
      throw new Error(
          '`warning(condition, format, ...args)` requires a warning ' +
          'message argument'
      );
    }
    if (!condition) {
      printWarning.apply(null, [format].concat(args));
    }
  };
}

module.exports = warning;


/***/ }),

/***/ "./src/index.js":
/*!**********************************!*\
  !*** ./src/index.js + 5 modules ***!
  \**********************************/
/*! no exports provided */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/@babel/runtime/helpers/esm/extends.js because of ./src/Components/Blog/postPage.js */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js (<- Module is not an ECMAScript module) */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/preact/compat/dist/compat.module.js because of ./src/Components/Blog/postPage.js */
/*! ModuleConcatenation bailout: Cannot concat with ./node_modules/react-router-dom/es/index.js because of ./src/Components/Blog/postPage.js */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);

// EXTERNAL MODULE: ./node_modules/preact/compat/dist/compat.module.js + 2 modules
var compat_module = __webpack_require__("./node_modules/preact/compat/dist/compat.module.js");

// EXTERNAL MODULE: ./node_modules/react-router-dom/es/index.js + 29 modules
var es = __webpack_require__("./node_modules/react-router-dom/es/index.js");

// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/objectWithoutPropertiesLoose.js
function _objectWithoutPropertiesLoose(source, excluded) {
  if (source == null) return {};
  var target = {};
  var sourceKeys = Object.keys(source);
  var key, i;

  for (i = 0; i < sourceKeys.length; i++) {
    key = sourceKeys[i];
    if (excluded.indexOf(key) >= 0) continue;
    target[key] = source[key];
  }

  return target;
}
// EXTERNAL MODULE: ./node_modules/@babel/runtime/helpers/esm/extends.js
var esm_extends = __webpack_require__("./node_modules/@babel/runtime/helpers/esm/extends.js");

// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/assertThisInitialized.js
function _assertThisInitialized(self) {
  if (self === void 0) {
    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
  }

  return self;
}
// CONCATENATED MODULE: ./node_modules/@babel/runtime/helpers/esm/inheritsLoose.js
function _inheritsLoose(subClass, superClass) {
  subClass.prototype = Object.create(superClass.prototype);
  subClass.prototype.constructor = subClass;
  subClass.__proto__ = superClass;
}
// EXTERNAL MODULE: ./node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js
var hoist_non_react_statics_cjs = __webpack_require__("./node_modules/hoist-non-react-statics/dist/hoist-non-react-statics.cjs.js");
var hoist_non_react_statics_cjs_default = /*#__PURE__*/__webpack_require__.n(hoist_non_react_statics_cjs);

// CONCATENATED MODULE: ./node_modules/@loadable/component/dist/loadable.esm.js







/* eslint-disable import/prefer-default-export */
function invariant(condition, message) {
  if (condition) return;
  var error = new Error("loadable: " + message);
  error.framesToPop = 1;
  error.name = 'Invariant Violation';
  throw error;
}
function warn(message) {
  // eslint-disable-next-line no-console
  console.warn("loadable: " + message);
}

var Context = /*#__PURE__*/
compat_module["default"].createContext();

var LOADABLE_REQUIRED_CHUNKS_KEY = '__LOADABLE_REQUIRED_CHUNKS__';
function getRequiredChunkKey(namespace) {
  return "" + namespace + LOADABLE_REQUIRED_CHUNKS_KEY;
}

var sharedInternals = /*#__PURE__*/Object.freeze({
  getRequiredChunkKey: getRequiredChunkKey,
  invariant: invariant,
  Context: Context
});

function resolveConstructor(ctor) {
  if (typeof ctor === 'function') {
    return {
      requireAsync: ctor
    };
  }

  return ctor;
}

var loadable_esm_withChunkExtractor = function withChunkExtractor(Component) {
  return function (props) {
    return compat_module["default"].createElement(Context.Consumer, null, function (extractor) {
      return compat_module["default"].createElement(Component, Object.assign({
        __chunkExtractor: extractor
      }, props));
    });
  };
};

var identity = function identity(v) {
  return v;
};

function createLoadable(_ref) {
  var _ref$resolve = _ref.resolve,
      resolve = _ref$resolve === void 0 ? identity : _ref$resolve,
      _render = _ref.render,
      onLoad = _ref.onLoad;

  function loadable(loadableConstructor, options) {
    if (options === void 0) {
      options = {};
    }

    var ctor = resolveConstructor(loadableConstructor);
    var cache = {};

    function _getCacheKey(props) {
      if (options.cacheKey) {
        return options.cacheKey(props);
      }

      if (ctor.resolve) {
        return ctor.resolve(props);
      }

      return null;
    }

    var InnerLoadable =
    /*#__PURE__*/
    function (_React$Component) {
      _inheritsLoose(InnerLoadable, _React$Component);

      InnerLoadable.getDerivedStateFromProps = function getDerivedStateFromProps(props, state) {
        var cacheKey = _getCacheKey(props);

        return Object(esm_extends["default"])({}, state, {
          cacheKey: cacheKey,
          loading: state.loading || state.cacheKey !== cacheKey
        });
      };

      function InnerLoadable(props) {
        var _this;

        _this = _React$Component.call(this, props) || this;
        _this.state = {
          result: null,
          error: null,
          loading: true,
          cacheKey: _getCacheKey(props)
        };
        _this.promise = null;
        invariant(!props.__chunkExtractor || ctor.requireSync, 'SSR requires `@loadable/babel-plugin`, please install it'); // Server-side

        if (props.__chunkExtractor) {
          // This module has been marked with no SSR
          if (options.ssr === false) {
            return _assertThisInitialized(_this);
          } // We run load function, we assume that it won't fail and that it
          // triggers a synchronous loading of the module


          ctor.requireAsync(props)["catch"](function () {}); // So we can require now the module synchronously

          _this.loadSync();

          props.__chunkExtractor.addChunk(ctor.chunkName(props));

          return _assertThisInitialized(_this);
        } // Client-side with `isReady` method present (SSR probably)
        // If module is already loaded, we use a synchronous loading


        if (ctor.isReady && ctor.isReady(props)) {
          _this.loadSync();
        }

        return _this;
      }

      var _proto = InnerLoadable.prototype;

      _proto.componentDidMount = function componentDidMount() {
        this.mounted = true;

        if (this.state.loading) {
          this.loadAsync();
        } else if (!this.state.error) {
          this.triggerOnLoad();
        }
      };

      _proto.componentDidUpdate = function componentDidUpdate(prevProps, prevState) {
        // Component is reloaded if the cacheKey has changed
        if (!Object.is(prevState.cacheKey, this.state.cacheKey)) {
          this.promise = null;
          this.loadAsync();
        }
      };

      _proto.componentWillUnmount = function componentWillUnmount() {
        this.mounted = false;
      };

      _proto.safeSetState = function safeSetState(nextState, callback) {
        if (this.mounted) {
          this.setState(nextState, callback);
        }
      };

      _proto.triggerOnLoad = function triggerOnLoad() {
        var _this2 = this;

        if (onLoad) {
          setTimeout(function () {
            onLoad(_this2.state.result, _this2.props);
          });
        }
      };

      _proto.loadSync = function loadSync() {
        if (!this.state.loading) return;

        try {
          var loadedModule = ctor.requireSync(this.props);
          var result = resolve(loadedModule, {
            Loadable: Loadable
          });
          this.state.result = result;
          this.state.loading = false;
        } catch (error) {
          this.state.error = error;
        }
      };

      _proto.getCacheKey = function getCacheKey() {
        return _getCacheKey(this.props) || JSON.stringify(this.props);
      };

      _proto.getCache = function getCache() {
        return cache[this.getCacheKey()];
      };

      _proto.setCache = function setCache(value) {
        cache[this.getCacheKey()] = value;
      };

      _proto.loadAsync = function loadAsync() {
        var _this3 = this;

        if (!this.promise) {
          var _this$props = this.props,
              __chunkExtractor = _this$props.__chunkExtractor,
              forwardedRef = _this$props.forwardedRef,
              props = _objectWithoutPropertiesLoose(_this$props, ["__chunkExtractor", "forwardedRef"]);

          this.promise = ctor.requireAsync(props).then(function (loadedModule) {
            var result = resolve(loadedModule, {
              Loadable: Loadable
            });

            if (options.suspense) {
              _this3.setCache(result);
            }

            _this3.safeSetState({
              result: resolve(loadedModule, {
                Loadable: Loadable
              }),
              loading: false
            }, function () {
              return _this3.triggerOnLoad();
            });
          })["catch"](function (error) {
            _this3.safeSetState({
              error: error,
              loading: false
            });
          });
        }

        return this.promise;
      };

      _proto.render = function render() {
        var _this$props2 = this.props,
            forwardedRef = _this$props2.forwardedRef,
            propFallback = _this$props2.fallback,
            __chunkExtractor = _this$props2.__chunkExtractor,
            props = _objectWithoutPropertiesLoose(_this$props2, ["forwardedRef", "fallback", "__chunkExtractor"]);

        var _this$state = this.state,
            error = _this$state.error,
            loading = _this$state.loading,
            result = _this$state.result;

        if (options.suspense) {
          var cachedResult = this.getCache();
          if (!cachedResult) throw this.loadAsync();
          return _render({
            loading: false,
            fallback: null,
            result: cachedResult,
            options: options,
            props: Object(esm_extends["default"])({}, props, {
              ref: forwardedRef
            })
          });
        }

        if (error) {
          throw error;
        }

        var fallback = propFallback || options.fallback || null;

        if (loading) {
          return fallback;
        }

        return _render({
          loading: loading,
          fallback: fallback,
          result: result,
          options: options,
          props: Object(esm_extends["default"])({}, props, {
            ref: forwardedRef
          })
        });
      };

      return InnerLoadable;
    }(compat_module["default"].Component);

    var EnhancedInnerLoadable = loadable_esm_withChunkExtractor(InnerLoadable);
    var Loadable = compat_module["default"].forwardRef(function (props, ref) {
      return compat_module["default"].createElement(EnhancedInnerLoadable, Object.assign({
        forwardedRef: ref
      }, props));
    }); // In future, preload could use `<link rel="preload">`

    Loadable.preload = function (props) {
      ctor.requireAsync(props);
    };

    Loadable.load = function (props) {
      return ctor.requireAsync(props);
    };

    return Loadable;
  }

  function lazy(ctor, options) {
    return loadable(ctor, Object(esm_extends["default"])({}, options, {
      suspense: true
    }));
  }

  return {
    loadable: loadable,
    lazy: lazy
  };
}

function resolveComponent(loadedModule, _ref) {
  var Loadable = _ref.Loadable;
  // eslint-disable-next-line no-underscore-dangle
  var Component = loadedModule.__esModule ? loadedModule["default"] : loadedModule["default"] || loadedModule;
  hoist_non_react_statics_cjs_default()(Loadable, Component, {
    preload: true
  });
  return Component;
}

/* eslint-disable no-use-before-define, react/no-multi-comp */

var _createLoadable =
/*#__PURE__*/
createLoadable({
  resolve: resolveComponent,
  render: function render(_ref) {
    var Component = _ref.result,
        props = _ref.props;
    return compat_module["default"].createElement(Component, props);
  }
}),
    loadable_esm_loadable = _createLoadable.loadable,
    loadable_esm_lazy = _createLoadable.lazy;

/* eslint-disable no-use-before-define, react/no-multi-comp */

var _createLoadable$1 =
/*#__PURE__*/
createLoadable({
  onLoad: function onLoad(result, props) {
    if (result && props.forwardedRef) {
      if (typeof props.forwardedRef === 'function') {
        props.forwardedRef(result);
      } else {
        props.forwardedRef.current = result;
      }
    }
  },
  render: function render(_ref) {
    var result = _ref.result,
        loading = _ref.loading,
        props = _ref.props;

    if (!loading && props.children) {
      return props.children(result);
    }

    return null;
  }
}),
    loadable$1 = _createLoadable$1.loadable,
    lazy$1 = _createLoadable$1.lazy;

/* eslint-disable no-underscore-dangle, camelcase */
var BROWSER = typeof window !== 'undefined';
function loadableReady(done, _temp) {
  if (done === void 0) {
    done = function done() {};
  }

  var _ref = _temp === void 0 ? {} : _temp,
      _ref$namespace = _ref.namespace,
      namespace = _ref$namespace === void 0 ? '' : _ref$namespace;

  if (!BROWSER) {
    warn('`loadableReady()` must be called in browser only');
    done();
    return Promise.resolve();
  }

  var requiredChunks = null;

  if (BROWSER) {
    var dataElement = document.getElementById(getRequiredChunkKey(namespace));

    if (dataElement) {
      requiredChunks = JSON.parse(dataElement.textContent);
    }
  }

  if (!requiredChunks) {
    warn('`loadableReady()` requires state, please use `getScriptTags` or `getScriptElements` server-side');
    done();
    return Promise.resolve();
  }

  var resolved = false;
  return new Promise(function (resolve) {
    window.__LOADABLE_LOADED_CHUNKS__ = window.__LOADABLE_LOADED_CHUNKS__ || [];
    var loadedChunks = window.__LOADABLE_LOADED_CHUNKS__;
    var originalPush = loadedChunks.push.bind(loadedChunks);

    function checkReadyState() {
      if (requiredChunks.every(function (chunk) {
        return loadedChunks.some(function (_ref2) {
          var chunks = _ref2[0];
          return chunks.includes(chunk);
        });
      })) {
        if (!resolved) {
          resolved = true;
          resolve();
          done();
        }
      }
    }

    loadedChunks.push = function () {
      originalPush.apply(void 0, arguments);
      checkReadyState();
    };

    checkReadyState();
  });
}

/* eslint-disable no-underscore-dangle */
var loadable$2 = loadable_esm_loadable;
loadable$2.lib = loadable$1;
var lazy$2 = loadable_esm_lazy;
lazy$2.lib = lazy$1;
var __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = sharedInternals;

/* harmony default export */ var loadable_esm = (loadable$2);


// CONCATENATED MODULE: ./src/app.js



var Home = loadable_esm(function () {
  return __webpack_require__.e(/*! import() */ 4).then(__webpack_require__.bind(null, /*! ./Components/Home */ "./src/Components/Home/index.js"));
});
var Blog = loadable_esm(function () {
  return Promise.all(/*! import() */[__webpack_require__.e(0), __webpack_require__.e(3)]).then(__webpack_require__.bind(null, /*! ./Components/Blog */ "./src/Components/Blog/index.js"));
});
var PostPage = loadable_esm(function () {
  return Promise.all(/*! import() */[__webpack_require__.e(0), __webpack_require__.e(1), __webpack_require__.e(2)]).then(__webpack_require__.bind(null, /*! ./Components/Blog/postPage */ "./src/Components/Blog/postPage.js"));
}); // import Home from './Components/Home'
// import Blog from './Components/Blog'
// import PostPage from './Components/Blog/postPage'

var app_App = function App() {
  return compat_module["default"].createElement(es["HashRouter"], null, compat_module["default"].createElement("div", {
    className: "app-wrapper"
  }, compat_module["default"].createElement(es["Route"], {
    exact: true,
    path: "/",
    component: Home
  }), compat_module["default"].createElement(es["Route"], {
    exact: true,
    path: "/blog",
    component: Blog
  }), compat_module["default"].createElement(es["Route"], {
    path: "/blog/:slug",
    component: PostPage
  }), compat_module["default"].createElement(es["Route"], {
    path: "/portfolio",
    component: Home
  })));
};

/* harmony default export */ var app = (app_App);
// CONCATENATED MODULE: ./src/index.js



__webpack_require__(/*! ./styles/main.sass */ "./src/styles/main.sass");


Object(compat_module["render"])(compat_module["default"].createElement(app, null), document.getElementById('app'));

/***/ }),

/***/ "./src/styles/main.sass":
/*!******************************!*\
  !*** ./src/styles/main.sass ***!
  \******************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports, __webpack_require__) {

// extracted by mini-css-extract-plugin

/***/ })

/******/ });