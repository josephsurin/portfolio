(window["webpackJsonp"] = window["webpackJsonp"] || []).push([[3],{

/***/ "./src/Components/Blog/index.js":
/*!**************************************!*\
  !*** ./src/Components/Blog/index.js ***!
  \**************************************/
/*! exports provided: default */
/*! ModuleConcatenation bailout: Module is referenced from these modules with unsupported syntax: ./src/app.js (referenced with import()) */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function() { return Blog; });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "./node_modules/preact/compat/dist/compat.module.js");
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../../util */ "./src/util/index.js");
/* harmony import */ var _tags__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./tags */ "./src/Components/Blog/tags.js");
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./util */ "./src/Components/Blog/util.js");
function _typeof(obj) { if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

function _possibleConstructorReturn(self, call) { if (call && (_typeof(call) === "object" || typeof call === "function")) { return call; } return _assertThisInitialized(self); }

function _getPrototypeOf(o) { _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf : function _getPrototypeOf(o) { return o.__proto__ || Object.getPrototypeOf(o); }; return _getPrototypeOf(o); }

function _assertThisInitialized(self) { if (self === void 0) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function"); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, writable: true, configurable: true } }); if (superClass) _setPrototypeOf(subClass, superClass); }

function _setPrototypeOf(o, p) { _setPrototypeOf = Object.setPrototypeOf || function _setPrototypeOf(o, p) { o.__proto__ = p; return o; }; return _setPrototypeOf(o, p); }





var posts = __webpack_require__(/*! ../../posts */ "./src/posts/index.js");



var Blog =
/*#__PURE__*/
function (_Component) {
  _inherits(Blog, _Component);

  function Blog(props) {
    var _this;

    _classCallCheck(this, Blog);

    _this = _possibleConstructorReturn(this, _getPrototypeOf(Blog).call(this, props));
    _this.state = {
      posts: posts,
      progressPercent: 0
    };
    _this.readyPostPage = _this.readyPostPage.bind(_assertThisInitialized(_this));
    return _this;
  }

  _createClass(Blog, [{
    key: "render",
    value: function render() {
      var _this2 = this;

      var _this$state = this.state,
          posts = _this$state.posts,
          progressPercent = _this$state.progressPercent;
      return react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
        className: "blog-container"
      }, react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
        className: "progress-loader",
        style: {
          width: "".concat(progressPercent, "%")
        }
      }), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
        className: "blog-header"
      }, "Personal blog by Joseph Surin"), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
        className: "blog-subtitle"
      }, "I put stuff about school, my thoughts and my projects here."), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
        className: "posts"
      }, posts.map(function (post) {
        var title = post.title,
            slug = post.slug,
            date = post.date,
            spoiler = post.spoiler,
            tags = post.tags;
        return react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
          key: title,
          className: "post"
        }, react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
          className: "post-title",
          onClick: function onClick() {
            return _this2.readyPostPage(slug);
          }
        }, title), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
          className: "post-date"
        }, Object(_util__WEBPACK_IMPORTED_MODULE_1__["formatDate"])(date)), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
          className: "post-spoiler"
        }, spoiler), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_tags__WEBPACK_IMPORTED_MODULE_2__["default"], {
          tags: tags
        }));
      })));
    }
  }, {
    key: "readyPostPage",
    value: function readyPostPage(slug) {
      var _this3 = this;

      this.setState({
        progressPercent: 80
      });
      Object(_util__WEBPACK_IMPORTED_MODULE_3__["fetchPostData"])(slug).then(function (postPageProps) {
        _this3.setState({
          progressPercent: 100
        });

        _util__WEBPACK_IMPORTED_MODULE_3__["simpleStore"].set('postPageProps', postPageProps);
        setTimeout(function () {
          _this3.props.history.push("blog/".concat(slug));
        }, 100);
      });
    }
  }]);

  return Blog;
}(react__WEBPACK_IMPORTED_MODULE_0__["Component"]);



/***/ }),

/***/ "./src/Components/Blog/tags.js":
/*!*************************************!*\
  !*** ./src/Components/Blog/tags.js ***!
  \*************************************/
/*! exports provided: default */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "./node_modules/preact/compat/dist/compat.module.js");


var Tags = function Tags(_ref) {
  var tags = _ref.tags;
  return react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
    className: "post-tags"
  }, tags.split(',').map(function (tag) {
    return react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
      key: tag,
      className: "post-tag"
    }, tag);
  }));
};

/* harmony default export */ __webpack_exports__["default"] = (Tags);

/***/ }),

/***/ "./src/Components/Blog/util.js":
/*!*************************************!*\
  !*** ./src/Components/Blog/util.js ***!
  \*************************************/
/*! exports provided: simpleStore, fetchPostData */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "simpleStore", function() { return simpleStore; });
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "fetchPostData", function() { return fetchPostData; });
function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

/* SIMPLE STORE */
var SimpleStore =
/*#__PURE__*/
function () {
  function SimpleStore() {
    _classCallCheck(this, SimpleStore);

    this.state = {};
  }

  _createClass(SimpleStore, [{
    key: "set",
    value: function set(k, v) {
      this.state[k] = v;
    }
  }, {
    key: "get",
    value: function get(k) {
      return this.state[k];
    }
  }]);

  return SimpleStore;
}();

var simpleStore = new SimpleStore();
/* FETCH POST DATA */

var postsBuildDir = 'posts/';

var frontmatter = __webpack_require__(/*! front-matter */ "./node_modules/front-matter/index.js");

function fetchPostData(slug) {
  return new Promise(function (resolve, reject) {
    var postFilepath = "".concat(postsBuildDir).concat(slug, ".md");
    fetch(postFilepath).then(function (x) {
      return x.text();
    }).then(function (rawMD) {
      var _frontmatter = frontmatter(rawMD),
          attributes = _frontmatter.attributes,
          body = _frontmatter.body;

      var postPageProps = {
        postMeta: attributes,
        postBody: body
      };
      return resolve(postPageProps);
    })["catch"](reject);
  });
}

/***/ }),

/***/ "./src/posts/index.js":
/*!****************************!*\
  !*** ./src/posts/index.js ***!
  \****************************/
/*! no static exports found */
/*! ModuleConcatenation bailout: Module is not an ECMAScript module */
/***/ (function(module, exports) {

module.exports = [{
  title: 'ISITDTU 2019 Quals CTF Writeups',
  slug: 'isitdtu-2019-quals-ctf-writeups',
  date: '01/07/2019',
  tags: 'ctf,infosec,writeup,crypto'
}, {
  title: 'First Semester at Unimelb',
  slug: 'first-sem-at-unimelb',
  date: '27/06/2019',
  tags: 'uni'
}, {
  title: 'Hosting a Discord bot on Heroku',
  slug: 'hosting-a-discord-bot-on-heroku',
  date: '19/03/2019',
  tags: 'development,project'
}, {
  title: 'Experimenting with GraphQL',
  slug: 'experimenting-with-graphql',
  date: '02/03/2019',
  tags: 'development,project,backend'
}, {
  title: 'Unimelb programming proficiency test',
  slug: 'unimelb-programming-proficiency-test',
  date: '27/02/2019',
  tags: 'uni'
}, {
  title: 'How this blog works',
  slug: 'how-this-blog-works',
  date: '25/02/2019',
  tags: 'development'
}, {
  title: 'Github Pages and serving md',
  slug: 'github-pages-and-serving-md',
  date: '24/02/2019',
  tags: 'development'
}, {
  title: 'Generating hexagons with SVG',
  slug: 'generating-hexagons-with-svg',
  date: '22/02/2019',
  tags: 'development,react,project,frontend'
}];

/***/ }),

/***/ "./src/util/index.js":
/*!***************************!*\
  !*** ./src/util/index.js ***!
  \***************************/
/*! exports provided: formatDate */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "formatDate", function() { return formatDate; });
function _slicedToArray(arr, i) { return _arrayWithHoles(arr) || _iterableToArrayLimit(arr, i) || _nonIterableRest(); }

function _nonIterableRest() { throw new TypeError("Invalid attempt to destructure non-iterable instance"); }

function _iterableToArrayLimit(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"] != null) _i["return"](); } finally { if (_d) throw _e; } } return _arr; }

function _arrayWithHoles(arr) { if (Array.isArray(arr)) return arr; }

var months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'Decemember'];
function formatDate(ddmmyyyy) {
  var _ddmmyyyy$split = ddmmyyyy.split('/'),
      _ddmmyyyy$split2 = _slicedToArray(_ddmmyyyy$split, 3),
      day = _ddmmyyyy$split2[0],
      month = _ddmmyyyy$split2[1],
      year = _ddmmyyyy$split2[2];

  return "".concat(months[parseInt(month - 1)], " ").concat(day, ", ").concat(year);
}

/***/ })

}]);