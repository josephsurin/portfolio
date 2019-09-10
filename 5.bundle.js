(window["webpackJsonp"] = window["webpackJsonp"] || []).push([[5],{

/***/ "./src/Components/Blog/postPage.js":
/*!*****************************************!*\
  !*** ./src/Components/Blog/postPage.js ***!
  \*****************************************/
/*! exports provided: default */
/*! ModuleConcatenation bailout: Module is referenced from these modules with unsupported syntax: ./src/app.js (referenced with import()) */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, "default", function() { return PostPage; });
/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! react */ "./node_modules/preact/compat/dist/compat.module.js");
/* harmony import */ var react_router_dom__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! react-router-dom */ "./node_modules/react-router-dom/es/index.js");
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../../util */ "./src/util/index.js");
/* harmony import */ var _tags__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./tags */ "./src/Components/Blog/tags.js");
/* harmony import */ var _markdown__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./markdown */ "./src/Components/Blog/markdown.js");
/* harmony import */ var _util__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! ./util */ "./src/Components/Blog/util.js");
function _typeof(obj) { if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } }

function _createClass(Constructor, protoProps, staticProps) { if (protoProps) _defineProperties(Constructor.prototype, protoProps); if (staticProps) _defineProperties(Constructor, staticProps); return Constructor; }

function _possibleConstructorReturn(self, call) { if (call && (_typeof(call) === "object" || typeof call === "function")) { return call; } return _assertThisInitialized(self); }

function _assertThisInitialized(self) { if (self === void 0) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return self; }

function _getPrototypeOf(o) { _getPrototypeOf = Object.setPrototypeOf ? Object.getPrototypeOf : function _getPrototypeOf(o) { return o.__proto__ || Object.getPrototypeOf(o); }; return _getPrototypeOf(o); }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function"); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, writable: true, configurable: true } }); if (superClass) _setPrototypeOf(subClass, superClass); }

function _setPrototypeOf(o, p) { _setPrototypeOf = Object.setPrototypeOf || function _setPrototypeOf(o, p) { o.__proto__ = p; return o; }; return _setPrototypeOf(o, p); }








var PostPage =
/*#__PURE__*/
function (_Component) {
  _inherits(PostPage, _Component);

  function PostPage(props) {
    var _this;

    _classCallCheck(this, PostPage);

    _this = _possibleConstructorReturn(this, _getPrototypeOf(PostPage).call(this, props));
    var postPageProps = _util__WEBPACK_IMPORTED_MODULE_5__["simpleStore"].get('postPageProps'); //prioritise using post data from state

    if (postPageProps) {
      _this.state = {
        postMeta: Object.assign({}, postPageProps.postMeta),
        postBody: postPageProps.postBody
      };
    } else {
      _this.fetchPostData();
    }

    return _this;
  }

  _createClass(PostPage, [{
    key: "componentDidMount",
    value: function componentDidMount() {
      window.scrollTo(0, 0);
    }
  }, {
    key: "render",
    value: function render() {
      if (!this.state) {
        return react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
          className: "loading"
        });
      }

      var _this$state = this.state,
          _this$state$postMeta = _this$state.postMeta,
          title = _this$state$postMeta.title,
          date = _this$state$postMeta.date,
          tags = _this$state$postMeta.tags,
          postBody = _this$state.postBody;
      return react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
        className: "post-page"
      }, react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(react_router_dom__WEBPACK_IMPORTED_MODULE_1__["Link"], {
        to: "/blog",
        className: "back-button"
      }, "BACK"), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
        className: "post-title"
      }, title), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
        className: "post-date"
      }, Object(_util__WEBPACK_IMPORTED_MODULE_2__["formatDate"])(date)), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(_tags__WEBPACK_IMPORTED_MODULE_3__["default"], {
        tags: tags
      }), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("hr", null), react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement("div", {
        className: "post-body",
        dangerouslySetInnerHTML: {
          __html: _markdown__WEBPACK_IMPORTED_MODULE_4__["md"].render(postBody || '')
        }
      }));
    }
  }, {
    key: "fetchPostData",
    value: function fetchPostData() {
      var _this2 = this;

      Object(_util__WEBPACK_IMPORTED_MODULE_5__["fetchPostData"])(this.props.match.params.slug).then(function (postPageProps) {
        _this2.setState({
          postMeta: Object.assign({}, postPageProps.postMeta),
          postBody: postPageProps.postBody
        });
      });
    }
  }]);

  return PostPage;
}(react__WEBPACK_IMPORTED_MODULE_0__["Component"]);



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

/***/ })

}]);