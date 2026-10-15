import { createApp } from 'vue';
import axios from 'axios';
import Notifications from '@kyvg/vue3-notification'
import VueGoodTablePlugin from 'vue-good-table-next'

var axios_cfg = function(url, data='', type='form') {
  if (data == '') {
    return {
      method: 'get',
      url: url
    };
  } else if (type == 'form') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    };
  } else if (type == 'file') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'multipart/form-data' }
    };
   } else if (type == 'json') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'application/json' }
    };
  }
};

// Human readable message of a failed axios request: the backend answers with
// plain text (http.Error) or with {"status": "...", "message": "..."}.
var errorMessage = function(error) {
  if (!error.response) {
    return error.message || String(error);
  }
  var data = error.response.data;
  if (data && typeof data === 'object') {
    return data.message || data.status || JSON.stringify(data);
  }
  if (data) {
    return String(data).trim();
  }
  return error.response.statusText || ('HTTP ' + error.response.status);
};

// Minimal document.cookie helper (replaces vue-cookies, same cookie format:
// URI-encoded value, path=/, never expires).
var cookies = {
  get: function(name) {
    var prefix = encodeURIComponent(name) + '=';
    var parts = document.cookie ? document.cookie.split('; ') : [];
    for (var i = 0; i < parts.length; i++) {
      if (parts[i].indexOf(prefix) === 0) {
        try {
          return decodeURIComponent(parts[i].substring(prefix.length));
        } catch (e) {
          return null;
        }
      }
    }
    return null;
  },
  set: function(name, value) {
    document.cookie = encodeURIComponent(name) + '=' + encodeURIComponent(String(value)) +
      '; expires=Fri, 31 Dec 9999 23:59:59 GMT; path=/; SameSite=Lax';
  }
};

// navigator.clipboard is only available in secure contexts (https or
// localhost), ovpn-admin is often served over plain http.
var legacyCopyToClipboard = function(text) {
  return new Promise(function(resolve, reject) {
    var textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.top = '0';
    textarea.style.left = '0';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    var copied = false;
    try {
      copied = document.execCommand('copy');
    } catch (e) {
      copied = false;
    }
    document.body.removeChild(textarea);
    if (copied) {
      resolve();
    } else {
      reject(new Error('copy command is not supported'));
    }
  });
};

var copyToClipboard = function(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text).catch(function() {
      return legacyCopyToClipboard(text);
    });
  }
  return legacyCopyToClipboard(text);
};

var emptyCcd = function() {
  return {
    User: '',
    ClientAddress: '',
    ClientAddressIPv6: '',
    CustomRoutes: []
  };
};

var emptyRoute = function() {
  return {
    Address: '',
    Mask: '',
    Description: ''
  };
};

// Sort function of the date columns. The backend sends dates as
// "yyyy-MM-dd HH:mm:ss" (or "" when there is none), which sort correctly as
// strings; empty values go first. The date compare of vue-good-table-next
// returns -1 for any two empty dates, and with such an inconsistent comparator
// its in-place sort of the reactive rows never settles (the tab hangs).
var compareDateStrings = function (x, y) {
  x = x || '';
  y = y || '';
  return x < y ? -1 : (x > y ? 1 : 0);
};

// Missing/empty ClientAddress or ClientAddressIPv6 means "dynamic".
var normalizeCcd = function(ccd, username) {
  ccd = (ccd && typeof ccd === 'object') ? ccd : {};
  return {
    User: ccd.User || username,
    ClientAddress: ccd.ClientAddress || 'dynamic',
    ClientAddressIPv6: ccd.ClientAddressIPv6 || 'dynamic',
    CustomRoutes: Array.isArray(ccd.CustomRoutes) ? ccd.CustomRoutes : []
  };
};

const app = createApp({
  data() {
    return {
      columns: [
        {
          label: 'Name',
          field: 'Identity',
          // filterable: true,
        },
        {
          label: 'Account Status',
          field: 'AccountStatus',
          filterable: true,
        },
        {
          label: 'Active Connections',
          field: 'Connections',
          filterable: true,
        },
        {
          label: 'Expiration Date',
          field: 'ExpirationDate',
          type: 'date',
          dateInputFormat: 'yyyy-MM-dd HH:mm:ss',
          dateOutputFormat: 'yyyy-MM-dd HH:mm:ss',
          sortFn: compareDateStrings,
          formatFn: function (value) {
            return value != "" ? value : ""
          }
        },
        {
          label: 'Revocation Date',
          field: 'RevocationDate',
          type: 'date',
          dateInputFormat: 'yyyy-MM-dd HH:mm:ss',
          dateOutputFormat: 'yyyy-MM-dd HH:mm:ss',
          sortFn: compareDateStrings,
          formatFn: function (value) {
            return value != "" ? value : ""
          }
        },
        {
          label: 'Actions',
          field: 'actions',
          sortable: false,
          tdClass: 'text-end',
          globalSearchDisabled: true,
        },
      ],
      rows: [],
      actions: [
        {
          name: 'u-change-password',
          label: 'Change password',
          class: 'btn-warning',
          showWhenStatus: 'Active',
          showForServerRole: ['master'],
          showForModule: ['passwdAuth'],
        },
        {
          name: 'u-revoke',
          label: 'Revoke',
          class: 'btn-warning',
          showWhenStatus: 'Active',
          showForServerRole: ['master'],
          showForModule: ["core"],
        },
        {
          name: 'u-delete',
          label: 'Delete',
          class: 'btn-danger',
          showWhenStatus: 'Revoked',
          showForServerRole: ['master'],
          showForModule: ["core"],
        },
        {
          name: 'u-delete',
          label: 'Delete',
          class: 'btn-danger',
          showWhenStatus: 'Expired',
          showForServerRole: ['master'],
          showForModule: ["core"],
        },
        {
          name: 'u-rotate',
          label: 'Rotate',
          class: 'btn-warning',
          showWhenStatus: 'Revoked',
          showForServerRole: ['master'],
          showForModule: ["core"],
        },
        {
          name: 'u-rotate',
          label: 'Rotate',
          class: 'btn-warning',
          showWhenStatus: 'Expired',
          showForServerRole: ['master'],
          showForModule: ["core"],
        },
        {
          name: 'u-unrevoke',
          label: 'Unrevoke',
          class: 'btn-primary',
          showWhenStatus: 'Revoked',
          showForServerRole: ['master'],
          showForModule: ["core"],
        },
        // {
        //   name: 'u-show-config',
        //   label: 'Show config',
        //   class: 'btn-primary',
        //   showWhenStatus: 'Active',
        //   showForServerRole: ['master', 'slave'],
        //   showForModule: ["core"],
        // },
        {
          name: 'u-download-config',
          label: 'Download config',
          class: 'btn-info',
          showWhenStatus: 'Active',
          showForServerRole: ['master', 'slave'],
          showForModule: ["core"],
        },
        {
          name: 'u-edit-ccd',
          label: 'Edit routes',
          class: 'btn-primary',
          showWhenStatus: 'Active',
          showForServerRole: ['master'],
          showForModule: ["ccd"],
        },
        {
          name: 'u-edit-ccd',
          label: 'Show routes',
          class: 'btn-primary',
          showWhenStatus: 'Active',
          showForServerRole: ['slave'],
          showForModule: ["ccd"],
        }
      ],
      filters: {
        hideRevoked: cookies.get('hideRevoked') == "true",
      },
      // set in index.html before the first paint
      darkTheme: document.documentElement.getAttribute('data-bs-theme') === 'dark',
      serverRole: "master",
      lastSync: "unknown",
      modulesEnabled: [],
      // user the current row action / modal works with
      username: '',
      u: {
        newUserName: '',
        newUserPassword: '',
        newUserCreateError: '',
        newPassword: '',
        passwordChangeStatus: '',
        passwordChangeMessage: '',
        rotateUserStatus: '',
        rotateUserMessage: '',
        deleteUserStatus: '',
        deleteUserMessage: '',
        modalNewUserVisible: false,
        modalShowConfigVisible: false,
        modalShowCcdVisible: false,
        modalChangePasswordVisible: false,
        modalRotateUserVisible: false,
        modalDeleteUserVisible: false,
        openvpnConfig: '',
        ccd: emptyCcd(),
        ccdLoaded: false,
        newRoute: emptyRoute(),
        ccdApplyStatus: "",
        ccdApplyStatusMessage: "",
      }
    }
  },
  mounted: function () {
    this.getUserData();
    this.getServerSetting();
    // the rows change their height with the data and the window width (action buttons wrap)
    const table = document.querySelector('.vgt-table');
    if (table && window.ResizeObserver) {
      new ResizeObserver(this.updatePageFooterHeight).observe(table);
    }
  },
  computed: {
    ipv6Enabled: function () {
      return this.modulesEnabled.includes('ipv6')
    },
    customAddressDynamic: function () {
      return this.u.ccd.ClientAddress == "dynamic"
    },
    customAddressIPv6Dynamic: function () {
      return this.u.ccd.ClientAddressIPv6 == "dynamic"
    },
    // a static IPv6 address left over in the ccd is shown even when IPv6 is
    // disabled, so that it can be cleared
    showIPv6Address: function () {
      return this.ipv6Enabled || (this.u.ccd.ClientAddressIPv6 != "" && !this.customAddressIPv6Dynamic)
    },
    ccdApplyStatusCssClass: function () {
        return this.u.ccdApplyStatus == 200 ? "alert-success" : "alert-danger"
    },
    passwordChangeStatusCssClass: function () {
      return this.u.passwordChangeStatus == 200 ? "alert-success" : "alert-danger"
    },
    userRotateStatusCssClass: function () {
      return this.u.rotateUserStatus == 200 ? "alert-success" : "alert-danger"
    },
    deleteUserStatusCssClass: function () {
      return this.u.deleteUserStatus == 200 ? "alert-success" : "alert-danger"
    },
    modalNewUserDisplay: function () {
      return this.u.modalNewUserVisible ? {display: 'flex'} : {}
    },
    modalShowConfigDisplay: function () {
      return this.u.modalShowConfigVisible ? {display: 'flex'} : {}
    },
    modalShowCcdDisplay: function () {
      return this.u.modalShowCcdVisible ? {display: 'flex'} : {}
    },
    modalChangePasswordDisplay: function () {
      return this.u.modalChangePasswordVisible ? {display: 'flex'} : {}
    },
    modalRotateUserDisplay: function () {
      return this.u.modalRotateUserVisible ? {display: 'flex'} : {}
    },
    modalDeleteUserDisplay: function () {
      return this.u.modalDeleteUserVisible ? {display: 'flex'} : {}
    },
    revokeFilterText: function() {
      return this.filters.hideRevoked ? "Show revoked" : "Hide revoked"
    },
    themeButtonText: function() {
      return this.darkTheme ? "\u2600 Light" : "\u263E Dark"
    },
    themeButtonTitle: function() {
      return this.darkTheme ? "Switch to the light theme" : "Switch to the dark theme"
    },
    filteredRows: function() {
      if (this.filters.hideRevoked) {
        return this.rows.filter(function(account) {
          return account.AccountStatus == "Active"
        });
      } else {
        return this.rows
      }
    }

  },
  methods: {
    // the page footer is half a user row high (see .page-footer in style.css)
    updatePageFooterHeight: function() {
      // a user row has a line number cell, the "no users" row has not
      const cell = document.querySelector('.vgt-table tbody th.line-numbers');
      const height = cell ? Math.round(cell.parentElement.getBoundingClientRect().height / 2) : 0;
      if (height > 0) {
        document.documentElement.style.setProperty('--page-footer-height', height + 'px');
      }
    },
    rowStyleClassFn: function(row) {
      if (row.ConnectionStatus == 'Connected') {
        return 'connected-user'
      }
      if (row.AccountStatus == 'Revoked') {
        return 'revoked-user'
      }
      if (row.AccountStatus == 'Expired') {
        return 'expired-user'
      }
      return ''
    },
    rowActions: function(row) {
      var _this = this;
      return _this.actions.filter(function(action) {
        return action.showWhenStatus == row.AccountStatus &&
          action.showForServerRole.includes(_this.serverRole) &&
          action.showForModule.some(function(p) { return _this.modulesEnabled.includes(p) });
      });
    },
    rowActionFn: function(actionName, username) {
      var handlers = {
        'u-revoke': this.revokeUserAction,
        'u-unrevoke': this.unrevokeUserAction,
        'u-rotate': this.rotateUserAction,
        'u-delete': this.deleteUserAction,
        'u-show-config': this.showConfigAction,
        'u-download-config': this.downloadConfigAction,
        'u-edit-ccd': this.editCcdAction,
        'u-disconnect-user': this.disconnectUserAction,
        'u-change-password': this.changePasswordAction,
      };
      var handler = handlers[actionName];
      if (!handler) {
        console.error('unknown row action: ' + actionName);
        return;
      }
      this.username = username;
      handler();
    },
    toggleRevokedFilter: function() {
      this.filters.hideRevoked = !this.filters.hideRevoked;
      cookies.set('hideRevoked', this.filters.hideRevoked);
    },
    toggleTheme: function() {
      this.darkTheme = !this.darkTheme;
      var theme = this.darkTheme ? 'dark' : 'light';
      document.documentElement.setAttribute('data-bs-theme', theme);
      cookies.set('theme', theme);
    },

    revokeUserAction: function() {
      var _this = this;
      var username = _this.username;
      var data = new URLSearchParams();
      data.append('username', username);
      axios.request(axios_cfg('api/user/revoke', data, 'form'))
      .then(function(response) {
        _this.getUserData();
        _this.$notify({title: 'User ' + username + ' revoked!', type: 'warn'})
      })
      .catch(function(error) {
        _this.$notify({title: 'Revoking user ' + username + ' failed!', text: errorMessage(error), type: 'error'})
      });
    },
    unrevokeUserAction: function() {
      var _this = this;
      var username = _this.username;
      var data = new URLSearchParams();
      data.append('username', username);
      axios.request(axios_cfg('api/user/unrevoke', data, 'form'))
      .then(function(response) {
        _this.getUserData();
        _this.$notify({title: 'User ' + username + ' unrevoked!', type: 'success'})
      })
      .catch(function(error) {
        _this.$notify({title: 'Unrevoking user ' + username + ' failed!', text: errorMessage(error), type: 'error'})
      });
    },
    rotateUserAction: function() {
      this.u.modalRotateUserVisible = true;
    },
    deleteUserAction: function() {
      this.u.modalDeleteUserVisible = true;
    },
    showConfigAction: function() {
      var _this = this;
      _this.u.modalShowConfigVisible = true;
      var data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/config/show', data, 'form'))
      .then(function(response) {
        _this.u.openvpnConfig = response.data;
      });
    },
    downloadConfigAction: function() {
      var username = this.username;
      var data = new URLSearchParams();
      data.append('username', username);
      axios.request(axios_cfg('api/user/config/show', data, 'form'))
      .then(function(response) {
        const blob = new Blob([response.data], { type: 'text/plain' })
        const link = document.createElement('a')
        link.href = URL.createObjectURL(blob)
        link.download = username + ".ovpn"
        link.click()
        URL.revokeObjectURL(link.href)
      }).catch(console.error);
    },
    editCcdAction: function() {
      var _this = this;
      _this.u.ccd = emptyCcd();
      _this.u.ccdLoaded = false;
      _this.u.newRoute = emptyRoute();
      _this.u.ccdApplyStatus = "";
      _this.u.ccdApplyStatusMessage = "";
      _this.u.modalShowCcdVisible = true;
      var data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/ccd', data, 'form'))
      .then(function(response) {
        _this.u.ccd = normalizeCcd(response.data, _this.username);
        _this.u.ccdLoaded = true;
      })
      .catch(function(error) {
        _this.$notify({title: 'Loading ccd for user ' + _this.username + ' failed!', text: errorMessage(error), type: 'error'})
      });
    },
    disconnectUserAction: function() {
      var data = new URLSearchParams();
      data.append('username', this.username);
      axios.request(axios_cfg('api/user/disconnect', data, 'form'))
      .then(function(response) {
        console.log(response.data);
      });
    },
    changePasswordAction: function() {
      this.u.modalChangePasswordVisible = true;
    },

    copyConfig: function() {
      var _this = this;
      copyToClipboard(_this.u.openvpnConfig)
      .then(function() {
        _this.$notify({title: 'Config copied to clipboard', type: 'success'})
      })
      .catch(function(error) {
        _this.$notify({title: 'Copying config to clipboard failed!', text: errorMessage(error), type: 'error'})
      });
    },

    getUserData: function() {
      var _this = this;
      axios.request(axios_cfg('api/users/list'))
        .then(function(response) {
          _this.rows = Array.isArray(response.data) ? response.data : [];
        });
    },

    getServerSetting: function() {
      var _this = this;
      axios.request(axios_cfg('api/server/settings'))
      .then(function(response) {
        _this.serverRole = response.data.serverRole;
        _this.modulesEnabled = Array.isArray(response.data.modules) ? response.data.modules : [];

        if (_this.serverRole == "slave") {
          axios.request(axios_cfg('api/sync/last/successful'))
          .then(function(response) {
            _this.lastSync =  response.data;
          });
        }
      });
    },

    createUser: function() {
      var _this = this;

      _this.u.newUserCreateError = "";

      var data = new URLSearchParams();
      data.append('username', _this.u.newUserName);
      data.append('password', _this.u.newUserPassword);

      _this.username = _this.u.newUserName;

      axios.request(axios_cfg('api/user/create', data, 'form'))
      .then(function(response) {
        _this.$notify({title: 'New user ' + _this.username + ' created', type: 'success'})
        _this.u.modalNewUserVisible = false;
        _this.u.newUserName = '';
        _this.u.newUserPassword = '';
        _this.getUserData();
      })
      .catch(function(error) {
        _this.u.newUserCreateError = errorMessage(error);
        _this.$notify({title: 'New user ' + _this.username + ' creation failed.', type: 'error'})

      });
    },

    addRoute: function() {
      var route = this.u.newRoute;
      if (route.Address.trim() == '') {
        return;
      }
      this.u.ccd.CustomRoutes.push({
        Address: route.Address.trim(),
        Mask: route.Mask.trim(),
        Description: route.Description
      });
      this.u.newRoute = emptyRoute();
    },

    closeCcdModal: function() {
      this.u.ccd = emptyCcd();
      this.u.ccdLoaded = false;
      this.u.newRoute = emptyRoute();
      this.u.ccdApplyStatusMessage = '';
      this.u.ccdApplyStatus = '';
      this.u.modalShowCcdVisible = false;
    },

    ccdApply: function() {
      var _this = this;

      _this.u.ccdApplyStatus = "";
      _this.u.ccdApplyStatusMessage = "";

      var ccd = {
        User: _this.u.ccd.User,
        ClientAddress: _this.u.ccd.ClientAddress.trim() || 'dynamic',
        ClientAddressIPv6: _this.u.ccd.ClientAddressIPv6.trim() || 'dynamic',
        CustomRoutes: _this.u.ccd.CustomRoutes
      };

      axios.request(axios_cfg('api/user/ccd/apply', JSON.stringify(ccd), 'json'))
      .then(function(response) {
        _this.u.ccdApplyStatus = 200;
        _this.u.ccdApplyStatusMessage = String(response.data);
        _this.$notify({title: 'Ccd for user ' + _this.username + ' applied', type: 'success'})
      })
      .catch(function(error) {
        _this.u.ccdApplyStatus = error.response ? error.response.status : '';
        _this.u.ccdApplyStatusMessage = errorMessage(error);
        _this.$notify({title: 'Ccd for user ' + _this.username + ' apply failed ', type: 'error'})
      });
    },

    changeUserPassword: function(user) {
      var _this = this;

      _this.u.passwordChangeMessage = "";

      var data = new URLSearchParams();
      data.append('username', user);
      data.append('password', _this.u.newPassword);

      axios.request(axios_cfg('api/user/change-password', data, 'form'))
        .then(function(response) {
          _this.u.passwordChangeStatus = 200;
          _this.u.newPassword = '';
          _this.getUserData();
          _this.u.modalChangePasswordVisible = false;
          _this.$notify({title: 'Password for user ' + _this.username + ' changed!', type: 'success'})
        })
        .catch(function(error) {
          _this.u.passwordChangeStatus = error.response ? error.response.status : '';
          _this.u.passwordChangeMessage = errorMessage(error);
          _this.$notify({title: 'Changing password for user ' + _this.username + ' failed!', type: 'error'})
        });
    },

    rotateUser: function(user) {
      var _this = this;

      _this.u.rotateUserMessage = "";

      var data = new URLSearchParams();
      data.append('username', user);
      data.append('password', _this.u.newPassword);

      axios.request(axios_cfg('api/user/rotate', data, 'form'))
        .then(function(response) {
          _this.u.rotateUserStatus = 200;
          _this.u.newPassword = '';
          _this.getUserData();
          _this.u.modalRotateUserVisible = false;
          _this.$notify({title: 'Certificates for user ' + _this.username + ' rotated!', type: 'success'})
        })
        .catch(function(error) {
          _this.u.rotateUserStatus = error.response ? error.response.status : '';
          _this.u.rotateUserMessage = errorMessage(error);
          _this.$notify({title: 'Rotate certificates for user ' + _this.username + ' failed!', type: 'error'})
        })
    },
    deleteUser: function(user) {
      var _this = this;

      _this.u.deleteUserMessage = "";

      var data = new URLSearchParams();
      data.append('username', user);

      axios.request(axios_cfg('api/user/delete', data, 'form'))
        .then(function(response) {
          _this.u.deleteUserStatus = 200;
          _this.u.newPassword = '';
          _this.getUserData();
          _this.u.modalDeleteUserVisible = false;
          _this.$notify({title: 'User ' + _this.username + ' deleted!', type: 'success'})
        })
        .catch(function(error) {
          _this.u.deleteUserStatus = error.response ? error.response.status : '';
          _this.u.deleteUserMessage = errorMessage(error);
          _this.$notify({title: 'Deleting user ' + _this.username + ' failed!', type: 'error'})
        })
    },
  }

});

app.use(Notifications);
app.use(VueGoodTablePlugin);
app.mount('#app');
