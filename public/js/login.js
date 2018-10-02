;(function (window, document) {

    'use strict';

    var PEACH = (function() {

        var SETTINGS = {
                userLocalStorageKey: 'peach_user',
                peachUserCookieKey : 'peach_infos',
            },

            getCookie = function (a) {
                var b = document.cookie.match('(^|;)\\s*' + a + '\\s*=\\s*([^;]+)');
                return b ? decodeURI(b.pop()) : null;
            },

            supportsHTML5Storage = function() {
                try {
                    return 'localStorage' in window && window['localStorage'] !== null;
                } catch (e) {
                    return false;
                }
            },

            getUserInfo = function(callback) {
                $.ajax({
                    type: 'GET',
                    url: 'https://id.rts.ch/api/v2/session/user/profile',
                    xhrFields: {
                        withCredentials: true
                    },
                    success: function (data, textStatus, jqXHR) {
                        var user = parseUser(jqXHR.responseText);
                        if (callback) {
                            callback(true, user);
                        }
                    }
                });
            },

            parseUser = function(json) {
                var user = null;

                try {
                    if (json) {
                        var userInfo = JSON.parse(userInfoStr),
                            userId = userInfo.user.id,
                            displayName = userInfo.user.display_name;

                        if (typeof userId !== 'undefined' && typeof displayName !== 'undefined') {
                            user = {
                                id: userId,
                                displayName: displayName
                            };
                        }
                    }
                } catch (e) {

                }

                return user;
            },

            _getUser = function (callback) {
                if (!callback) return;

                var user = parseUser(),
                    isLoggedIn = getCookie(SETTINGS.peachUserCookieKey) !== null;


                if (isLoggedIn && user) {
                    callback(user);
                }
                else if (isLoggedIn && !user) {
                    getUserInfo(function (success, user) {
                        callback(user);
                    });
                }
                else if (user && !isLoggedIn) {
                    if (supportsHTML5Storage()) {
                        localStorage.removeItem(SETTINGS.userLocalStorageKey);
                    }
                    callback(user);
                } else {
                    callback(user);
                }
            };

        return {
            getUser: function (callback) {
                _getUser(callback);
            }
        };

    })();

    window.PEACH = PEACH;

})(window, document);
