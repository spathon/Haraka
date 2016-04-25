// This plugin checks for clients that talk before we sent a response

var ipaddr = require('ipaddr.js');
var isIPv6 = require('net').isIPv6;

exports.register = function() {
    var plugin = this;
    plugin.load_config();
    plugin.register_hook('connect_init', 'early_talker');
    plugin.register_hook('data',         'early_talker');
};

exports.load_config = function () {
    var plugin = this;
    plugin.whitelist = {};

    function load_ip_list(type, file_name) {
        plugin.whitelist[type] = [];

        var list = Object.keys(plugin.cfg[file_name]);

        for (var i = 0; i < list.length; i++) {
            try {
                var addr = list[i];
                if (addr.match(/\/\d+$/)) {
                    addr = ipaddr.parseCIDR(addr);
                }
                else {
                    addr = ipaddr.parseCIDR(addr + ((isIPv6(addr)) ? '/128' : '/32'));
                }

                plugin.whitelist[type].push(addr);
            } catch (e) {
            }
        }

        plugin.logdebug('whitelist {' + type + '} loaded from ' + file_name + ' with ' + plugin.whitelist[type].length + ' entries');
    }

    plugin.cfg = plugin.config.get('early_talker.ini', {
        booleans: [
            '+main.reject'
        ]
    },
    function () {
        plugin.load_config();
    });

    if (plugin.cfg.main && plugin.cfg.main.pause) {
        plugin.pause = plugin.cfg.main.pause * 1000;
        return;
    }

    // config/early_talker.pause is in milliseconds
    plugin.pause = plugin.config.get('early_talker.pause', function () {
        plugin.load_config();
    });
    load_ip_list('ip', 'ip_whitelist');
};

exports.early_talker = function(next, connection) {
    var plugin = this;
    if (!plugin.pause) return next();

    if (connection.relaying) {    // Don't delay AUTH/RELAY clients
        if (connection.early_talker) {
            connection.results.add(plugin, { skip: 'relay client'});
        }
        return next();
    }

    // Don't delay whitelisted IPs
    if (plugin.ip_in_list(connection.remote_ip)) { // check connecting IP
        connection.transaction.results.add(plugin, {
            skip: 'config-whitelist(ip)'
        });
        return next();
    }

    var check = function () {
        if (!connection) return next();
        if (!connection.early_talker) {
            connection.results.add(plugin, {pass: 'early'});
            return next();
        }
        connection.results.add(plugin, {fail: 'early'});
        if (!plugin.cfg.main.reject) return next();
        return next(DENYDISCONNECT, "You talk too soon");
    };

    var pause = plugin.pause;
    if (plugin.hook === 'connect_init') {
        var elapsed = (Date.now() - connection.start_time);
        if (elapsed > plugin.pause) {
            // Something else already waited
            return check();
        }
        pause = plugin.pause - elapsed;
    }

    setTimeout(function () { check(); }, pause);
};

exports.ip_in_list = function (ip) {
    var plugin = this;
    var ipobj = ipaddr.parse(ip);

    var list = plugin.whitelist.ip;

    for (var i = 0; i < list.length; i++) {
        try {
            if (ipobj.match(list[i])) {
                return true;
            }
        } catch (e) {
        }
    }

    return false;
};
