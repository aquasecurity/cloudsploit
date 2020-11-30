var ONE_DAY = 24*60*60*1000;

var daysBetween = function(date1, date2) {
    return Math.round(Math.abs((new Date(date1).getTime() - new Date(date2).getTime())/(ONE_DAY)));
};

module.exports = {
    daysBetween: daysBetween,

    daysAgo: function(date) {
        return daysBetween(date, new Date());
    },

    mostRecentDate: function(dates) {
        var mostRecentDate;

        for (var d in dates) {
            if (!mostRecentDate || dates[d] > mostRecentDate) {
                mostRecentDate = dates[d];
            }
        }

        return mostRecentDate;
    },

    isCustom: function(providedSettings, pluginSettings) {
        var isCustom = false;

        for (var s in pluginSettings) {
            if (providedSettings[s] && pluginSettings[s].default &&
                (providedSettings[s] !== pluginSettings[s].default)) {
                isCustom = true;
                break;
            }
        }

        return isCustom;
    },

    addError: function(original){
        if (!original || !original.err) {
            return 'Unable to obtain data';
        } else if (typeof original.err === 'string') {
            return original.err;
        } else if (original.err.message) {
            return original.err.message;
        } else if (original.err.code) {
            return original.err.code;
        } else {
            return 'Unable to obtain data';
        }
    },

    cidrSize: function(block){
        /*
         Determine the number of IP addresses in a given CIDR block
         Algorithm from https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation
         2^(address length - prefix length)
         */
        return Math.pow(2, 32 - block.split('/')[1]);
    },

    addSource: function(cache, source, paths){
        // paths = array of arrays (props of each element; service, call, region, extra)
        var service = paths[0];
        var call = paths[1];
        var region = paths[2];
        var extra = paths[3];

        if (!source[service]) source[service] = {};
        if (!source[service][call]) source[service][call] = {};
        if (!source[service][call][region]) source[service][call][region] = {};

        var original;
        if (extra) {
            original = (cache[service] &&
                cache[service][call] &&
                cache[service][call][region] &&
                cache[service][call][region][extra]) ?
                cache[service][call][region][extra] : null;

            source[service][call][region][extra] = original;
        } else {
            original = (cache[service] &&
                cache[service][call] &&
                cache[service][call][region]) ?
                cache[service][call][region] : null;

            source[service][call][region] = original;
        }

        return original;
    },

    addResult: function(results, status, message, region, resource, custom){
        results.push({
            status: status,
            message: message,
            region: region || 'global',
            resource: resource || null,
            custom: custom || false
        });
    },

    objectFirstKey: function(object) {
        return Object.keys(object)[0];
    },

    isValidArray: function(value){
        return (Array.isArray(value) && value.length > 0);
    },

    isValidObject: function(value){
        return (value && (typeof value === 'object') && (value.constructor === Object));
    },

    compareVersions: function compareVersions(v1, v2) {
        var s1 = v1.split('.');
        var s2 = v2.split('.');

        for (var i = 0; i < Math.max(s1.length - 1, s2.length - 1); i++) {
            var n1 = parseInt(s1[i] || 0, 10);
            var n2 = parseInt(s2[i] || 0, 10);

            if (n1 > n2) return 1;
            if (n2 > n1) return -1;
        }
        return 0;
    }
};
