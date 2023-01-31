var ONE_DAY = 24*60*60*1000;
var ONE_HOUR = 60*60*1000;

var daysBetween = function(date1, date2) {
    return Math.round(Math.abs((new Date(date1).getTime() - new Date(date2).getTime())/(ONE_DAY)));
};

var hoursBetween = function(date1, date2) {
    return Math.round(Math.abs((new Date(date1).getTime() - new Date(date2).getTime())/(ONE_HOUR)));
};

var minutesBetween = function(date1, date2) {
    return Math.round(Math.abs((new Date(date1).getTime() - new Date(date2).getTime())/(60*1000)));
};

var processIntegration = function(serviceName, settings, collection, calls, postcalls, debugMode, iCb) {
    let localEvent = {};
    let localSettings = {};
    localSettings = settings;

    localEvent.collection = {};
    localEvent.previousCollection = {};

    localEvent.collection[serviceName.toLowerCase()] = {};
    localEvent.previousCollection[serviceName.toLowerCase()] = {};

    localEvent.collection[serviceName.toLowerCase()] = collection[serviceName.toLowerCase()] ? collection[serviceName.toLowerCase()] : {};
    localEvent.previousCollection[serviceName.toLowerCase()] = settings.previousCollection && settings.previousCollection[serviceName.toLowerCase()] ? settings.previousCollection[serviceName.toLowerCase()] : {};

    if (!localSettings.identifier) localSettings.identifier = {};
    localSettings.identifier.service = serviceName.toLowerCase();

    // Single Source Fields
    if (calls[serviceName] && calls[serviceName].sendIntegration && calls[serviceName].sendIntegration.isSingleSource) {
        localEvent.data = calls[serviceName].sendIntegration;
    }

    for (let postcall of postcalls) {
        if (postcall[serviceName] && postcall[serviceName].sendIntegration && postcall[serviceName].sendIntegration.isSingleSource) {
            localEvent.data = postcall[serviceName].sendIntegration;
            break;
        }
    }

    processIntegrationAdditionalData(serviceName, settings, collection, calls, postcalls, localEvent.collection, function(collectionReturned){
        localEvent.collection = collectionReturned;

        processIntegrationAdditionalData(serviceName, settings, settings.previousCollection, calls, postcalls, localEvent.previousCollection, function(previousCollectionReturned){
            localEvent.previousCollection = previousCollectionReturned;
            localSettings.integration(localEvent, function() {
                if (debugMode) console.log(`Processed Event: ${JSON.stringify(localEvent)}`);

                return iCb();
            });
        });
    });
};

var processIntegrationAdditionalData = function(serviceName, localSettings, localCollection, calls, postcalls, localEventCollection, callback){
    if (localCollection == undefined ||
        (localCollection &&
            (JSON.stringify(localCollection)==='{}' ||
                localCollection[serviceName.toLowerCase()] == undefined ||
                JSON.stringify(localCollection[serviceName.toLowerCase()])==='{}'))) {
        return callback(null);
    }

    let callsMap = calls[serviceName] ? Object.keys(calls[serviceName]) : null;
    let foundData=[];

    if (callsMap && callsMap.find(mycall => mycall == 'sendIntegration') &&
        reliesOnFound(calls, localCollection, serviceName)) {
        foundData = reliesOnData(calls, localCollection, serviceName);
    }

    if (callsMap && callsMap.find(mycall => mycall == 'sendIntegration') &&
        integrationReliesOnFound(calls, localCollection, serviceName)) {
        foundData = integrationReliesOnData(calls, localCollection, serviceName);

        if (foundData &&
            Object.keys(foundData).length){
            for (let d of Object.keys(foundData)){
                localEventCollection[d]=foundData[d];
            }
        }
    }

    for (let postcall of postcalls) {
        if (!postcall[serviceName]) continue;
        let postCallsMap = Object.keys(postcall[serviceName]);

        foundData=[];

        if (postCallsMap.find(mycall => mycall == 'sendIntegration') &&
            reliesOnFound(postcall, localCollection, serviceName)){
            foundData = reliesOnData(postcall, localCollection, serviceName);
        }

        if (postCallsMap.find(mycall => mycall == 'sendIntegration') &&
            integrationReliesOnFound(postcall, localCollection, serviceName)){
            foundData = integrationReliesOnData(postcall, localCollection, serviceName);

            if (foundData &&
                Object.keys(foundData).length){
                for (let d of Object.keys(foundData)){
                    localEventCollection[d]=foundData[d];
                }
            }
        }
    }

    localSettings.identifier.service = serviceName.toLowerCase();
    return callback(localEventCollection);
};

var reliesOnFound = function(calls, localCollection, serviceName){
    let callsMap = Object.keys(calls[serviceName]);

    if (callsMap.find(mycall => mycall == 'sendIntegration')) {
        if (calls[serviceName] &&
            calls[serviceName].sendIntegration &&
            calls[serviceName].sendIntegration.enabled &&
            calls[serviceName].sendIntegration.reliesOnCalls &&
            calls[serviceName].sendIntegration.reliesOnCalls.length) {

            let allRelies = true;

            for (let rc of calls[serviceName].sendIntegration.reliesOnCalls) {
                let svc = rc.split(':')[0];
                let svcCall = rc.split(':')[1];
                if (!(localCollection[svc.toLowerCase()] &&
                    localCollection[svc.toLowerCase()][svcCall] &&
                    Object.keys(localCollection[svc.toLowerCase()][svcCall]) &&
                    Object.keys(localCollection[svc.toLowerCase()][svcCall]).length>0)){
                    allRelies = false;
                }
            }

            return allRelies;
        }
    }
};

var integrationReliesOnFound = function(calls, localCollection, serviceName){
    let callsMap = Object.keys(calls[serviceName]);

    if (callsMap.find(mycall => mycall == 'sendIntegration')) {
        if (calls[serviceName] &&
            calls[serviceName].sendIntegration &&
            calls[serviceName].sendIntegration.enabled &&
            calls[serviceName].sendIntegration.integrationReliesOn &&
            calls[serviceName].sendIntegration.integrationReliesOn.serviceName &&
            Array.isArray(calls[serviceName].sendIntegration.integrationReliesOn.serviceName) &&
            calls[serviceName].sendIntegration.integrationReliesOn.serviceName.length) {
            return true;
        } else {
            return false;
        }
    }
};

var reliesOnData = function(calls, localCollection, serviceName){
    let callsMap = Object.keys(calls[serviceName]);

    if (callsMap.find(mycall => mycall == 'sendIntegration')) {
        if (calls[serviceName] &&
            calls[serviceName].sendIntegration &&
            calls[serviceName].sendIntegration.enabled &&
            calls[serviceName].sendIntegration.reliesOnCalls &&
            calls[serviceName].sendIntegration.reliesOnCalls.length) {

            let allRelies = true;

            for (let rc of calls[serviceName].sendIntegration.reliesOnCalls) {
                let svc = rc.split(':')[0];
                let svcCall = rc.split(':')[1];
                if (!(localCollection[svc.toLowerCase()] &&
                    localCollection[svc.toLowerCase()][svcCall] &&
                    Object.keys(localCollection[svc.toLowerCase()][svcCall]) &&
                    Object.keys(localCollection[svc.toLowerCase()][svcCall]).length>0)){
                    allRelies = false;
                }

                return allRelies ? localCollection[svc.toLowerCase()] : [];
            }
        }
    }
};

var integrationReliesOnData = function(calls, localCollection, serviceName){
    let callsMap = Object.keys(calls[serviceName]);

    if (callsMap.find(mycall => mycall == 'sendIntegration')) {
        if (localCollection &&
            calls[serviceName] &&
            calls[serviceName].sendIntegration &&
            calls[serviceName].sendIntegration.enabled &&
            calls[serviceName].sendIntegration.integrationReliesOn &&
            calls[serviceName].sendIntegration.integrationReliesOn.serviceName &&
            Array.isArray(calls[serviceName].sendIntegration.integrationReliesOn.serviceName) &&
            calls[serviceName].sendIntegration.integrationReliesOn.serviceName.length) {

            let serviceReliedOn = {};
            for (let serv of calls[serviceName].sendIntegration.integrationReliesOn.serviceName) {
                if (localCollection[serv.toLowerCase()]) {
                    serviceReliedOn[serv.toLowerCase()] = localCollection[serv.toLowerCase()];
                }
            }

            return serviceReliedOn;
        } else {
            return {};
        }
    }
};

var callsCollected = function(serviceName, localCollection, calls, postcalls) {
    var callsFoundMap = {};
    let serviceCallMap = Object.keys(localCollection[serviceName.toLowerCase()]);

    for (let call of serviceCallMap){
        if (!(localCollection[serviceName.toLowerCase()] &&
            localCollection[serviceName.toLowerCase()][call] &&
            Object.keys(localCollection[serviceName.toLowerCase()][call]) &&
            Object.keys(localCollection[serviceName.toLowerCase()][call]).length>0)){
            return false;
        }
    }

    if (calls[serviceName]) {
        let callsMap = Object.keys(calls[serviceName]);
        for (let checkCall of serviceCallMap) {
            if (callsMap.find(mycall => mycall != 'sendIntegration' && mycall == checkCall)){
                if (reliesOnFound(calls, localCollection, serviceName)==false) return false;

                if (callsMap.find(mycall => mycall != 'sendIntegration' && mycall == checkCall) == serviceCallMap.find(mycall => mycall == checkCall)){
                    callsFoundMap[checkCall]=true;
                } else {
                    return false;
                }
            }
        }
    }

    for (let postcall of postcalls) {
        if (!postcall[serviceName]) continue;
        let postCallsMap = Object.keys(postcall[serviceName]);

        for (let checkCall of serviceCallMap) {
            if (callsFoundMap[checkCall]) continue;
            if (reliesOnFound(postcall, localCollection, serviceName)==false) return false;

            if (postCallsMap.find(mycall => mycall != 'sendIntegration' && mycall == checkCall)){
                if (!(postCallsMap.find(mycall => mycall != 'sendIntegration' && mycall == checkCall) == serviceCallMap.find(mycall => mycall == checkCall))){
                    return false;
                }
            }
        }
    }

    return true;
};

module.exports = {
    callsCollected: callsCollected,

    processIntegration: processIntegration,

    daysBetween: daysBetween,

    hoursBetween: hoursBetween,

    minutesBetween: minutesBetween,

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
