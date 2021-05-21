var shared = require(__dirname + '/../shared.js');

var disabledKeywords = ['has not been used', 'it is disabled'];

function addResult(results, status, message, region, resource, custom, err, required) {
    var pushResult = function(status, message, region, resource, custom) {
        results.push({
            status: status,
            message: message,
            region: region || 'global',
            resource: resource || null,
            custom: custom || false
        });
    };

    var processError = function(errorObj) {
        if (errorObj &&
            errorObj.code &&
            errorObj.code == 404) {
            pushResult(0, 'Project is deleted or pending deletion.', region, resource, custom);
        } else if (errorObj &&
            errorObj.code &&
            errorObj.code == 403 &&
            errorObj.message &&
            disabledKeywords.some(substring=>errorObj.message.includes(substring))) {
            pushResult(required ? 2 : 0, required ? 'Service is not enabled, but it is recommended to run a secure workload in GCP.' : 'Service is not enabled', region, resource, custom);
        } else if (errorObj &&
            errorObj.code &&
            errorObj.code == 403 &&
            errorObj.errors &&
            errorObj.errors.length) {
            errorObj.errors.forEach(function(errError){
                if (errError &&
                    errError.message &&
                    disabledKeywords.some(substring=>errError.message.includes(substring))){
                    pushResult(required ? 2 : 0, required ? 'Service is not enabled, but it is recommended to run a secure workload in GCP.' : 'Service is not enabled', region, resource, custom);
                } else {
                    pushResult(3, (errError.message ? errError.message : message), region, resource, custom);
                }
            });

        } else {
            pushResult(3, (errorObj.message ? errorObj.message : 'Unable to query the API: ' + errorObj.code), region, resource, custom);
        }
    };

    if (err &&
        err.code) {
        processError(err);
    } else if (err &&
        err[region] &&
        err[region].length) {
        err[region].forEach(function(errRegion) {
            if (errRegion &&
                err[region][errRegion] &&
                err[region][errRegion].code) {
                processError(err[region][errRegion]);
            } else {
                pushResult(3, (err[region][errRegion].message ? err[region][errRegion].message : message), region, resource, custom);
            }
        });
    } else if (message &&
        disabledKeywords.some(substring=>message.includes(substring))) {
        pushResult(required ? 2 : 0, required ? 'Service is not enabled, but it is recommended to run a secure workload in GCP.' : 'Service is not enabled', region, resource, custom);
    } else {
        pushResult(status, message, region, resource, custom);
    }
}

function findOpenPorts(ngs, protocols, service, location, results) {
    let found = false;
    for (let sgroups of ngs) {
        let strings = [];
        let resource = sgroups.id;
        if (sgroups.allowed && sgroups.allowed.length) {
            let firewallRules = sgroups.allowed;
            let sourceAddressPrefix = sgroups.sourceRanges;

            if (!sourceAddressPrefix || !sourceAddressPrefix.length) continue;

            for (let firewallRule of firewallRules) {
                for (let protocol in protocols) {
                    let ports = protocols[protocol];

                    for (let port of ports) {
                        if (sgroups['direction'] && (sgroups['direction'] === 'INGRESS') &&
                            firewallRule['IPProtocol'] && (firewallRule['IPProtocol'] === protocol) &&
                            !sgroups['disabled'] &&
                            (sourceAddressPrefix.includes('*') || sourceAddressPrefix.includes('') || sourceAddressPrefix.includes('0.0.0.0/0') || sourceAddressPrefix.includes('<nw>/0') || sourceAddressPrefix.includes('/0') || sourceAddressPrefix.includes('internet'))) {
                            var sourcefilter = (sourceAddressPrefix === '0.0.0.0/0' ? 'any IP' : sourceAddressPrefix);
                            if (firewallRule['ports']) {
                                firewallRule['ports'].forEach((portRange) => {
                                    if (portRange.includes("-")) {
                                        portRange = portRange.split("-");
                                        let startPort = portRange[0];
                                        let endPort = portRange[1];
                                        if (parseInt(startPort) < port && parseInt(endPort) > port) {
                                            var string = `` + (protocol === '*' ? `All protocols` : protocol.toUpperCase()) +
                                                ` port ` + port + ` open to ` + sourcefilter; strings.push(string);
                                            if (strings.indexOf(string) === -1) strings.push(string);
                                            found = true;
                                        }
                                    } else if (parseInt(portRange) === port) {
                                        var string = `` + (protocol === '*' ? `All protocols` : protocol.toUpperCase()) +
                                            ` port ` + port + ` open to ` + sourcefilter;
                                        if (strings.indexOf(string) === -1) strings.push(string);
                                        found = true;
                                    }
                                });
                            }
                        }
                    }
                }
            }
        }
        if (strings.length) {
            shared.addResult(results, 2,
                'Firewall Rule:(' + sgroups.name +
                ') has ' + service + ': ' + strings.join(' and '), location,
                resource);
        }
    }

    if (!found) {
        shared.addResult(results, 0, 'No public open ports found', location);
    }
}

function findOpenAllPorts(ngs, location, results) {
    let found = false;
    let protocols = {'tcp': '*', 'udp' : '*'};
    for (let sgroups of ngs) {
        let strings = [];
        let resource = sgroups.id;
        if (sgroups.allowed && sgroups.allowed.length) {
            let firewallRules = sgroups.allowed;
            let sourceAddressPrefix = sgroups.sourceRanges;

            if (!sourceAddressPrefix || !sourceAddressPrefix.length) continue;

            for (let firewallRule of firewallRules) {
                for (let protocol in protocols) {
                    if (sgroups['direction'] && (sgroups['direction'] === 'INGRESS') &&
                        firewallRule['IPProtocol'] && (firewallRule['IPProtocol'] === protocol) &&
                        !sgroups['disabled'] &&
                        sourceAddressPrefix &&
                        (sourceAddressPrefix.includes('*') || sourceAddressPrefix.includes('') || sourceAddressPrefix.includes('0.0.0.0/0') || sourceAddressPrefix.includes('<nw>/0') || sourceAddressPrefix.includes('/0') || sourceAddressPrefix.includes('internet'))) {
                        if (firewallRule['ports']) {
                            firewallRule['ports'].forEach((portRange) => {
                                if (portRange.includes("-")) {
                                    portRange = portRange.split("-");
                                    let startPort = portRange[0];
                                    let endPort = portRange[1];
                                    if (parseInt(startPort) === 0 && parseInt(endPort) === 65535) {
                                        var string = 'all ports open to the public';
                                        if (strings.indexOf(string) === -1) strings.push(string);
                                        found = true;
                                    }
                                } else if (portRange === 'all') {
                                    var string = 'all ports open to the public';
                                    if (strings.indexOf(string) === -1) strings.push(string);
                                    found = true;
                                }
                            });
                        }
                    } else if (sgroups['direction'] && (sgroups['direction'] === 'INGRESS') &&
                        firewallRule['IPProtocol'] && (firewallRule['IPProtocol'] === 'all') &&
                        !sgroups['disabled'] &&
                        sourceAddressPrefix &&
                        (sourceAddressPrefix.includes('*') || sourceAddressPrefix.includes('') || sourceAddressPrefix.includes('0.0.0.0/0') || sourceAddressPrefix.includes('<nw>/0') || sourceAddressPrefix.includes('/0') || sourceAddressPrefix.includes('internet'))) {
                        var string = 'all ports open to the public';
                        if (strings.indexOf(string) === -1) strings.push(string);
                        found = true;

                    }
                }
            }
        }
        if (strings.length) {
            shared.addResult(results, 2,
                'Firewall Rule:(' + sgroups.name +
                ') has ' + strings.join(' and '), location,
                resource);
        }
    }

    if (!found) {
        shared.addResult(results, 0, 'No public open ports found', location);
    }
}

function hasBuckets(buckets){
    if(buckets.length &&
        Object.keys(buckets[0]).length>1) {
        return true;
    } else {
        return false;
    }
}

module.exports = {
    addResult: addResult,
    findOpenPorts: findOpenPorts,
    findOpenAllPorts: findOpenAllPorts,
    hasBuckets: hasBuckets
};
