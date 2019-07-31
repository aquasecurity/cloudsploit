var shared = require(__dirname + '/../shared.js');

var ipProtocol = {
    "tcp" : {
        "id" : 6,
        "name" : "TCP",
        "protocol" : "Transmission Control"
    },
    "icmp" : {
        "id" : 1,
        "name" : "ICMP",
        "protocol" : "Internet Control Message"
    }
};

function findOpenPorts(groups, ports, service, region, results) {
    var found = false;

    for (g in groups) {
        var strings = [];
        var sgroups = groups[g];

        for (sg in sgroups) {

            var resource = sgroups[sg].id;

            for (p in sgroups[sg].ingressSecurityRules) {
                var permission = sgroups[sg].ingressSecurityRules[p];
                if (permission.tcpOptions && permission.source === '0.0.0.0/0') {
                    for (portIndex in ports) {
                        var port = ports[portIndex];

                        if (permission.tcpOptions && permission.tcpOptions.destinationPortRange &&
                            permission.tcpOptions.destinationPortRange.min <= port[0] && permission.tcpOptions.destinationPortRange.max >= port[0]) {
                            var string = portIndex.toUpperCase() +
                                ' port ' + port + ' open to 0.0.0.0/0';
                            if (strings.indexOf(string) === -1) strings.push(string);
                            found = true;
                        }
                    }
                }

                if (permission.tcpOptions && permission.source === '::/0') {
                    for (portIndex in ports) {
                        var port = ports[portIndex];

                        if (permission.tcpOptions && permission.tcpOptions.destinationPortRange &&
                            permission.tcpOptions.destinationPortRange.min <= port[0] && permission.tcpOptions.destinationPortRange.max >= port[0]) {
                            var string = portIndex.toUpperCase() +
                                ' port ' + port + ' open to ::/0';
                            if (strings.indexOf(string) === -1) strings.push(string);
                            found = true;
                        }
                    }
                }
            }

            if (strings.length) {
                shared.addResult(results, 2,
                    'Security group: ' + sgroups[sg].id +
                    ' (' + sgroups[sg].displayName +
                    ') has ' + service + ': ' + strings.join(' and '), region,
                    resource);
            }
        }
    }

    if (!found) {
        shared.addResult(results, 0, 'No public open ports found', region);
    }

    return;
}

function findOpenPortsAll(groups, ports, service, region, results) {
    var found = false;

    for (g in groups) {
        var strings = [];
        var sgroups = groups[g];

        for (sg in sgroups) {

            var resource = sgroups[sg].id;

            for (p in sgroups[sg].ingressSecurityRules) {
                var permission = sgroups[sg].ingressSecurityRules[p];

                if (permission.protocol && permission.protocol=="all" && permission.source === '0.0.0.0/0') {
                    var string = portIndex.toUpperCase() +
                        ' all protocols open to 0.0.0.0/0';
                    if (strings.indexOf(string) === -1) strings.push(string);
                    found = true;
                }

                if (permission.protocol && permission.protocol=="all" && permission.source === '::/0') {
                    var string = portIndex.toUpperCase() +
                        ' all protocols open to ::/0';
                    if (strings.indexOf(string) === -1) strings.push(string);
                    found = true;
                }

                if (permission.tcpOptions && permission.source === '0.0.0.0/0') {
                    if (permission.tcpOptions && !permission.tcpOptions.destinationPortRange) {
                        var string = portIndex.toUpperCase() +
                            ' all ports open to 0.0.0.0/0';
                        if (strings.indexOf(string) === -1) strings.push(string);
                        found = true;
                    }
                }

                if (permission.tcpOptions && permission.source === '::/0') {
                    if (permission.tcpOptions && !permission.tcpOptions.destinationPortRange) {
                        var string = portIndex.toUpperCase() +
                            ' all ports open to ::/0';
                        if (strings.indexOf(string) === -1) strings.push(string);
                        found = true;
                    }
                }
            }

            if (strings.length) {
                shared.addResult(results, 2,
                    'Security group: ' + sgroups[sg].id +
                    ' (' + sgroups[sg].displayName +
                    ') has ' + service + ': ' + strings.join(' and '), region,
                    resource);
            }
        }
    }

    if (!found) {
        shared.addResult(results, 0, 'No public open ports found', region);
    }

    return;
}

function checkRegionSubscription (cache, source, results, region) {
    var regionSubscription = shared.addSource(cache, source,
        ['regionSubscription', 'list', shared.objectFirstKey(cache['regionSubscription']['list'])]);

    var subscribedToRegion = regionSubscription.data.find(function(rs){
        return rs.regionName == region;
    });

    if (!subscribedToRegion) {
        shared.addResult(results, 0,
            'Not subscribed to region', region);
        return false;
    } else {
        return true;
    }
}

module.exports = {
    findOpenPorts: findOpenPorts,
    findOpenPortsAll: findOpenPortsAll,
    checkRegionSubscription: checkRegionSubscription
};
