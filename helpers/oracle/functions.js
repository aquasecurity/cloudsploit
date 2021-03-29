var shared = require(__dirname + '/../shared.js');

var ipProtocol = {
    "tcp" : {
        "id" : '6',
        "name" : "TCP",
        "protocol" : "Transmission Control"
    },
    "icmp" : {
        "id" : '1',
        "name" : "ICMP",
        "protocol" : "Internet Control Message"
    },
    "udp" : {
        "id" : '17',
        "name" : "UDP",
        "protocol" : "User Datagram"
    }
};

function findOpenPorts(groups, ports, service, region, results, isSecurityRule, securityGroups) {
    var found = false;
    if (isSecurityRule) {
        for (var p in groups) {
            var messages = [];
            var permission = groups[p];
            if (permission.isValid &&
                permission.direction &&
                permission.direction == "INGRESS" &&
                permission.sourceType &&
                permission.sourceType == "CIDR_BLOCK" &&
                permission.tcpOptions &&
                permission.source === '0.0.0.0/0') {
                for (var portIndex in ports) {
                    var port = ports[portIndex];

                    if (portIndex == 'tcp' &&
                        permission.tcpOptions &&
                        permission.tcpOptions.destinationPortRange &&
                        permission.tcpOptions.destinationPortRange.min &&
                        permission.tcpOptions.destinationPortRange.max &&
                        permission.tcpOptions.destinationPortRange.min <= port[0] &&
                        permission.tcpOptions.destinationPortRange.max >= port[0]) {
                        var message = portIndex.toUpperCase() +
                            ' port ' + port + ' open to 0.0.0.0/0';
                        if (messages.indexOf(message) === -1) messages.push(message);
                        found = true;
                    }
                }
            } else if (permission.isValid &&
                permission.direction &&
                permission.direction == "INGRESS" &&
                permission.sourceType &&
                permission.sourceType == "CIDR_BLOCK" &&
                permission.udpOptions &&
                permission.source === '0.0.0.0/0') {
                for (portIndex in ports) {
                    var port = ports[portIndex];

                    if (portIndex == 'udp' &&
                        permission.udpOptions &&
                        permission.udpOptions.destinationPortRange &&
                        permission.udpOptions.destinationPortRange.min &&
                        permission.udpOptions.destinationPortRange.max &&
                        permission.udpOptions.destinationPortRange.min <= port[0] &&
                        permission.udpOptions.destinationPortRange.max >= port[0]) {
                        var message = portIndex.toUpperCase() +
                            ' port ' + port + ' open to 0.0.0.0/0';
                        if (messages.indexOf(message) === -1) messages.push(message);
                        found = true;
                    }
                }
            }

            if (permission.isValid &&
                permission.direction &&
                permission.direction == "INGRESS" &&
                permission.sourceType &&
                permission.sourceType == "CIDR_BLOCK" &&
                permission.tcpOptions &&
                permission.source === '::/0') {
                for (portIndex in ports) {
                    var port = ports[portIndex];

                    if (portIndex == 'udp' &&
                        permission.tcpOptions &&
                        permission.tcpOptions.destinationPortRange &&
                        permission.tcpOptions.destinationPortRange.min &&
                        permission.tcpOptions.destinationPortRange.max &&
                        permission.tcpOptions.destinationPortRange.min <= port[0] &&
                        permission.tcpOptions.destinationPortRange.max >= port[0]) {
                        var message = portIndex.toUpperCase() +
                            ' port ' + port + ' open to ::/0';
                        if (messages.indexOf(message) === -1) messages.push(message);
                        found = true;
                    }
                }
            } else if (permission.isValid &&
                permission.direction &&
                permission.direction == "INGRESS" &&
                permission.sourceType &&
                permission.sourceType == "CIDR_BLOCK" &&
                permission.udpOptions &&
                permission.source === '::/0') {
                for (portIndex in ports) {
                    var port = ports[portIndex];

                    if (portIndex == 'udp' &&
                        permission.udpOptions &&
                        permission.udpOptions.destinationPortRange &&
                        permission.udpOptions.destinationPortRange.min &&
                        permission.udpOptions.destinationPortRange.max &&
                        permission.udpOptions.destinationPortRange.min <= port[0] &&
                        permission.udpOptions.destinationPortRange.max >= port[0]) {
                        var message = portIndex.toUpperCase() +
                            ' port ' + port + ' open to ::/0';
                        if (messages.indexOf(message) === -1) messages.push(message);
                        found = true;
                    }
                }
            }

            if (messages.length) {
                if (securityGroups &&
                    securityGroups.data.find(group=> group.id == groups[p].networkSecurityGroups)) {
                    var securityGroupName = securityGroups.data.find(group=> group.id == groups[p].networkSecurityGroups).displayName;
                }
                shared.addResult(results, 2,
                    'The Security Group: ' + (securityGroupName ? securityGroupName : groups[p].networkSecurityGroups) +
                    ' has ' + service + ': ' + messages.join(' and '), region, groups[p].networkSecurityGroups);
            }

        }
    } else {
        for (g in groups) {
            var messages = [];
            var sgroups = groups[g];

            var resource = sgroups.id;

            for (p in sgroups.ingressSecurityRules) {
                var permission = sgroups.ingressSecurityRules[p];
                if (permission.tcpOptions && permission.source === '0.0.0.0/0') {
                    for (var portIndex in ports) {
                        var port = ports[portIndex];

                        if (portIndex == 'tcp' &&
                            permission.tcpOptions &&
                            permission.tcpOptions.destinationPortRange &&
                            permission.tcpOptions.destinationPortRange.min &&
                            permission.tcpOptions.destinationPortRange.max &&
                            permission.tcpOptions.destinationPortRange.min <= port[0] &&
                            permission.tcpOptions.destinationPortRange.max >= port[0]) {
                            var message = portIndex.toUpperCase() +
                                ' port ' + port + ' open to 0.0.0.0/0';
                            if (messages.indexOf(message) === -1) messages.push(message);
                            found = true;
                        }
                    }
                } else if (permission.udpOptions && permission.source === '0.0.0.0/0') {
                    for (portIndex in ports) {
                        var port = ports[portIndex];

                        if (portIndex == 'udp' &&
                            permission.udpOptions &&
                            permission.udpOptions.destinationPortRange &&
                            permission.udpOptions.destinationPortRange.min &&
                            permission.udpOptions.destinationPortRange.max &&
                            permission.udpOptions.destinationPortRange.min <= port[0] &&
                            permission.udpOptions.destinationPortRange.max >= port[0]) {
                            var message = portIndex.toUpperCase() +
                                ' port ' + port + ' open to 0.0.0.0/0';
                            if (messages.indexOf(message) === -1) messages.push(message);
                            found = true;
                        }
                    }
                }

                if (permission.tcpOptions && permission.source === '::/0') {
                    for (portIndex in ports) {
                        var port = ports[portIndex];

                        if (portIndex == 'udp' &&
                            permission.tcpOptions &&
                            permission.tcpOptions.destinationPortRange &&
                            permission.tcpOptions.destinationPortRange.min &&
                            permission.tcpOptions.destinationPortRange.max &&
                            permission.tcpOptions.destinationPortRange.min <= port[0] &&
                            permission.tcpOptions.destinationPortRange.max >= port[0]) {
                            var message = portIndex.toUpperCase() +
                                ' port ' + port + ' open to ::/0';
                            if (messages.indexOf(message) === -1) messages.push(message);
                            found = true;
                        }
                    }
                } else if (permission.udpOptions && permission.source === '::/0') {
                    for (portIndex in ports) {
                        var port = ports[portIndex];

                        if (portIndex == 'udp' &&
                            permission.udpOptions &&
                            permission.udpOptions.destinationPortRange &&
                            permission.udpOptions.destinationPortRange.min &&
                            permission.udpOptions.destinationPortRange.max &&
                            permission.udpOptions.destinationPortRange.min <= port[0] &&
                            permission.udpOptions.destinationPortRange.max >= port[0]) {
                            var message = portIndex.toUpperCase() +
                                ' port ' + port + ' open to ::/0';
                            if (messages.indexOf(message) === -1) messages.push(message);
                            found = true;
                        }
                    }
                }
            }

            if (messages.length) {
                shared.addResult(results, 2,
                    'The Security List: ' + sgroups.displayName +
                    ' has ' + service + ': ' + messages.join(' and '), region,
                    resource);
            }

        }
    }
    if (!found &&
        isSecurityRule) {
        shared.addResult(results, 0, 'No open ports found in Network Security Groups', region);
    } else {
        shared.addResult(results, 0, 'No open ports found in Security Lists', region);

    }

    return;
}

function findOpenPortsAll(groups, ports, service, region, results) {
    var found = false;
    for (g in groups) {
        var messages = [];
        var sgroups = groups[g];

        var resource = sgroups.id;

        for (p in sgroups.ingressSecurityRules) {
            var permission = sgroups.ingressSecurityRules[p];
            var message;

            if (permission.protocol &&
                permission.protocol=== "all" &&
                permission.source &&
                permission.source === '0.0.0.0/0') {
                message = 'all protocols open to 0.0.0.0/0';
                if (messages.indexOf(message) === -1) messages.push(message);
                found = true;

            } else if (permission.source &&
                permission.source === '0.0.0.0/0' &&
                permission.protocol &&
                permission.protocol === ipProtocol.tcp.id &&
                (!permission.tcpOptions ||
                (permission.tcpOptions &&
                !permission.tcpOptions.destinationPortRange))) {
                message = `all ${ipProtocol.tcp.name} ports open to 0.0.0.0/0`;
                if (messages.indexOf(message) === -1) messages.push(message);
                found = true;

            } else if (permission.source &&
                permission.source === '0.0.0.0/0' &&
                permission.protocol &&
                permission.protocol === ipProtocol.udp.id &&
                (!permission.udpOptions ||
                (permission.udpOptions &&
                !permission.udpOptions.destinationPortRange))) {
                message = `all ${ipProtocol.udp.name} ports open to 0.0.0.0/0`;
                if (messages.indexOf(message) === -1) messages.push(message);
                found = true;
            }
        }

        if (messages.length) {
            shared.addResult(results, 2,
                'The Security List: ' + sgroups.displayName +
                ' has ' + service + ': ' + messages.join(' and '), region,
                resource);
        }
    }

    if (!found) {
        shared.addResult(results, 0, 'No public open ports found', region);
    }

}

function checkRegionSubscription (cache, source, results, region) {
    var regionSubscription = shared.addSource(cache, source,
        ['regionSubscription', 'list', shared.objectFirstKey(cache['regionSubscription']['list'])]);

    if (!regionSubscription || !regionSubscription.data) {
        shared.addResult(results, 0, 'Not subscribed to region', region);
        return false;
    }

    var subscribedToRegion = regionSubscription.data.find(function(rs){
        return rs.regionName == region;
    });

    if (!subscribedToRegion) {
        shared.addResult(results, 0, 'Not subscribed to region', region);
        return false;
    } else {
        return true;
    }
}

function normalizePolicyStatement(policyStatement) {
    let statement = policyStatement.toLowerCase();
    statement = statement.replace('  ', ' ');
    let statementArr = statement.split(' ');
    var statementObj = {};

    if (statementArr[1] === 'any-user') {
        statementObj['subject'] = 'any-user';
        statementObj['subjectType'] = '';
    } else {
        statementObj['subject'] = statementArr.slice(2, statementArr.indexOf('to'));
        statementObj['subject'] = statementObj['subject'].join(' ');
        statementObj['subjectType'] = statementArr[1] + ' ';
        statementObj['subject'] = statementObj['subject'].replace(',', '');
    }

    statementObj['verb'] = statementArr[statementArr.indexOf('to') + 1];
    statementObj['resourceType'] = statementArr[statementArr.indexOf('to') + 2];

    if (statementArr[statementArr.indexOf('in') + 1] === 'tenancy') {
        statementObj['location'] = statementArr[statementArr.indexOf('in') + 1]
    } else {
        statementObj['location'] = 'compartment ' + statementArr[statementArr.indexOf('in') + 2]
    }

    if (statementArr.indexOf('where') > -1) statementObj['condition'] = statementArr.slice(statementArr.indexOf('where') + 1, statementArr.length)
    return statementObj;
}

function testStatement(statementObj, resourceTypes, policyAdmins, verbs) {
    let whereNames = ['request.user.id', 'request.user.name', 'request.groups.id', 'request.group.name', 'request.networkSource.name', 'target.user.name', 'request.instance.compartment.id', 'request.ad'];

    if (resourceTypes.indexOf('all-resources') === -1) resourceTypes.push('all-resources');

    let subjectArr = statementObj['subject'].split(' ');
    policyAdmins = policyAdmins.toLowerCase();
    subjectArr.forEach(subject => {
        if (policyAdmins.indexOf(subject) > -1) subjectArr.splice(subjectArr.indexOf(subject), 1);
    })

    if (!subjectArr.length) return true;
    statementObj['subject'] = subjectArr.join(', ')

    if (verbs && verbs.indexOf(statementObj['verb']) === -1) return true;
    else if (statementObj['verb'] !== 'manage') return true;

    if (resourceTypes.indexOf(statementObj['resourceType']) === -1) return true;

    if (statementObj['condition']) {
        let passingCondition = false;
        whereNames.forEach(conditionName => {
            if (statementObj['condition'].indexOf(conditionName) > -1) {
                passingCondition = true;
            }
        })

        return passingCondition;
    }

    return false;
}
module.exports = {
    findOpenPorts: findOpenPorts,
    findOpenPortsAll: findOpenPortsAll,
    checkRegionSubscription: checkRegionSubscription,
    normalizePolicyStatement: normalizePolicyStatement,
    testStatement: testStatement
};
