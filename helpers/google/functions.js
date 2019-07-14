var shared = require(__dirname + '/../shared.js');


function addResult(results, status, message, region, resource, custom){
    // Override unknown results for regions that are opt-in
        results.push({
            status: status,
            message: message,
            region: region || 'global',
            resource: resource || null,
            custom: custom || false
        });
}

function findOpenPorts(ngs, protocols, service, location, results) {
    let found = false;
    for (let sgroups of ngs) {
        let strings = [];
        let resource = sgroups.id;
        if (sgroups.allowed) {
            let firewallRules = sgroups.allowed;
            let sourceAddressPrefix = sgroups.sourceRanges;
            for (let firewallRule of firewallRules) {
                for (let protocol in protocols) {
                    let ports = protocols[protocol];
                    
                    for (let port of ports) {
                        if (sgroups['direction'] === 'INGRESS' && 
                        firewallRule['IPProtocol'] === protocol && 
                        sgroups['disabled'] === false &&
                        (sourceAddressPrefix.includes('*') || sourceAddressPrefix.includes('') || sourceAddressPrefix.includes('0.0.0.0/0') || sourceAddressPrefix.includes('<nw>/0') || sourceAddressPrefix.includes('/0') || sourceAddressPrefix.includes('internet'))) {
                            sourcefilter = (sourceAddressPrefix == '0.0.0.0/0' ? 'any IP' : sourceAddressPrefix);
                            if (firewallRule['ports']) {
                                firewallRule['ports'].forEach((portRange) => {
                                    if (portRange.includes("-")) {
                                        portRange = portRange.split("-");
                                        let startPort = portRange[0];
                                        let endPort = portRange[1];
                                        if (parseInt(startPort) < port && parseInt(endPort) > port) {
                                            var string = `` + (protocol == '*' ? `All protocols` : protocol.toUpperCase()) +
                                            ` port ` + port + ` open to ` + sourcefilter; strings.push(string);
                                            if (strings.indexOf(string) === -1) strings.push(string);
                                            found = true;
                                        }
                                    } else if (portRange == port) {
                                        var string = `` + (protocol == '*' ? `All protocols` : protocol.toUpperCase()) +
                                        ` port ` + port + ` open to ` + sourcefilter;
                                        if (strings.indexOf(string) === -1) strings.push(string);
                                        found = true;
                                    }
                                })
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

    return;
}

module.exports = {
    addResult: addResult,
    findOpenPorts: findOpenPorts,
};