var shared = require(__dirname + '/../shared.js');

function findOpenPorts(ngs, protocols, service, location, results) {
    let found = false;

    for (let sgroups of ngs) {
        let strings = [];
        let resource = sgroups.id;
        let securityRules = sgroups.securityRules;
        for (let securityRule of securityRules) {
            let sourceAddressPrefix = securityRule['sourceAddressPrefix'];

            for (let protocol in protocols) {
                let ports = protocols[protocol];

                for (let port of ports) {
                    if (securityRule['access'] === 'Allow'
                        && securityRule['direction'] === 'Inbound'
                        && securityRule['protocol'] === protocol
                        && (sourceAddressPrefix === '*' || sourceAddressPrefix === '' || sourceAddressPrefix === '0.0.0.0' || sourceAddressPrefix === '<nw>/0' || sourceAddressPrefix === '/0' || sourceAddressPrefix === 'internet')) {

                        sourcefilter = (sourceAddressPrefix == '*' ? 'any IP' : sourceAddressPrefix);

                        if (securityRule['destinationPortRange']) {
                            if (securityRule['destinationPortRange'].toString().indexOf("-") > -1) {
                                let portRange = securityRule['destinationPortRange'].split("-");
                                let startPort = portRange[0];
                                let endPort = portRange[1];
                                if (parseInt(startPort) < port && parseInt(endPort) > port) {
                                    var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol == '*' ? `All protocols` : protocol.toUpperCase()) +
                                        ` port ` + ports + ` open to ` + sourcefilter; strings.push(string);
                            if (strings.indexOf(string) === -1) strings.push(string);
                            found = true;
                        }
                            } else if (securityRule['destinationPortRange'].toString().indexOf(port) > -1) {
                                var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol == '*' ? `All protocols` : protocol.toUpperCase()) +
                                     (ports == '*' ? ` and all ports` : ` port ` + ports) + ` open to ` + sourcefilter;
                                if (strings.indexOf(string) === -1) strings.push(string);
                            found = true;
                    }

                        } else if (securityRule['destinationPortRanges'].toString().indexOf(port) > -1) {
                            var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol == '*' ? `All protocols` : protocol.toUpperCase()) +
                                ` port ` + ports + ` open to ` + sourcefilter;
                            if (strings.indexOf(string) === -1) strings.push(string);
                            found = true;
                        }
                    }
                }
            }
        }
        if (strings.length) {
            shared.addResult(results, 2,
                'Security group:(' + sgroups.name +
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
    findOpenPorts: findOpenPorts
};