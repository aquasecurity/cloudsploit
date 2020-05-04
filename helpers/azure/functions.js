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

function checkPolicyAssignment(policyAssignments, param, text, results, location) {
    if (!policyAssignments) return;

    if (policyAssignments.err || !policyAssignments.data) {
        shared.addResult(results, 3,
            'Unable to query for Policy Assignments: ' + shared.addError(policyAssignments), location);
        return;
    }

    if (!policyAssignments.data.length) {
        shared.addResult(results, 0, 'No existing Policy Assignments found', location);
        return;
    }

    const policyAssignment = policyAssignments.data.find((policyAssignment) => {
        return (policyAssignment.displayName &&
            policyAssignment.displayName.includes("ASC Default")) ||
            (policyAssignment.displayName &&
                policyAssignment.displayName.includes("ASC default"));
    });

    if (!policyAssignment) {
        shared.addResult(results, 0,
            'There are no ASC Default Policy Assignments', location);
        return;
    }

    if (policyAssignment.parameters &&
        policyAssignment.parameters[param] &&
        policyAssignment.parameters[param].value &&
        (policyAssignment.parameters[param].value == 'AuditIfNotExists' || policyAssignment.parameters[param].value == 'Audit')) {
        shared.addResult(results, 0,
            text + ' is enabled', location, policyAssignment.id);
    } else {
        shared.addResult(results, 2,
            text + ' is disabled', location, policyAssignment.id);
    }
}

function checkLogAlerts(activityLogAlerts, conditionResource, text, results, location) {
    if (!activityLogAlerts) return;

    if (activityLogAlerts.err || !activityLogAlerts.data) {
        shared.addResult(results, 3,
            'Unable to query for Activity Alerts: ' + shared.addError(activityLogAlerts), location);
        return;
    }

    if (!activityLogAlerts.data.length) {
        shared.addResult(results, 2, 'No existing Activity Alerts found', location);
        return;
    }

    let alertCreateUpdateEnabled = false;
    let alertDeleteEnabled = false;
    let alertCreateDeleteEnabled = false;
    let subscriptionId;

    for (let res in activityLogAlerts.data) {
        const activityLogAlertResource = activityLogAlerts.data[res];
        subscriptionId = "/subscriptions/" + activityLogAlertResource.id.split('/')[2];

        if (activityLogAlertResource.type &&
            activityLogAlertResource.type.toLowerCase() !== 'Microsoft.Insights/ActivityLogAlerts'.toLowerCase()) continue;

        const allConditions = activityLogAlertResource.condition;

        if (!allConditions || !allConditions.allOf || !allConditions.allOf.length) continue;


        var conditionOperation = allConditions.allOf.filter((d) => {
            return (d.equals && d.equals.toLowerCase().indexOf(conditionResource) > -1);
        });
        if (conditionOperation && conditionOperation.length) {
            allConditions.allOf.forEach(condition => {
                if (condition.field && (condition.field === 'resourceType') && (condition.equals && (condition.equals.toLowerCase() === conditionResource))) {
                    alertCreateDeleteEnabled = (!alertCreateDeleteEnabled && activityLogAlertResource.enabled ? true : alertCreateDeleteEnabled);
                } else if (condition.equals.toLowerCase().indexOf(conditionResource + "/write") > -1) {
                    alertCreateUpdateEnabled = (!alertCreateUpdateEnabled && activityLogAlertResource.enabled ? true : alertCreateUpdateEnabled);
                } else
                if (condition.equals.toLowerCase().indexOf(conditionResource + "/delete") > -1) {
                    alertDeleteEnabled = (!alertDeleteEnabled && activityLogAlertResource.enabled ? true : alertDeleteEnabled);
                }
            })
        }
    }

    if ((alertCreateDeleteEnabled && alertDeleteEnabled && alertCreateUpdateEnabled) ||
        (alertCreateUpdateEnabled && alertDeleteEnabled) ||
        (alertCreateDeleteEnabled && !alertDeleteEnabled && !alertCreateUpdateEnabled)) {
        shared.addResult(results, 0,
            `Log Alert for ${text} write and delete is enabled`, location, subscriptionId);
    } else if ((alertCreateDeleteEnabled && alertDeleteEnabled) ||
        (alertDeleteEnabled && !alertCreateUpdateEnabled && !alertCreateDeleteEnabled)) {
        shared.addResult(results, 0,
            `Log alert for ${text} delete is enabled`, location, subscriptionId);
        shared.addResult(results, 2,
            `Log alert for ${text} write is not enabled`, location, subscriptionId);
    } else if ((alertCreateDeleteEnabled && alertCreateUpdateEnabled) ||
        (alertCreateUpdateEnabled && !alertCreateDeleteEnabled && !alertDeleteEnabled)) {
        shared.addResult(results, 0,
            `Log alert for ${text} write is enabled`, location, subscriptionId);
        shared.addResult(results, 2,
            `Log Alert for ${text} delete is not enabled`, location, subscriptionId);
    } else {
        shared.addResult(results, 2,
            `Log Alert for ${text} write and delete is not enabled`, location, subscriptionId);
    }
}

module.exports = {
    findOpenPorts: findOpenPorts,
    checkPolicyAssignment: checkPolicyAssignment,
    checkLogAlerts: checkLogAlerts
};