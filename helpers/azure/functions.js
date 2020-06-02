var shared = require(__dirname + '/../shared.js');

function addResult(results, status, message, region, resource, custom) {
    // Override unknown results for known error messages
    if (status == 3 && message && typeof message == 'string') {
        var overrideMsg;
        var skipStatusChange = false;

        if (message.indexOf('The requested operation is not implemented') > -1) {
            overrideMsg = 'Azure does not yet support this resource and method in this location.';
        } else if (message.indexOf('The specified account is disabled') > -1) {
            overrideMsg = 'This resource is disabled for this functionality in this location.';
        } else if (message.indexOf('is not supported for the account') > -1) {
            overrideMsg = 'This resource type is not supported for this query.';
        } else if (message.indexOf('ENOTFOUND') > -1) {
            overrideMsg = 'This endpoint is not supported for this resource.';
        } else if (message.indexOf('No registered resource provider found') > -1) {
            overrideMsg = 'Azure does not support this check in this location.';
        } else if (message.indexOf('using Storage Account SAS') > -1) {
            overrideMsg = 'Aqua does not have permission to list storage account keys. For help fixing this error, see: https://bit.ly/2AhlVP0';
            skipStatusChange = true;
        } else if (message.indexOf('list permission on key vault') > -1) {
            overrideMsg = 'Aqua does not have permission to list objects in this Key Vault. For help fixing this error, see: https://bit.ly/3cbpFyL';
            skipStatusChange = true;
        }

        if (overrideMsg) {
            status = skipStatusChange ? status : 0;
            message = overrideMsg;
        }
    }

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
    var openPrefix = ['*', '0.0.0.0', '<nw/0>', '/0', 'internet'];
    for (let sGroups of ngs) {
        let strings = [];
        let resource = sGroups.id;
        let securityRules = sGroups.securityRules;
        var sourceFilter;
        for (let securityRule of securityRules) {
            if (!securityRule.properties) continue;
            let sourceAddressPrefix = securityRule.properties['sourceAddressPrefix'];
            let sourceAddressPrefixes = securityRule.properties['sourceAddressPrefixes'];
            if (!sourceAddressPrefixes || !sourceAddressPrefixes.length) {
                sourceAddressPrefixes = [];
            }
            sourceAddressPrefixes.push(sourceAddressPrefix);
            var sourceFound = false;

            for (let source of sourceAddressPrefixes) {
                if (openPrefix.indexOf(source) > -1) {
                    sourceFilter = openPrefix[openPrefix.indexOf(source)];
                    sourceFound = true;
                    break;
                }
            }
            if (sourceFound) {
                for (let protocol in protocols) {
                    let ports = protocols[protocol];
                    for (let port of ports) {
                        if (securityRule.properties['access'] &&
                            securityRule.properties['access'] === 'Allow' &&
                            securityRule.properties['direction'] &&
                            securityRule.properties['direction'] === 'Inbound' &&
                            securityRule.properties['protocol'] &&
                            securityRule.properties['protocol'] === protocol) {
                            if (securityRule.properties['destinationPortRange']) {
                                if (securityRule.properties['destinationPortRange'].toString().indexOf("-") > -1) {
                                    let portRange = securityRule.properties['destinationPortRange'].split("-");
                                    let startPort = portRange[0];
                                    let endPort = portRange[1];
                                    if (parseInt(startPort) < port && parseInt(endPort) > port) {
                                        var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol == '*' ? `All protocols` : protocol.toUpperCase()) +
                                            ` port ` + ports + ` open to ` + sourceFilter;
                                        strings.push(string);
                                        if (strings.indexOf(string) === -1) strings.push(string);
                                        found = true;
                                    }
                                } else if (securityRule.properties['destinationPortRange'].toString().indexOf(port) > -1) {
                                    var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol == '*' ? `All protocols` : protocol.toUpperCase()) +
                                        (ports == '*' ? ` and all ports` : ` port ` + ports) + ` open to ` + sourceFilter;
                                    if (strings.indexOf(string) === -1) strings.push(string);
                                    found = true;
                                }
                            } else if (securityRule.properties['destinationPortRanges'] &&
                                securityRule.properties['destinationPortRanges'].toString().indexOf(port) > -1) {
                                var string = `Security Rule "` + securityRule['name'] + `": ` + (protocol == '*' ? `All protocols` : protocol.toUpperCase()) +
                                    ` port ` + ports + ` open to ` + sourceFilter;
                                if (strings.indexOf(string) === -1) strings.push(string);
                                found = true;
                            }
                        }
                    }
                }
            }
        }
        if (strings.length) {
            addResult(results, 2,
                'Security group:(' + sGroups.name +
                ') has ' + service + ': ' + strings.join(' and '), location,
                resource);
        }
    }

    if (!found) {
        addResult(results, 0, 'No public open ports found', location);
    }

    return;
}

function checkPolicyAssignment(policyAssignments, param, text, results, location) {
    if (!policyAssignments) return;

    if (policyAssignments.err || !policyAssignments.data) {
        addResult(results, 3,
            'Unable to query for Policy Assignments: ' + shared.addError(policyAssignments), location);
        return;
    }

    if (!policyAssignments.data.length) {
        addResult(results, 0, 'No existing Policy Assignments found', location);
        return;
    }

    const policyAssignment = policyAssignments.data.find((policyAssignment) => {
        return (policyAssignment && 
                policyAssignment.displayName &&
                policyAssignment.displayName.toLowerCase().includes('asc default'));
    });

    if (!policyAssignment) {
        addResult(results, 0,
            'There are no ASC Default Policy Assignments', location);
        return;
    }

    if (policyAssignment.parameters &&
        policyAssignment.parameters[param] &&
        policyAssignment.parameters[param].value &&
        (policyAssignment.parameters[param].value == 'AuditIfNotExists' || policyAssignment.parameters[param].value == 'Audit')) {
        addResult(results, 0,
            text + ' is enabled', location, policyAssignment.id);
    } else {
        addResult(results, 2,
            text + ' is disabled', location, policyAssignment.id);
    }
}

function checkLogAlerts(activityLogAlerts, conditionResource, text, results, location) {
    if (!activityLogAlerts) return;

    if (activityLogAlerts.err || !activityLogAlerts.data) {
        addResult(results, 3,
            'Unable to query for Activity Alerts: ' + shared.addError(activityLogAlerts), location);
        return;
    }

    if (!activityLogAlerts.data.length) {
        addResult(results, 2, 'No existing Activity Alerts found', location);
        return;
    }

    let alertCreateUpdateEnabled = false;
    let alertDeleteEnabled = false;
    let alertCreateDeleteEnabled = false;
    let subscriptionId;

    for (let res in activityLogAlerts.data) {
        const activityLogAlertResource = activityLogAlerts.data[res];
        subscriptionId = '/subscriptions/' + activityLogAlertResource.id.split('/')[2];

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
                } else if (condition.equals.toLowerCase().indexOf(conditionResource + '/write') > -1) {
                    alertCreateUpdateEnabled = (!alertCreateUpdateEnabled && activityLogAlertResource.enabled ? true : alertCreateUpdateEnabled);
                } else
                if (condition.equals.toLowerCase().indexOf(conditionResource + '/delete') > -1) {
                    alertDeleteEnabled = (!alertDeleteEnabled && activityLogAlertResource.enabled ? true : alertDeleteEnabled);
                }
            })
        }
    }

    if ((alertCreateDeleteEnabled && alertDeleteEnabled && alertCreateUpdateEnabled) ||
        (alertCreateUpdateEnabled && alertDeleteEnabled) ||
        (alertCreateDeleteEnabled && !alertDeleteEnabled && !alertCreateUpdateEnabled)) {
        addResult(results, 0,
            `Log Alert for ${text} write and delete is enabled`, location, subscriptionId);
    } else if ((alertCreateDeleteEnabled && alertDeleteEnabled) ||
        (alertDeleteEnabled && !alertCreateUpdateEnabled && !alertCreateDeleteEnabled)) {
        addResult(results, 0,
            `Log alert for ${text} delete is enabled`, location, subscriptionId);
        addResult(results, 2,
            `Log alert for ${text} write is not enabled`, location, subscriptionId);
    } else if ((alertCreateDeleteEnabled && alertCreateUpdateEnabled) ||
        (alertCreateUpdateEnabled && !alertCreateDeleteEnabled && !alertDeleteEnabled)) {
        addResult(results, 0,
            `Log alert for ${text} write is enabled`, location, subscriptionId);
        addResult(results, 2,
            `Log Alert for ${text} delete is not enabled`, location, subscriptionId);
    } else {
        addResult(results, 2,
            `Log Alert for ${text} write and delete is not enabled`, location, subscriptionId);
    }
}

function checkAppVersions(webConfigs, results, location, webAppId, checkProp, allowedProp, name, custom) {
    var found = false;
    if (!webConfigs || webConfigs.err || !webConfigs.data) {
        addResult(results, 3,
            'Unable to query App Service: ' + shared.addError(webConfigs),
            location, webAppId);
    } else {
        if (webConfigs.data[0] &&
            webConfigs.data[0][checkProp] &&
            webConfigs.data[0][checkProp] !== '') {
            found = true;
            var version = parseFloat(webConfigs.data[0][checkProp].replace(/[^\d.-]/g, ''));
            var allowedVersion = parseFloat(allowedProp);

            if (Math.fround(version) >= Math.fround(allowedVersion)) {
                addResult(results, 0,
                    `The ${name} version (${webConfigs.data[0][checkProp]}) is the latest version`, location, webAppId, custom);
            } else {
                addResult(results, 2,
                    `The ${name} version (${webConfigs.data[0][checkProp]}) is not the latest version`, location, webAppId, custom);
            }
        }
    }
    return found;
}

function checkServerConfigs(servers, cache, source, location, results, serverType, configProperty, configName) {
    if (!servers) return;

    if (servers.err || !servers.data) {
        addResult(results, 3,
            'Unable to query for ' + serverType + ' Servers: ' + shared.addError(servers), location);
        return;
    }

    if (!servers.data.length) {
        addResult(results, 0, 'No existing ' + serverType + ' Servers found', location);
        return;
    }
    
    servers.data.forEach(function(server) {
        const configurations = shared.addSource(cache, source,
            ['configurations', 'listByServer', location, server.id]);

        if (!configurations || configurations.err || !configurations.data) {
            addResult(results, 3,
                'Unable to query for ' + serverType + ' Server configuration: ' + shared.addError(configurations), location, server.id);
        } else {
            var configuration = configurations.data.filter(config => {
                return (config.name == configProperty && config.value.toLowerCase() == 'on');
            });

            if (configuration && configuration.length) {
                addResult(results, 0, configName + ' is enabled for the ' + serverType + ' Server configuration', location, server.id);
            } else {
                addResult(results, 2, configName + ' is disabled for the ' + serverType + ' Server configuration', location, server.id);
            }
        }
    });
}

module.exports = {
    addResult: addResult,
    findOpenPorts: findOpenPorts,
    checkPolicyAssignment: checkPolicyAssignment,
    checkLogAlerts: checkLogAlerts,
    checkAppVersions: checkAppVersions,
    checkServerConfigs: checkServerConfigs
};