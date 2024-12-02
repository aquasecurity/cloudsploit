var async = require('async');
var regions = require(__dirname + '/regions');
var AWS = require('aws-sdk');
var helpers = require('../shared.js');

function waitForCredentialReport(iam, callback, CREDENTIAL_DOWNLOAD_STARTED) {
    if (!CREDENTIAL_DOWNLOAD_STARTED) {
        iam.generateCredentialReport(function(err, data){
            if ((err && err.code && err.code == 'ReportInProgress') || (data && data.State)) {
                // Okay to query for credential report
                waitForCredentialReport(iam, callback, true);
            } else {
                //CREDENTIAL_REPORT_ERROR = 'Error downloading report';
                //callback(CREDENTIAL_REPORT_ERROR);
                callback('Error downloading report');
            }
        });
    } else {
        var pingCredentialReport = function(pingCb) {
            iam.getCredentialReport(function(getErr, getData) {
                if (getErr || !getData || !getData.Content) {
                    return pingCb('Error waiting for credential report: ' + (getErr ? getErr : 'No data returned from AWS after 60 seconds.'));
                }

                pingCb(null, getData);
            });
        };

        async.retry({times: 20, interval: 3000}, pingCredentialReport, function(reportErr, reportData){
            if (reportErr || !reportData) {
                //CREDENTIAL_REPORT_ERROR = 'Error downloading report';
                //return callback(CREDENTIAL_REPORT_ERROR);
                return callback('Error downloading report');
            }

            //CREDENTIAL_REPORT_DATA = reportData;
            //callback(null, CREDENTIAL_REPORT_DATA);
            callback(null, reportData);
        });
    }
}

function addResult(results, status, message, region, resource, custom){
    // Override unknown results for regions that are opt-in
    if (status == 3 && region && regions.optin.indexOf(region) > -1 && message &&
        (message.indexOf('AWS was not able to validate the provided access credentials') > -1 ||
            message.indexOf('The security token included in the request is invalid') > -1)) {
        results.push({
            status: 0,
            message: 'Region is not enabled',
            region: region,
            resource: resource || null,
            custom: custom || false
        });
    } else {
        results.push({
            status: status,
            message: message,
            region: region || 'global',
            resource: resource || null,
            custom: custom || false
        });
    }
}

function findOpenPorts(groups, ports, service, region, results, cache, config, callback, settings={}) {
    if (config.ec2_skip_unused_groups) {
        var usedGroups = getUsedSecurityGroups(cache, results, region);
        if (usedGroups && usedGroups.length && usedGroups[0] === 'Error') return callback();
    }
    var awsOrGov = defaultPartition(settings);
    for (var g in groups) {
        var string;
        var openV4Ports = [];
        var openV6Ports = [];
        var resource = `arn:${awsOrGov}:ec2:${region}:${groups[g].OwnerId}:security-group/${groups[g].GroupId}`;

        for (var p in groups[g].IpPermissions) {
            var permission = groups[g].IpPermissions[p];

            for (var k in permission.IpRanges) {
                var range = permission.IpRanges[k];

                if (range.CidrIp === '0.0.0.0/0' && ports[permission.IpProtocol]) {
                    for (var portIndex in ports[permission.IpProtocol]) {
                        var port = ports[permission.IpProtocol][portIndex];
                        if (port.toString().indexOf('-') > -1) {
                            var portRange = port.split('-');
                            var rangeFrom = Number(portRange[0]);
                            var rangeTo = Number(portRange[1]);

                            for (let i = rangeFrom; i <= rangeTo; i++) {
                                if (permission.FromPort <= i && permission.ToPort >= i) {
                                    string = `some of ${permission.IpProtocol.toUpperCase()}:${port}`;
                                    openV4Ports.push(string);
                                    break;
                                }
                            }
                        } else {
                            port = Number(port);
                            if (permission.FromPort <= port && permission.ToPort >= port) {
                                string = `${permission.IpProtocol.toUpperCase()}:${port}`;
                                if (openV4Ports.indexOf(string) === -1) openV4Ports.push(string);
                            }
                        }
                    }
                }
            }

            for (var l in permission.Ipv6Ranges) {
                var rangeV6 = permission.Ipv6Ranges[l];

                if (rangeV6.CidrIpv6 === '::/0' && ports[permission.IpProtocol]) {
                    for (var portIndexV6 in ports[permission.IpProtocol]) {
                        var portV6 = ports[permission.IpProtocol][portIndexV6];
                        if (portV6.toString().indexOf('-') > -1) {
                            var portRangeV6 = Number(portV6.split('-'));
                            var rangeFromV6 = Number(portRangeV6[0]);
                            var rangeToV6 = portRangeV6[1];

                            for (let i = rangeFromV6; i <= rangeToV6; i++) {
                                if (permission.FromPort <= i && permission.ToPort >= i) {
                                    string = `some of ${permission.IpProtocol.toUpperCase()}:${portV6}`;
                                    openV6Ports.push(string);
                                    break;
                                }
                            }
                        } else {
                            portV6 = Number(portV6);
                            if (permission.FromPort <= portV6 && permission.ToPort >= portV6) {
                                var stringV6 = `${permission.IpProtocol.toUpperCase()}:${portV6}`;
                                if (openV6Ports.indexOf(stringV6) === -1) openV6Ports.push(stringV6);
                            }
                        }
                    }
                }
            }
        }

        if (openV4Ports.length || openV6Ports.length) {
            var resultsString = '';
            if (openV4Ports.length) {
                resultsString = `Security group: ${groups[g].GroupId} (${groups[g].GroupName}) has ${service}:${openV4Ports.join(' and ')} open to 0.0.0.0/0`;
            }

            if (openV6Ports.length) {
                if (resultsString.length) {
                    resultsString = `${resultsString} and ${openV6Ports.join(' and ')} open to ::/0`;
                } else {
                    resultsString = `Security group: ${groups[g].GroupId} (${groups[g].GroupName}) has ${service}:${openV6Ports.join(' and ')} open to ::/0`;
                }
            }

            if (config.ec2_skip_unused_groups && groups[g].GroupId && (!usedGroups || !usedGroups.includes(groups[g].GroupId))) {
                addResult(results, 1, `Security Group: ${groups[g].GroupId} is not in use`,
                    region, resource);
            } else if (config.check_network_interface) {
                checkNetworkInterface(groups[g].GroupId,groups[g].GroupName, resultsString, region, results, resource, cache);
            } else {
                addResult(results, 2, resultsString,
                    region, resource);
            }
        } else {
            let strings = [];

            for (const key in ports) {
                strings.push(`${key.toUpperCase()}:${ports[key]}`);
            }

            if (strings.length){
                addResult(results, 0,
                    `Security group: ${groups[g].GroupId} (${groups[g].GroupName}) does not have ${strings.join(', ')} open to 0.0.0.0/0 or ::0`,
                    region, resource);
            }
        }
    }

    return;
}

function checkNetworkInterface(groupId, groupName, resultsString, region, results, resource, cache, bool = false) {
    const describeNetworkInterfaces = helpers.addSource(cache, {},
        ['ec2', 'describeNetworkInterfaces', region]);

    if (!describeNetworkInterfaces || describeNetworkInterfaces.err || !describeNetworkInterfaces.data) {
        if (bool) {
            return false;
        }
        helpers.addResult(results, 3,
            'Unable to query for network interfaces: ' + helpers.addError(describeNetworkInterfaces), region);
        return;
    }
    let hasOpenSecurityGroup = false;
    let networksWithSecurityGroup = [];
    for (var network of describeNetworkInterfaces.data) {
        for (const group of network.Groups) {
            if (groupId === group.GroupId) {
                networksWithSecurityGroup.push(network);
                hasOpenSecurityGroup = true;
                break;
            }
        }
    }
    if (bool && !networksWithSecurityGroup.length) {
        return groupId;
    }
    let exposedENI;
    if (hasOpenSecurityGroup) {
        let hasPublicIp = false;
        for (var eni of networksWithSecurityGroup) {
            if (eni.Association && eni.Association.PublicIp) {
                hasPublicIp = true;
                exposedENI = `sg ${groupId} > eni ${eni.NetworkInterfaceId}`;
                break;
            }
        }
        if (hasPublicIp) {
            if (bool) return exposedENI;
            addResult(results, 2, `Security Group ${groupId}(${groupName}) is associated with an ENI that is publicly exposed`, region, resource);
        } else {
            if (bool) return false;
            addResult(results, 0, `Security Group ${groupId} (${groupName}) is only exposed internally`, region, resource);
        }
    } else {
        if (bool) return false;
        addResult(results, 2, resultsString, region, resource);
    }
}
function normalizePolicyDocument(doc) {
    /*
    Convert a policy document for IAM into a normalized object that can be used
    by plugins to check policy attributes.
    Returns an array of statements with normalized effect, action, and resource.
    */

    if (typeof doc === 'string') {
        // Need to parse to JSON
        try {
            // Need to urldecode
            if (doc.charAt(0) === '%') doc = decodeURIComponent(doc);
            doc = JSON.parse(doc);
        } catch (e) {
            //Could not parse policy document into JSON
            return false;
        }
    }

    if (typeof doc !== 'object') {
        //Could not parse policy document. Not valid JSON
        return false;
    }

    if (!doc.Statement) return false;

    var statementsToReturn = [];

    // If Statement is an object, convert to array
    if (!Array.isArray(doc.Statement)) doc.Statement = [doc.Statement];

    for (var s in doc.Statement) {
        var statement = doc.Statement[s];

        if (!statement.Effect || !statement.Effect.length ||
            !statement.Action || !statement.Action.length) {
            break;
        }

        if (typeof statement.Effect !== 'string') break;

        if (!Array.isArray(statement.Action)) statement.Action = [statement.Action];
        if (statement.Resource && !Array.isArray(statement.Resource)) statement.Resource = [statement.Resource];

        statementsToReturn.push(statement);
    }

    return statementsToReturn;
}

function globalPrincipal(principal, settings={}) {
    if (!principal) return false;

    if (typeof principal === 'string' && principal === '*') {
        return true;
    }

    var awsPrincipals = principal.AWS;
    if (!Array.isArray(awsPrincipals)) {
        awsPrincipals = [awsPrincipals];
    }

    var awsOrGov = defaultPartition(settings);
    if (awsPrincipals.indexOf('*') > -1 ||
        awsPrincipals.indexOf(`arn:${awsOrGov}:iam::*`) > -1) {
        return true;
    }

    return false;
}

function userGlobalAccess(statement, restrictedPermissions) {
    if (statement.Effect && statement.Effect === 'Allow' &&
        statement.Action && restrictedPermissions.some(permission=> statement.Action.includes(permission))) {
        return true;
    }

    return false;
}

function crossAccountPrincipal(principal, accountId, fetchPrincipals, settings={}) {
    var awsOrGov = defaultPartition(settings);
    if (typeof principal === 'string' &&
        (/^[0-9]{12}$/.test(principal) || new RegExp(`^arn:${awsOrGov}:.*/`).test(principal)) &&
        !principal.includes(accountId)) {
        if (fetchPrincipals) return [principal];
        return true;
    }

    var awsPrincipals = principal.AWS;
    if (!Array.isArray(awsPrincipals)) {
        awsPrincipals = [awsPrincipals];
    }

    var principals = [];

    for (var a in awsPrincipals) {
        if (new RegExp(`^arn:${awsOrGov}:.*`).test(awsPrincipals[a]) &&
            awsPrincipals[a].indexOf(accountId) === -1) {
            if (!fetchPrincipals) return true;
            principals.push(awsPrincipals[a]);
        }
    }

    if (fetchPrincipals) return principals;
    return false;
}

function hasFederatedUserRole(policyDocument) {
    // true iff every statement refers to federated user access
    for (let statement of policyDocument) {
        if (statement.Action &&
            !statement.Action.includes('sts:AssumeRoleWithSAML') &&
            !statement.Action.includes('sts:AssumeRoleWithWebIdentity')){
            return false;
        }
    }
    return true;
}

function extractStatementPrincipals(statement) {
    let response = [];
    if (statement.Principal) {
        let principal = statement.Principal;

        if (typeof principal === 'string') {
            return [principal];
        }

        if (!principal.AWS) return response;

        var awsPrincipals = principal.AWS;
        if (!Array.isArray(awsPrincipals)) {
            awsPrincipals = [awsPrincipals];
        }

        response.push.apply(response, awsPrincipals);
    }

    return response;
}

function getDenyPermissionsMap(statements, excludeStatementId) {
    let permissionsMap = {};

    for (let statement of statements) {
        if ((statement.Sid && statement.Sid == excludeStatementId) || (statement.Effect && statement.Effect.toUpperCase() !== 'DENY')) continue;

        let principals = extractStatementPrincipals(statement);
        principals.forEach(principal => {
            let permissionsObj = JSON.parse(JSON.stringify(getDenyActionResourceMap([statement])));
            if (permissionsMap[principal]) permissionsMap[principal] = {...permissionsObj,...permissionsMap[principal]};
            else permissionsMap[principal] = permissionsObj;
        });
    }

    return permissionsMap;
}

function getDenyActionResourceMap(statements, excludeStatementId) {
    let denyActionResourceMap = {};
    for (let statement of statements) {
        if (statement.Sid && statement.Sid != excludeStatementId &&
            statement.Effect && statement.Effect == 'Deny' &&
            statement.Resource && statement.Resource.length &&
            statement.Action && statement.Action.length) {
            statement.Action.forEach(action => {
                if (denyActionResourceMap[action]) denyActionResourceMap[action].push.apply(denyActionResourceMap[action], statement.Resource);
                else denyActionResourceMap[action] = statement.Resource;
            });
        }
    }

    return denyActionResourceMap;
}

function filterDenyPermissionsByPrincipal(permissionsMap, principal) {
    let response = {};
    Object.keys(permissionsMap).forEach(key => {
        if (matchKeys(key, principal)) {
            Object.keys(permissionsMap[key]).forEach(action => {
                if (response[action]) response[action].push.apply(response[action], permissionsMap[key][action]);
                else response[action] = permissionsMap[key][action];
            });
        }
    });
    return response;
}

function isValidCondition(statement, allowedConditionKeys, iamConditionOperators, fetchConditionPrincipals, accountId, settings={}) {
    if (statement.Condition && statement.Effect) {
        var effect = statement.Effect;
        var values = [];
        var foundValid = false;

        for (var operator of Object.keys(statement.Condition)) {
            var defaultOperator = operator;
            if (operator.includes(':')) defaultOperator = operator.split(':')[1];

            var subCondition = statement.Condition[operator];
            for (var key of Object.keys(subCondition)) {
                let keyLower = key.toLowerCase();
                if (!allowedConditionKeys.find(conditionKey => conditionKey.toLowerCase() == keyLower)) continue;

                var value = subCondition[key];
                var awsOrGov = defaultPartition(settings);
                if (iamConditionOperators.string[effect].includes(defaultOperator) ||
                    iamConditionOperators.arn[effect].includes(defaultOperator)) {
                    if (keyLower === 'kms:calleraccount' && typeof value === 'string' && effect === 'Allow' &&  value === accountId) {
                        foundValid = true;
                        values.push(value);
                    } else if (/^[0-9]{12}$/.test(value) || new RegExp(`^arn:${awsOrGov}:.+`).test(value) || /^o-[a-zA-Z0-9]{10,32}$/.test(value)) {
                        foundValid = true;
                        values.push(value);
                    }
                } else if (defaultOperator === 'Bool') {
                    if ((effect === 'Allow' && value) || effect === 'Deny' && !value) foundValid = true;
                } else if (iamConditionOperators.ipaddress[effect].includes(defaultOperator)) {
                    if (value !== '0.0.0.0/0' && value !== '::/0') foundValid = true;
                }
            }
        }

        if (!foundValid) return false;
        if (fetchConditionPrincipals) return values;
    }

    return true;
}

function isEffectivePolicyStatement(statement, denyActionResourceMap) {
    let statementActionResourceMap = {};
    if (statement.Action && statement.Resource) {
        for (let action of statement.Action) {
            statementActionResourceMap[action] = statement.Resource;
        }
    }

    for (let action of Object.keys(statementActionResourceMap)) {
        for (let key of Object.keys(denyActionResourceMap)) {
            if (matchKeys(key, action)) {
                var deniedResources = [];
                for (let stmResource of statementActionResourceMap[action]) {
                    if (denyActionResourceMap[key].find(deniedResource => matchKeys(deniedResource, stmResource))) deniedResources.push(stmResource);
                }

                statementActionResourceMap[action] = statementActionResourceMap[action].filter(resource => !deniedResources.includes(resource));
            }
        }

        if (statementActionResourceMap[action].length) return true;
    }

    return false;
}

function isEffectiveStatement(statement, denyPermissionsMap) {
    var principals = extractStatementPrincipals(statement);

    for (let principal of principals) {
        let denyActionResourceMap = filterDenyPermissionsByPrincipal(denyPermissionsMap, principal);
        if (isEffectivePolicyStatement(statement, denyActionResourceMap)) return true;
    }

    return false;
}

function matchKeys(first, second) {
    if (!first.length && !second.length) return true;

    if (first.length > 1 && first[0] == '*' && !second.length) return false;

    if ((first.length > 1 && first[0] == '?') || (first.length && second.length && first[0] == second[0])) return matchKeys(first.slice(1), second.slice(1));

    if (first.length && first[0] == '*') {
        return matchKeys(first.slice(1), second) || matchKeys(first,second.slice(1));
    }

    return false;
}

function defaultRegion(settings) {
    if (settings.govcloud) return 'us-gov-west-1';
    if (settings.china) return 'cn-north-1';
    return 'us-east-1';
}

function defaultPartition(settings) {
    if (settings.govcloud) return 'aws-us-gov';
    if (settings.china) return 'aws-cn';
    return 'aws';
}

function getS3BucketLocation(cache, region, bucketName) {
    var getBucketLocation = helpers.addSource(cache, {},
        ['s3', 'getBucketLocation', region, bucketName]);

    if (getBucketLocation && getBucketLocation.data) {
        if (getBucketLocation.data.LocationConstraint &&
            regions.all.includes(getBucketLocation.data.LocationConstraint)) return getBucketLocation.data.LocationConstraint;
        else if (getBucketLocation.data.LocationConstraint &&
            !regions.all.includes(getBucketLocation.data.LocationConstraint)) return 'global';
        else return 'us-east-1';
    }

    return 'global';
}

function remediatePlugin(config, call, params, callback) {
    var service = call.split(':')[0];
    var callKey = call.split(':')[1];
    var executor = new AWS[service](config);

    var executorCb = function(err, data) {
        if (err) {
            return callback(err, null);
        } else {
            return callback(null, data);
        }
    };

    executor[callKey](params, executorCb);
}

function nullArray(object) {
    for (var key in object) {
        if (Array.isArray(object[key]) && !object[key].length) {
            object[key] = null;
        }
    }
    return object;
}

let divideArray = function(array, size) {
    var arrayOfArrays = [];
    while (array.length > 0) {
        arrayOfArrays.push(array.splice(0, size));
    }
    return arrayOfArrays;
};

function getEncryptionLevel(kmsKey, encryptionLevels) {
    if (kmsKey.Origin) {
        if (kmsKey.Origin === 'AWS_KMS') {
            if (kmsKey.KeyManager) {
                if (kmsKey.KeyManager === 'AWS') {
                    return encryptionLevels.indexOf('awskms');
                }
                if (kmsKey.KeyManager === 'CUSTOMER') {
                    return encryptionLevels.indexOf('awscmk');
                }
            }
        }
        if (kmsKey.Origin === 'EXTERNAL') {
            return encryptionLevels.indexOf('externalcmk');
        }
        if (kmsKey.Origin === 'AWS_CLOUDHSM') {
            return encryptionLevels.indexOf('cloudhsm');
        }
    }

    return encryptionLevels.indexOf('none');
}

function remediatePasswordPolicy(putCall, pluginName, remediation_file, passwordKey, config, cache, settings, resource, input, callback) {
    config.region = defaultRegion({});
    var params;
    var getAccountPasswordPolicy = helpers.addSource(cache, {},
        ['iam', 'getAccountPasswordPolicy', config.region]);

    if (!getAccountPasswordPolicy) return callback('No data found');

    let createPolicyInput = pluginName + 'CreatePolicy';

    if ((getAccountPasswordPolicy.err ||
        !getAccountPasswordPolicy.data || !Object.keys(getAccountPasswordPolicy.data).length) && (settings.input && settings.input[createPolicyInput])) {
        remediation_file['pre_remediate']['actions'][pluginName][resource] = null;
        params = {
            HardExpiry: true,
            MaxPasswordAge: '179',
            MinimumPasswordLength: '14',
            PasswordReusePrevention: '24',
            RequireLowercaseCharacters: true,
            RequireNumbers: true,
            RequireSymbols: true,
            RequireUppercaseCharacters: true
        };
        if (input && input[passwordKey]) params[passwordKey] = input[passwordKey];
    } else if (getAccountPasswordPolicy.data && Object.keys(getAccountPasswordPolicy.data).length){
        params = getAccountPasswordPolicy.data;
        remediation_file['pre_remediate']['actions'][pluginName][resource] = params;

        if (input && input[passwordKey]) params[passwordKey] = input[passwordKey];
    } else {
        return callback('No previous policy found');
    }
    // needed because this gets passed in the get call but breaks the put call
    if (params['ExpirePasswords']) delete params['ExpirePasswords'];

    // passes the config, put call, and params to the remediate helper function
    remediatePlugin(config, putCall[0], params, function(err) {
        if (err) {
            remediation_file['remediate']['actions'][pluginName]['error'] = err;
            return callback(err, null);
        }

        let action = params;
        action.action = putCall;

        remediation_file['post_remediate']['actions'][pluginName][resource] = action;
        remediation_file['remediate']['actions'][pluginName][resource] = {
            'Action': 'Enabled'
        };
        settings.remediation_file = remediation_file;
        return callback(null, action);
    });
}

function remediateOpenPorts(putCall, pluginName, protocol, port, config, cache, settings, resource, remediation_file, cb) {
    if (resource && resource.length) {
        var sgId = resource.split('/')[1];
        config.region = resource.split(':')[3];
    } else {
        return cb('No resource provided');
    }

    if (!config.region) return cb('No region found when parsing resource');
    if (!sgId) return cb('No security group name found when parsing resource');


    var describeSecurityGroups = helpers.addSource(cache, {},
        ['ec2', 'describeSecurityGroups', config.region]);

    if (!describeSecurityGroups.data || describeSecurityGroups.err) return cb('Unable to query for security groups: ' + helpers.addError(describeSecurityGroups));

    if (!describeSecurityGroups.data.length) return cb('No security groups present');

    var securityGroup = describeSecurityGroups.data.find(group => {
        return (group.GroupId && group.GroupId === sgId);
    });

    if (!securityGroup) return cb('The target security group was not found');

    remediation_file['pre_remediate']['actions'][pluginName][resource] = [];
    remediation_file['post_remediate']['actions'][pluginName][resource] = [];
    remediation_file['remediate']['actions'][pluginName][resource]['steps'] = [];
    var failingPermissions = securityGroup.IpPermissions.filter(permission => {
        return (permission.FromPort && permission.FromPort <= port && permission.ToPort && permission.ToPort >= port && permission.IpProtocol && permission.IpProtocol === protocol);
    });
    if (!failingPermissions.length) return cb();
    // because this changed to async need a way to aggregate errors and actions without stopping the whole function
    var errors = [];
    var actions = [];
    // changed this to an async function to avoid the callback already called error(was forEach loop before)
    async.each(failingPermissions,function(failingPermission, fpCb) {
        var openIpRange = false;
        var openIpv6Range = false;
        var finalIpRanges = [];
        var finalIpv6Ranges = [];
        var localIpExists = false;
        var localIpV6Exists = false;

        // these variables will hold the failing rules description
        var ipDescription;
        var ipv6Description;
        var ipv4InputKey = pluginName + 'ReplacementIpAddress';
        var ipv6InputKey = pluginName + 'ReplacementIpv6Address';

        if (failingPermission.IpRanges && failingPermission.IpRanges.length) {
            failingPermission.IpRanges.forEach(ipRange => {
                if (ipRange.CidrIp && ipRange.CidrIp === '0.0.0.0/0') {
                    openIpRange = true;
                    // Grabs the description when it identifies the failing rule
                    ipDescription = ipRange.Description ? ipRange.Description : null;
                } else if (ipRange.CidrIp && settings.input && settings.input[ipv4InputKey] && ipRange.CidrIp === settings.input[ipv4InputKey]) {
                    localIpExists = true;
                } else {
                    finalIpRanges.push(ipRange);
                }
            });
        }
        if (failingPermission.Ipv6Ranges && failingPermission.Ipv6Ranges.length) {
            failingPermission.Ipv6Ranges.forEach(ipv6Range => {
                if (ipv6Range.CidrIpv6 && ipv6Range.CidrIpv6 === '::/0') {
                    openIpv6Range = true;
                    // Grabs the description when it identifies the failing rule
                    ipv6Description = ipv6Range.Description ? ipv6Range.Description : null;
                } else if (ipv6Range.CidrIpv6 && settings.input && settings.input[ipv6InputKey] && ipv6Range.CidrIpv6 === settings.input[ipv6InputKey]) {
                    localIpV6Exists = true;
                } else {
                    finalIpv6Ranges.push(ipv6Range);
                }
            });
        }
        // changed to make this check right after getting both variables
        if (!openIpv6Range && !openIpRange) return fpCb();

        var params = {
            DryRun: false,
            GroupId: securityGroup.GroupId,
            IpPermissions: [
                {
                    IpRanges: failingPermission.IpRanges,
                    Ipv6Ranges: failingPermission.Ipv6Ranges,
                    PrefixListIds: failingPermission.PrefixListIds.length ? failingPermission.PrefixListIds : null,
                    UserIdGroupPairs: failingPermission.UserIdGroupPairs.length ? failingPermission.UserIdGroupPairs : null,
                    ToPort: failingPermission.ToPort,
                    FromPort: failingPermission.FromPort,
                    IpProtocol: failingPermission.IpProtocol,
                }
            ],
        };

        remediation_file['pre_remediate']['actions'][pluginName][resource].push(JSON.parse(JSON.stringify(params)));

        params.IpPermissions[0].Ipv6Ranges = [];
        params.IpPermissions[0].IpRanges = [];
        params.IpPermissions[0].UserIdGroupPairs = null;

        var oldIpv6Range = {CidrIpv6: '::/0'};
        var oldIpRange = {CidrIp: '0.0.0.0/0'};

        // this checks if a description was found then adds it to the new ip range


        async.series([
            function(rCb) {
                if (!settings.input || (openIpRange && (!settings.input[ipv4InputKey] || !settings.input[ipv4InputKey].length)) && (openIpv6Range && (!settings.input[ipv6InputKey] || !settings.input[ipv6InputKey].length))) return rCb();

                if (openIpRange && !localIpExists && settings.input[ipv4InputKey]) {
                    var newIpCidrRange = settings.input[ipv4InputKey].split(',');
                    for (var newIpCidr of newIpCidrRange) {
                        var newIpRange = {CidrIp: newIpCidr};
                        if (ipDescription && newIpRange) newIpRange.Description = ipDescription;
                        params.IpPermissions[0].IpRanges.push(newIpRange);
                        finalIpRanges.push(newIpRange);
                    }
                } else if (!openIpRange || (openIpRange && localIpExists) || (!settings.input[ipv4InputKey] || !settings.input[ipv4InputKey].length)) {
                    params.IpPermissions[0].IpRanges = null;
                }

                if (openIpv6Range && !localIpV6Exists && settings.input[ipv6InputKey]) {
                    var newIpv6CidrRange = settings.input[ipv6InputKey].split(',');
                    for (var newIpv6Cidr of newIpv6CidrRange) {
                        var newIpv6Range = {CidrIpv6: newIpv6Cidr};
                        if (ipv6Description && newIpv6Range) newIpv6Range.Description = ipv6Description;
                        params.IpPermissions[0].Ipv6Ranges.push(newIpv6Range);
                        finalIpv6Ranges.push(newIpv6Range);
                    }
                } else if (!openIpv6Range || (openIpv6Range && localIpV6Exists) || (!settings.input[ipv6InputKey] || !settings.input[ipv6InputKey].length)) {
                    params.IpPermissions[0].Ipv6Ranges = null;
                }

                remediatePlugin(config, putCall[0], params, function(err) {
                    if (err) {
                        errors.push(err);
                        return rCb(err);
                    } else {
                        if (openIpv6Range && !localIpV6Exists) {
                            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                                'inboundRule': '::1/128',
                                'action': 'ADDED'
                            });
                        } else if (openIpv6Range && localIpV6Exists) {
                            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                                'inboundRule': '::1/128',
                                'action': 'Already Exists'
                            });
                        }

                        if (openIpRange && !localIpExists) {
                            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                                'inboundRule': '127.0.0.1/32',
                                'action': 'ADDED'
                            });
                        } else if (openIpRange && localIpExists){
                            remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                                'inboundRule': '127.0.0.1/32',
                                'action': 'Already Exists'
                            });
                        }

                        return rCb();
                    }
                });

            },
            function(rCb) {
                if (openIpRange) {
                    params.IpPermissions[0].IpRanges = [];
                    params.IpPermissions[0].IpRanges.push(oldIpRange);
                } else {
                    params.IpPermissions[0].IpRanges = null;
                }

                if (openIpv6Range) {
                    params.IpPermissions[0].Ipv6Ranges = [];
                    params.IpPermissions[0].Ipv6Ranges.push(oldIpv6Range);
                } else {
                    params.IpPermissions[0].Ipv6Ranges = null;
                }

                remediatePlugin(config, putCall[1], params, function(err) {
                    if (err) {
                        errors.push(err);
                        return rCb(err);
                    }
                    if (openIpRange) {
                        remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                            'inboundRule': '0.0.0.0/0',
                            'action': 'DELETED'
                        });
                        params.IpPermissions[0].IpRanges = finalIpRanges;
                    }
                    if (openIpv6Range) {
                        remediation_file['remediate']['actions'][pluginName][resource]['steps'].push({
                            'inboundRule': '::/0',
                            'action': 'DELETED'
                        });
                        params.IpPermissions[0].Ipv6Ranges = finalIpv6Ranges;
                    }

                    params.IpPermissions[0].UserIdGroupPairs = failingPermission.UserIdGroupPairs.length ? failingPermission.UserIdGroupPairs : null;
                    actions.push(params);
                    return rCb();
                });
            }
        ], function(err) {
            if (err) {
                errors.push(err);
                return fpCb();
            } else {
                return fpCb();
            }
        });
    }, function(err) {
        if (errors && errors.length) {
            cb(errors.join(', '));
        } else if (err) {
            cb(err);
        } else {
            cb(null, actions);
        }
    });
}

function getDefaultKeyId(cache, region, defaultKeyDesc) {
    var source = {};

    var listKeys = helpers.addSource(cache, source, ['kms', 'listKeys', region]);

    if (!listKeys || listKeys.err || !listKeys.data || !listKeys.data.length) {
        return false;
    }

    var defaultKey = listKeys.data.find(key => {
        var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, key.KeyId]);

        if (describeKey && describeKey.data && describeKey.data.KeyMetadata) {
            var keyToAdd = describeKey.data.KeyMetadata;

            if (keyToAdd.KeyManager && keyToAdd.KeyManager === 'AWS' && keyToAdd.Description &&
                keyToAdd.Description.indexOf(defaultKeyDesc) === 0 && keyToAdd.Enabled && keyToAdd.KeyState && keyToAdd.KeyState === 'Enabled') {
                return keyToAdd;
            }
        }
    });

    if (defaultKey) return defaultKey.KeyId;

    return false;
}

function getOrganizationAccounts(listAccounts, accountId) {
    let orgAccountIds = [];
    if (listAccounts.data && listAccounts.data.length){
        listAccounts.data.forEach(account => {
            if (account.Id && account.Id !== accountId) orgAccountIds.push(account.Id);
        });
    }

    return orgAccountIds;
}

function getUsedSecurityGroups(cache, results, region) {
    let result = [];
    const describeNetworkInterfaces = helpers.addSource(cache, {},
        ['ec2', 'describeNetworkInterfaces', region]);

    if (!describeNetworkInterfaces || describeNetworkInterfaces.err || !describeNetworkInterfaces.data) {
        helpers.addResult(results, 3,
            'Unable to query for network interfaces: ' + helpers.addError(describeNetworkInterfaces), region);
        return  result['Error'];
    }

    const listFunctions = helpers.addSource(cache, {},
        ['lambda', 'listFunctions', region]);

    if (!listFunctions || listFunctions.err || !listFunctions.data) {
        helpers.addResult(results, 3,
            'Unable to list lambda functions: ' + helpers.addError(listFunctions), region);
        return  result['Error'];
    }

    describeNetworkInterfaces.data.forEach(interface => {
        if (interface.Groups) {
            interface.Groups.forEach(group => {
                if (!result.includes(group.GroupId)) result.push(group.GroupId);
            });
        }
    });

    listFunctions.data.forEach(func => {
        if (func.VpcConfig && func.VpcConfig.SecurityGroupIds) {
            func.VpcConfig.SecurityGroupIds.forEach(group => {
                if (!result.includes(group)) result.push(group);
            });
        }
    });

    return result;
}

function getPrivateSubnets(subnetRTMap, subnets, routeTables) {
    let response = [];
    let privateRouteTables = [];

    routeTables.forEach(routeTable => {
        if (routeTable.RouteTableId && routeTable.Routes &&
            routeTable.Routes.every(route => !route.GatewayId || !route.GatewayId.startsWith('igw-'))) {
            privateRouteTables.push(routeTable.RouteTableId);
        }
    });

    subnets.forEach(subnet => {
        if (subnet.SubnetId && subnetRTMap[subnet.SubnetId] && privateRouteTables.includes(subnetRTMap[subnet.SubnetId])) response.push(subnet.SubnetId);
    });

    return response;
}

function getSubnetRTMap(subnets, routeTables) {
    let subnetRTMap = {};
    let vpcRTMap = {};

    routeTables.forEach(routeTable => {
        if (routeTable.RouteTableId && routeTable.Associations && routeTable.Associations.length) {
            routeTable.Associations.forEach(association => {
                if (association.SubnetId && !subnetRTMap[association.SubnetId]) subnetRTMap[association.SubnetId] =  routeTable.RouteTableId;
            });
        }
        if (routeTable.VpcId && routeTable.RouteTableId && routeTable.Associations &&
            routeTable.Associations.find(association => association.Main) && !vpcRTMap[routeTable.VpcId]) vpcRTMap[routeTable.VpcId] = routeTable.RouteTableId;
    });

    subnets.forEach(subnet => {
        if (subnet.SubnetId && subnet.VpcId &&
            !subnetRTMap[subnet.SubnetId] && vpcRTMap[subnet.VpcId]) subnetRTMap[subnet.SubnetId] = vpcRTMap[subnet.VpcId];
    });

    return subnetRTMap;
}

var isRateError = function(err) {
    let isError = false;
    var rateError = {message: 'rate', statusCode: 429};
    if (err && err.statusCode && rateError.statusCode == err.statusCode){
        isError = true;
    } else if (err && rateError && rateError.message && err.message &&
        err.message.toLowerCase().indexOf(rateError.message.toLowerCase()) > -1){
        isError = true;
    }

    return isError;
};

function makeCustomCollectorCall(executor, callKey, params, retries, apiRetryAttempts=2, apiRetryCap=1000, apiRetryBackoff=500, callback) {
    async.retry({
        times: apiRetryAttempts,
        interval: function(retryCount){
            let retryExponential = 3;
            let retryLeveler = 3;
            let timestamp = parseInt(((new Date()).getTime()).toString().slice(-1));
            let retry_temp = Math.min(apiRetryCap, (apiRetryBackoff * (retryExponential + timestamp) ** retryCount));
            let retry_seconds = Math.round(retry_temp/retryLeveler + Math.random(0, retry_temp) * 5000);

            console.log(`Trying ${callKey} again in: ${retry_seconds/1000} seconds`);
            retries.push({seconds: Math.round(retry_seconds/1000)});
            return retry_seconds;
        },
        errorFilter: function(err) {
            return isRateError(err);
        }
    }, function(cb) {
        executor[callKey](params, function(err, data) {
            return cb(err, data);
        });
    }, function(err, result) {
        callback(err, result);
    });
}

var debugApiCalls = function(call, service, debugMode, finished) {
    if (!debugMode) return;
    finished ? console.log(`[INFO] ${service}:${call} returned`) : console.log(`[INFO] ${service}:${call} invoked`);
};

var logError = function(service, call, region, err, errorsLocal, apiCallErrorsLocal, apiCallTypeErrorsLocal, totalApiCallErrorsLocal, errorSummaryLocal, errorTypeSummaryLocal, debugMode) {
    if (debugMode) console.log(`[INFO] ${service}:${call} returned error: ${err.message}`);
    totalApiCallErrorsLocal++;

    if (!errorSummaryLocal[service]) errorSummaryLocal[service] = {};

    if (!errorSummaryLocal[service][call]) errorSummaryLocal[service][call] = {};

    if (err.code && !errorSummaryLocal[service][call][err.code]) {
        apiCallErrorsLocal++;
        errorSummaryLocal[service][call][err.code] = {};
        errorSummaryLocal[service][call][err.code].total = apiCallErrorsLocal;
        errorSummaryLocal.total = totalApiCallErrorsLocal;
    }

    if (err.code && !errorTypeSummaryLocal[err.code]) errorTypeSummaryLocal[err.code] = {};
    if (err.code && !errorTypeSummaryLocal[err.code][service]) errorTypeSummaryLocal[err.code][service] = {};
    if (err.code && !errorTypeSummaryLocal[err.code][service][call]) {
        apiCallTypeErrorsLocal++;
        errorTypeSummaryLocal[err.code][service][call] = {};
        errorTypeSummaryLocal[err.code][service][call].total = apiCallTypeErrorsLocal;
        errorTypeSummaryLocal.total = totalApiCallErrorsLocal;
    }

    if (debugMode){
        if (!errorsLocal[service]) errorsLocal[service] = {};
        if (!errorsLocal[service][call]) errorsLocal[service][call] = {};
        if (err.code && !errorsLocal[service][call][err.code]) {
            errorsLocal[service][call][err.code] = {};
            errorsLocal[service][call][err.code].total = apiCallErrorsLocal;
            if (err.requestId) {
                errorsLocal[service][call][err.code][err.requestId] = {};
                if (err.statusCode) errorsLocal[service][call][err.code][err.requestId].statusCode = err.statusCode;
                if (err.message) errorsLocal[service][call][err.code][err.requestId].message = err.message;
                if (err.time) errorsLocal[service][call][err.code][err.requestId].time = err.time;
                if (region) errorsLocal[service][call][err.code][err.requestId].region = region;
            }
        }
    }
};

function checkConditions(startsWithBuckets, notStartsWithBuckets, endsWithBuckets, notEndsWithBuckets, bucketName) {
    const startsWithCondition = startsWithBuckets.length > 0 ? startsWithBuckets.some(startsWith => bucketName.startsWith(startsWith)): false;
    const notStartsWithCondition = notStartsWithBuckets.length > 0 ? !notStartsWithBuckets.some(notStartsWith => bucketName.startsWith(notStartsWith)): false;
    const endsWithCondition = endsWithBuckets.length > 0 ? endsWithBuckets.some(endsWith => bucketName.endsWith(endsWith)): false;
    const notEndsWithCondition = notEndsWithBuckets.length > 0 ? !notEndsWithBuckets.some(notEndsWith => bucketName.endsWith(notEndsWith)): false;

    return {
        startsWithCondition, notStartsWithCondition,  endsWithCondition, notEndsWithCondition
    };
}

var collectRateError = function(err, rateError) {
    let isError = false;

    if (err && err.statusCode && rateError && rateError.statusCode == err.statusCode) {
        isError = true;
    } else if (err && rateError && rateError.message && err.message &&
        err.message.toLowerCase().indexOf(rateError.message.toLowerCase()) > -1) {
        isError = true;
    }

    return isError;
};
function processFieldSelectors(fieldSelectors,buckets ,startsWithBuckets,notEndsWithBuckets,endsWithBuckets, notStartsWithBuckets) {
    fieldSelectors.forEach(f => {
        if (f.Field === 'resources.ARN') {
            if (f.Equals && f.Equals.length) {
                const bucketName = f.Equals[0].split(':::')[1].split('/')[0];
                buckets.push(bucketName);
            }
            if (f.StartsWith && f.StartsWith.length) {
                startsWithBuckets.push(...f.StartsWith);
            }
            if (f.EndsWith && f.EndsWith.length) {
                endsWithBuckets.push(...f.EndsWith);
            }
            if (f.NotStartsWith && f.NotStartsWith.length) {
                notStartsWithBuckets.push(...f.NotStartsWith);
            }
            if (f.NotEndsWith && f.NotEndsWith.length) {
                notEndsWithBuckets.push(...f.NotEndsWith);
            }
        }
    });
    return { buckets, startsWithBuckets, endsWithBuckets, notStartsWithBuckets, notEndsWithBuckets };
}

var checkTags = function(cache, resourceName, resourceList, region, results, settings={}) {
    const allResources = helpers.addSource(cache, {},
        ['resourcegroupstaggingapi', 'getResources', region]);

    if (!allResources || allResources.err || !allResources.data) {
        helpers.addResult(results, 3,
            'Unable to query all resources from group tagging api:' + helpers.addError(allResources), region);
        return;
    }
    var awsOrGov = defaultPartition(settings);
    const resourceARNPrefix = `arn:${awsOrGov}:${resourceName.split(' ')[0].toLowerCase()}:`;
    const filteredResourceARN = [];
    allResources.data.map(resource => {
        if ((resource.ResourceARN.startsWith(resourceARNPrefix)) && (resource.Tags.length > 0)){
            filteredResourceARN.push(resource.ResourceARN);
        }
    });

    resourceList.map(arn => {
        if (filteredResourceARN.includes(arn)) {
            helpers.addResult(results, 0, `${resourceName} has tags`, region, arn);
        } else {
            helpers.addResult(results, 2, `${resourceName} does not have any tags`, region, arn);
        }
    });
};

function checkSecurityGroup(securityGroup, cache, region, checkENIs = true) {
    let allowsAllTraffic;
    for (var p in securityGroup.IpPermissions) {
        var permission = securityGroup.IpPermissions[p];

        for (var k in permission.IpRanges) {
            var range = permission.IpRanges[k];

            if (range.CidrIp === '0.0.0.0/0') {
                allowsAllTraffic = true;
            }
        }

        for (var l in permission.Ipv6Ranges) {
            var rangeV6 = permission.Ipv6Ranges[l];

            if (rangeV6.CidrIpv6 === '::/0') {
                allowsAllTraffic = true;
            }
        }
    }

    if (allowsAllTraffic && checkENIs) {
        return checkNetworkInterface(securityGroup.GroupId, securityGroup.GroupName, '', region, null, securityGroup, cache, true);
    }
    return allowsAllTraffic;
}

var getAttachedELBs =  function(cache, source, region, resourceId, lbField, lbAttribute) {
    let elbs = [];

    // check classice ELBs
    var describeLoadBalancers = helpers.addSource(cache, source,
        ['elb', 'describeLoadBalancers', region]);

    if (describeLoadBalancers && !describeLoadBalancers.err && describeLoadBalancers.data && describeLoadBalancers.data.length) {
        elbs  = describeLoadBalancers.data.filter(lb => lb[lbField] && lb[lbField].some(instance => instance[lbAttribute] === resourceId));
    }

    // check ALBs/NLBs

    var describeLoadBalancersv2 = helpers.addSource(cache, source,
        ['elbv2', 'describeLoadBalancers', region]);

    if (describeLoadBalancersv2 && !describeLoadBalancersv2.err && describeLoadBalancersv2.data && describeLoadBalancersv2.data.length) {
        describeLoadBalancersv2.data.forEach(function(lb) {
            lb.targetGroups = [];
            var describeTargetGroups = helpers.addSource(cache, source,
                ['elbv2', 'describeTargetGroups', region, lb.DNSName]);

            if (describeTargetGroups && !describeTargetGroups.err && describeTargetGroups.data && describeTargetGroups.data.TargetGroups && describeTargetGroups.data.TargetGroups.length) {
                describeTargetGroups.data.TargetGroups.forEach(function(tg) {
                    var describeTargetHealth = helpers.addSource(cache, source,
                        ['elbv2', 'describeTargetHealth', region, tg.TargetGroupArn]);

                    if (describeTargetHealth && !describeTargetHealth.err && describeTargetHealth.data
                        && describeTargetHealth.data.TargetHealthDescriptions && describeTargetHealth.data.TargetHealthDescriptions.length) {
                        describeTargetHealth.data.TargetHealthDescriptions.forEach(healthDescription => {
                            if (healthDescription.Target && healthDescription.Target.Id &&
                                healthDescription.Target.Id === resourceId) {
                                lb.targetGroups.push({targetgroupName: tg.TargetGroupName, targetGroupArn: tg.TargetGroupArn});
                            }
                        });
                    }
                });
            }

            if (lb.targetGroups && lb.targetGroups.length) {
                let hasListener = false;
                var describeListeners = helpers.addSource(cache, source,
                    ['elbv2', 'describeListeners', region, lb.DNSName]);
                if (describeListeners && describeListeners.data && describeListeners.data.Listeners && describeListeners.data.Listeners.length) {
                    describeListeners.data.Listeners.forEach(listener => {
                        if (!hasListener) {
                            hasListener = listener.DefaultActions.some(action =>
                                action.TargetGroupArn && lb.targetGroups.some(tg => tg.targetGroupArn === action.TargetGroupArn)
                            );
                        }

                    });
                }
                if (hasListener) {
                    elbs.push(lb);
                }
            }
        });
    }

    return elbs;
};

var getApiIdFromArn = function(arn) {
    if (!arn) return null;
    const matches = arn.match(/arn:aws:execute-api:[^:]+:[^:]+:([^/]+)/);
    return matches ? matches[1] : null;
};

var checkNetworkExposure = function(cache, source, subnets, securityGroups, elbs, region, results, resource) {
    var internetExposed = '';
    var isSubnetPrivate = false;

    if (resource && (resource.functionPolicy || resource.functionUrlConfig)) {
        // Check Function URL exposure
        if (resource.functionUrlConfig && resource.functionUrlConfig.data && 
            resource.functionUrlConfig.data.AuthType === 'NONE') {
            internetExposed += 'public function URL';
        }

        // Check API Gateway exposure
        if (resource.functionPolicy && resource.functionPolicy.data && 
            resource.functionPolicy.data.Policy) {
            let statements = helpers.normalizePolicyDocument(resource.functionPolicy.data.Policy);
            
            for (let statement of statements) {
                if (statement.Principal && statement.Principal.Service === 'apigateway.amazonaws.com') {
                    let getRestApis = helpers.addSource(cache, source,
                        ['apigateway', 'getRestApis', region]);

                    if (getRestApis && getRestApis.data && getRestApis.data.items) {
                        let apiId = getApiIdFromArn(statement.SourceArn);
                        let api = getRestApis.data.items.find(a => a.id === apiId);
                        
                        if (api && api.endpointConfiguration && 
                            (api.endpointConfiguration.types.includes('EDGE') || 
                             api.endpointConfiguration.types.includes('REGIONAL'))) {
                            internetExposed += internetExposed.length ? 
                                `, API Gateway ${api.name}` : `API Gateway ${api.name}`;
                        }
                    }
                }
            }
        }

        return internetExposed;
    }

    // Check public endpoint access for specific resources like EKS
    if (resource && resource.resourcesVpcConfig && resource.resourcesVpcConfig.endpointPublicAccess) {
        return 'public endpoint access';
    }

    // Scenario 1: check if resource is in a private subnet
    let subnetRouteTableMap, privateSubnets;
    var describeSubnets = helpers.addSource(cache, source,
        ['ec2', 'describeSubnets', region]);
    var describeRouteTables = helpers.addSource(cache, {},
        ['ec2', 'describeRouteTables', region]);

    if (!describeRouteTables || describeRouteTables.err || !describeRouteTables.data) {
        helpers.addResult(results, 3,
            'Unable to query for route tables: ' + helpers.addError(describeRouteTables), region);
    } else if (!describeSubnets || describeSubnets.err || !describeSubnets.data) {
        helpers.addResult(results, 3,
            'Unable to query for subnets: ' + helpers.addError(describeSubnets), region);
    } else if (describeSubnets.data.length && subnets.length) {
        subnetRouteTableMap = getSubnetRTMap(describeSubnets.data, describeRouteTables.data);
        privateSubnets = getPrivateSubnets(subnetRouteTableMap, describeSubnets.data, describeRouteTables.data);
        if (privateSubnets && privateSubnets.length) {
            isSubnetPrivate = !subnets.some(subnet => !privateSubnets.includes(subnet.id));
        }

        // if it's in a private subnet and has no ELBs attached then its not exposed
        if (isSubnetPrivate && (!elbs || !elbs.length)) {
            return '';
        }
    }

    // If the subnet is not private we will check if security groups and Network ACLs allow internal traffic

    // Scenario 2: check if security group allows all traffic
    var describeSecurityGroups = helpers.addSource(cache, source,
        ['ec2', 'describeSecurityGroups', region]);

    if (!isSubnetPrivate) {
        if (!describeSecurityGroups || describeSecurityGroups.err || !describeSecurityGroups.data) {
            helpers.addResult(results, 3,
                'Unable to query for security groups: ' + helpers.addError(describeSecurityGroups), region);
        } else if (describeSecurityGroups.data.length && securityGroups && securityGroups.length) {
            let instanceSGs = describeSecurityGroups.data.filter(sg => securityGroups.find(isg => isg.GroupId === sg.GroupId));
            for (var group of instanceSGs) {
                let exposedSG = checkSecurityGroup(group, cache, region);
                if (exposedSG) {
                    internetExposed += internetExposed ?  `, ${exposedSG}` : exposedSG;
                }
            }
        }


        // if security group allows all traffic we need to check NACLs
        if (internetExposed.length) {
            let subnetIds = subnets.map(s => s.id);
            // Scenario 3: check if Network ACLs associated with the resource allow all traffic
            var describeNetworkAcls = helpers.addSource(cache, source,
                ['ec2', 'describeNetworkAcls', region]);

            if (!describeNetworkAcls || describeNetworkAcls.err || !describeNetworkAcls.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Network ACLs: ${helpers.addError(describeNetworkAcls)}`, region);
            } else if (describeNetworkAcls.data.length && subnetIds) {
                let naclDeny = true;
                for (let subnetId of subnetIds) {
                    let instanceACL = describeNetworkAcls.data.find(acl => acl.Associations.find(assoc => assoc.SubnetId === subnetId));
                    if (instanceACL && instanceACL.Entries && instanceACL.Entries.length) {
                        const allowRules = instanceACL.Entries.filter(entry =>
                            entry.Egress === false &&
                            entry.RuleAction === 'allow' &&
                            (entry.CidrBlock === '0.0.0.0/0' || entry.Ipv6CidrBlock === '::/0')
                        );

                        const denyIPv4 = instanceACL.Entries.find(entry =>
                            entry.Egress === false &&
                            entry.RuleAction === 'deny' &&
                            entry.CidrBlock === '0.0.0.0/0'
                        );

                        const denyIPv6 = instanceACL.Entries.find(entry =>
                            entry.Egress === false &&
                            entry.RuleAction === 'deny' &&
                            entry.Ipv6CidrBlock === '::/0'
                        );

                        let exposed = allowRules.some(allowRule => {
                            return !instanceACL.Entries.some(denyRule => {
                                return (
                                    denyRule.Egress === false &&
                                    denyRule.RuleAction === 'deny' &&
                                    (
                                        (allowRule.CidrBlock && denyRule.CidrBlock === allowRule.CidrBlock) ||
                                        (allowRule.Ipv6CidrBlock && denyRule.Ipv6CidrBlock === allowRule.Ipv6CidrBlock)
                                    ) &&
                                    denyRule.Protocol === allowRule.Protocol &&
                                    (
                                        denyRule.PortRange ?
                                            (allowRule.PortRange &&
                                                denyRule.PortRange.From === allowRule.PortRange.From &&
                                                denyRule.PortRange.To === allowRule.PortRange.To) : true
                                    ) &&
                                    denyRule.RuleNumber < allowRule.RuleNumber
                                );
                            });
                        });

                        // exposed - if NACL has an allow all rule
                        if (exposed) {
                            internetExposed += `, nacl ${instanceACL.NetworkAclId}`;
                        }

                        // not exposed - if NACL has a deny rule
                        if (exposed || !denyIPv4 || !denyIPv6) {
                            naclDeny = false;
                        }
                    } else {
                        naclDeny = false;
                    }
                }

                // not exposed - if all NACLs have deny rules
                if (naclDeny) {
                    return '';
                }
            }

        }
    }

    // if there are no explicit allow or deny rules, we look at ELBs


    if (elbs && elbs.length) {
        for (const lb of elbs) {

            let isLBPublic = false;
            if (lb.Scheme && lb.Scheme.toLowerCase() === 'internet-facing') {
                if (lb.SecurityGroups && lb.SecurityGroups.length && describeSecurityGroups &&
                    !describeSecurityGroups.err && describeSecurityGroups.data && describeSecurityGroups.data.length) {
                    let elbSGs = describeSecurityGroups.data.filter(sg => lb.SecurityGroups.includes(sg.GroupId));
                    for (var elbSG of elbSGs) {
                        let exposedSG = checkSecurityGroup(elbSG, cache, region, false);
                        if (exposedSG) {
                            isLBPublic = true;
                        }
                    }
                }
            }

            if (isLBPublic) {
                internetExposed += internetExposed.length ? `, elb ${lb.LoadBalancerName}`: `elb ${lb.LoadBalancerName}`;
            }
        }
    }

    return internetExposed;
};

module.exports = {
    addResult: addResult,
    findOpenPorts: findOpenPorts,
    waitForCredentialReport: waitForCredentialReport,
    normalizePolicyDocument: normalizePolicyDocument,
    globalPrincipal: globalPrincipal,
    userGlobalAccess: userGlobalAccess,
    crossAccountPrincipal: crossAccountPrincipal,
    defaultRegion: defaultRegion,
    defaultPartition: defaultPartition,
    remediatePlugin: remediatePlugin,
    nullArray: nullArray,
    divideArray:divideArray,
    remediatePasswordPolicy:remediatePasswordPolicy,
    remediateOpenPorts: remediateOpenPorts,
    hasFederatedUserRole: hasFederatedUserRole,
    getEncryptionLevel: getEncryptionLevel,
    extractStatementPrincipals: extractStatementPrincipals,
    getDefaultKeyId: getDefaultKeyId,
    isValidCondition: isValidCondition,
    isEffectiveStatement: isEffectiveStatement,
    getDenyActionResourceMap: getDenyActionResourceMap,
    getDenyPermissionsMap: getDenyPermissionsMap,
    isEffectivePolicyStatement: isEffectivePolicyStatement,
    getS3BucketLocation: getS3BucketLocation,
    getOrganizationAccounts: getOrganizationAccounts,
    getUsedSecurityGroups: getUsedSecurityGroups,
    getPrivateSubnets: getPrivateSubnets,
    getSubnetRTMap: getSubnetRTMap,
    makeCustomCollectorCall: makeCustomCollectorCall,
    debugApiCalls: debugApiCalls,
    logError: logError,
    collectRateError: collectRateError,
    checkTags: checkTags,
    checkConditions: checkConditions,
    processFieldSelectors: processFieldSelectors,
    checkNetworkInterface: checkNetworkInterface,
    checkNetworkExposure: checkNetworkExposure,
    getAttachedELBs: getAttachedELBs
};

