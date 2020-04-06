var async = require('async');
var regions = require(__dirname + '/regions');
var AWS = require('aws-sdk');

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
        var pingCredentialReport = function(pingCb, pingResults) {
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

function findOpenPorts(groups, ports, service, region, results) {
    var found = false;

    for (g in groups) {
        var strings = [];
        var resource = 'arn:aws:ec2:' + region + ':' +
                       groups[g].OwnerId + ':security-group/' +
                       groups[g].GroupId;

        for (p in groups[g].IpPermissions) {
            var permission = groups[g].IpPermissions[p];

            for (k in permission.IpRanges) {
                var range = permission.IpRanges[k];

                if (range.CidrIp === '0.0.0.0/0' && ports[permission.IpProtocol]) {
                    for (portIndex in ports[permission.IpProtocol]) {
                        var port = ports[permission.IpProtocol][portIndex];

                        if (permission.FromPort <= port && permission.ToPort >= port) {
                            var string = permission.IpProtocol.toUpperCase() +
                                ' port ' + port + ' open to 0.0.0.0/0';
                            if (strings.indexOf(string) === -1) strings.push(string);
                            found = true;
                        }
                    }
                }
            }

            for (k in permission.Ipv6Ranges) {
                var range = permission.Ipv6Ranges[k];

                if (range.CidrIpv6 === '::/0' && ports[permission.IpProtocol]) {
                    for (portIndex in ports[permission.IpProtocol]) {
                        var port = ports[permission.IpProtocol][portIndex];

                        if (permission.FromPort <= port && permission.ToPort >= port) {
                            var string = permission.IpProtocol.toUpperCase() +
                                ' port ' + port + ' open to ::/0';
                            if (strings.indexOf(string) === -1) strings.push(string);
                            found = true;
                        }
                    }
                }
            }
        }

        if (strings.length) {
            addResult(results, 2,
                'Security group: ' + groups[g].GroupId +
                ' (' + groups[g].GroupName +
                ') has ' + service + ': ' + strings.join(' and '), region,
                resource);
        }
    }

    if (!found) {
        addResult(results, 0, 'No public open ports found', region);
    }

    return;
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

    for (s in doc.Statement) {
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

function globalPrincipal(principal) {
    if (typeof principal === 'string' && principal === '*') {
        return true;
    }

    var awsPrincipals = principal.AWS;
    if(!Array.isArray(awsPrincipals)) {
        awsPrincipals = [awsPrincipals];
    }

    if (awsPrincipals.indexOf('*') > -1 ||
        awsPrincipals.indexOf('arn:aws:iam::*') > -1) {
        return true;
    }

    return false;
}

function crossAccountPrincipal(principal, accountId) {
    if (typeof principal === 'string' &&
        /^[0-9]{12}$/.test(principal) &&
        principal !== accountId) {
        return true;
    }

    var awsPrincipals = principal.AWS;
    if(!Array.isArray(awsPrincipals)) {
        awsPrincipals = [awsPrincipals];
    }

    for (a in awsPrincipals) {
        if (/^arn:aws:iam::[0-9]{12}.*/.test(awsPrincipals[a]) &&
            awsPrincipals[a].indexOf(accountId) === -1) {
            return true;
        }
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

function remediatePlugin(config, call, params, callback) {
    var service = call.split(':')[0];
    var callKey = call.split(':')[1];
    var executor = new AWS[service](config);

    var executorCb = function (err, data) {
        if (err) {
            return callback(err, null)
        } else if (data) {
           return callback(null, data);
        }
    };

    executor[callKey](params, executorCb);
}

function nullArray(object) {
    for (key in object) {
        if (Array.isArray(object[key]) && !object[key].length) {
            object[key] = null;
        }
    }
    return object;
}

module.exports = {
    addResult: addResult,
    findOpenPorts: findOpenPorts,
    waitForCredentialReport: waitForCredentialReport,
    normalizePolicyDocument: normalizePolicyDocument,
    globalPrincipal: globalPrincipal,
    crossAccountPrincipal: crossAccountPrincipal,
    defaultRegion: defaultRegion,
    defaultPartition: defaultPartition,
    remediatePlugin: remediatePlugin,
    nullArray: nullArray
};