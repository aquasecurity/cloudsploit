var ONE_DAY = 24*60*60*1000;

function daysBetween(date1, date2) {
    return Math.round(Math.abs((new Date(date1).getTime() - new Date(date2).getTime())/(ONE_DAY)));
}

function daysAgo(date1) {
    return daysBetween(date1, new Date());
}

function mostRecentDate(dates) {
    var mostRecentDate;

    for (d in dates) {
        if (!mostRecentDate || dates[d] > mostRecentDate) {
            mostRecentDate = dates[d];
        }
    }

    return mostRecentDate;
}

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
                    return pingCb('Waiting for credential report');
                }

                pingCb(null, getData);
            });
        };

        async.retry({times: 10, interval: 1000}, pingCredentialReport, function(reportErr, reportData){
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
    results.push({
        status: status,
        message: message,
        region: region || 'global',
        resource: resource || null,
        custom: custom || false
    });
}

function addSource(cache, source, paths){
    // paths = array of arrays (props of each element; service, call, region, extra)
    var service = paths[0];
    var call = paths[1];
    var region = paths[2];
    var extra = paths[3];

    if (!source[service]) source[service] = {};
    if (!source[service][call]) source[service][call] = {};
    if (!source[service][call][region]) source[service][call][region] = {};

    if (extra) {
        var original = (cache[service] &&
        cache[service][call] &&
        cache[service][call][region] &&
        cache[service][call][region][extra]) ?
            cache[service][call][region][extra] : null;

        source[service][call][region][extra] = original;
    } else {
        var original = (cache[service] &&
        cache[service][call] &&
        cache[service][call][region]) ?
            cache[service][call][region] : null;

        source[service][call][region] = original;
    }

    return original;
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

function addError(original){
    if (!original || !original.err) {
        return 'Unable to obtain data';
    } else if (typeof original.err === 'string') {
        return original.err;
    } else if (original.err.message) {
        return original.err.message;
    } else {
        return 'Unable to obtain data';
    }
}

function isCustom(providedSettings, pluginSettings) {
    var isCustom = false;

    for (s in pluginSettings) {
        if (providedSettings[s] && pluginSettings[s].default &&
            (providedSettings[s] !== pluginSettings[s].default)) {
            isCustom = true;
            break;
        }
    }

    return isCustom;
}

function cidrSize(block){
	/*
	 Determine the number of IP addresses in a given CIDR block
	 Algorithm from https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation
	 2^(address length - prefix length)
	 */
    return Math.pow(2, 32 - block.split('/')[1]);
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
            !statement.Action || !statement.Action.length ||
            !statement.Resource || !statement.Resource.length) {
            break;
        }

        if (typeof statement.Effect !== 'string') break;

        if (!Array.isArray(statement.Action)) statement.Action = [statement.Action];
        if (!Array.isArray(statement.Resource)) statement.Resource = [statement.Resource];

        statementsToReturn.push(statement);
    }

    return statementsToReturn;
}

module.exports = {
    daysBetween: daysBetween,
    cidrSize: cidrSize,
    daysAgo: daysAgo,
    mostRecentDate: mostRecentDate,
	addResult: addResult,
    addSource: addSource,
    addError: addError,
    findOpenPorts: findOpenPorts,
    waitForCredentialReport: waitForCredentialReport,
    isCustom: isCustom,
    normalizePolicyDocument: normalizePolicyDocument
};