var async = require('async');

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

function addResult(results, status, message, region, resource){
	results.push({
		status: status,
		message: message,
		region: region || 'global',
		resource: resource || null
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

module.exports = {
	daysBetween: daysBetween,
	daysAgo: daysAgo,
	mostRecentDate: mostRecentDate,
	addResult: addResult,
	addSource: addSource,
	addError: addError,
	findOpenPorts: findOpenPorts,
	waitForCredentialReport: waitForCredentialReport
};