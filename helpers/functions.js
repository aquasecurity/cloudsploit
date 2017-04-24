var async = require('async');

var ONE_DAY = 24*60*60*1000;

var CREDENTIAL_REPORT_DATA;
var CREDENTIAL_REPORT_ERROR;

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

	if (extra) {
		var original = (cache[service] &&
					   cache[service][call] &&
					   cache[service][call][region] &&
					   cache[service][call][region][extra]) ? 
					   cache[service][call][region][extra] : null;
	} else {
		var original = (cache[service] &&
					   cache[service][call] &&
					   cache[service][call][region]) ?
					   cache[service][call][region] : null;
	}

	if (!source[service]) source[service] = {};
	source[service][region] = original;

	return original;
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
	addError: addError
};