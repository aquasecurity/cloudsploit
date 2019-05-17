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
	var extra = paths[2];

	if (!source[service]) source[service] = {};
	if (!source[service][call]) source[service][call] = {};
	if (!source[service][call]) source[service][call] = {};

	if (extra) {
		var original = (cache[service] &&
					   cache[service][call] &&
					   cache[service][call] &&
					   cache[service][call][extra]) ?
					   cache[service][call][extra] : null;

		source[service][call][extra] = original;
	} else {
		var original = (cache[service] &&
					   cache[service][call] &&
					   cache[service][call]) ?
					   cache[service][call] : null;

		source[service][call] = original;
	}

	return original;
}

function addError(original){
	if (!original || !original.err) {
		return 'Unable to obtain data';
	} else if (typeof original.err === 'string') {
		return original.err;
	} else if (original.err.name && original.err.status) {
		return original.err.name + ':' + original.err.status;
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

function getResource(obj) {
	// Returns a unique resource name given an object
	if (obj.url) {
		// Parse URL into resource

	} else {
		return null;
	}
}

module.exports = {
	daysBetween: daysBetween,
	daysAgo: daysAgo,
	mostRecentDate: mostRecentDate,
	addResult: addResult,
	addSource: addSource,
	addError: addError,
	isCustom: isCustom,
	getResource: getResource
};