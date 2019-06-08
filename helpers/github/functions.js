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
		return obj.url;
	} else {
		return null;
	}
}

var dataBlacklist = [
	'node_id', 'avatar_url', 'gravatar_id', 'followers_url', 'following_url', 'gists_url', 'starred_url',
	'subscriptions_url', 'organizations_url', 'repos_url', 'events_url', 'received_events_url', 'forks_url',
	'keys_url', 'collaborators_url', 'teams_url', 'hooks_url', 'issue_events_url', 'events_url', 'assignees_url',
	'branches_url', 'tags_url', 'blobs_url', 'git_tags_url', 'git_refs_url', 'trees_url', 'statuses_url',
	'languages_url', 'stargazers_url', 'contributors_url', 'subscribers_url', 'subscription_url', 'commits_url',
	'git_commits_url', 'comments_url', 'issue_comment_url', 'contents_url', 'compare_url', 'merges_url',
	'archive_url', 'downloads_url', 'issues_url', 'pulls_url', 'milestones_url', 'notifications_url',
	'labels_url', 'releases_url', 'deployments_url', 'git_url', 'ssh_url', 'clone_url', 'svn_url',
	'mirror_url'
];

var errBlacklist = [
	'access-control-allow-origin', 'access-control-expose-headers', 'connection', 'content-encoding',
	'content-security-policy', 'content-type', 'expect-ct', 'referrer-policy', 'retry-after',
	'strict-transport-security', 'transfer-encoding', 'x-content-type-options', 'x-frame-options',
	'x-github-media-type', 'x-xss-protection', 'user-agent', 'accept'
];

function cleanCollection(collection) {
	// Remove unnecessary properties from collection
	function processObj(obj, blacklist) {
		if (typeof obj == 'string') {
			return;
		} else if (Array.isArray(obj)) {
			for (i in obj) {
				processObj(obj[i], blacklist);
			}
		} else {
			for (prop in obj) {
				if (typeof obj[prop] == 'string') {
					if (blacklist.indexOf(prop) > -1) {
						delete obj[prop];
					}
				} else {
					processObj(obj[prop], blacklist);
				}
			}
		}
	}

	for (service in collection) {
		for (call in collection[service]) {
			if (collection[service][call].data) {
				processObj(collection[service][call].data, dataBlacklist);
			} else if (collection[service][call].err) {
				processObj(collection[service][call].err, errBlacklist);
			} else {
				for (c in collection[service][call]) {
					if (collection[service][call][c].data) {
						processObj(collection[service][call][c].data, dataBlacklist);
					} else if (collection[service][call][c].err) {
						processObj(collection[service][call][c].err, errBlacklist);
					}
				}
			}
		}
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
	getResource: getResource,
	cleanCollection: cleanCollection
};