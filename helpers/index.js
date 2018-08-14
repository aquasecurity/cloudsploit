var regRegions = require('./regions.js');
var govRegions = require('./regions_gov.js');

var regions = function(govcloud) {
	if (govcloud) return govRegions;
	return regRegions;
};

module.exports = {
	functions: require('./functions.js'),
	regions: regions,
	addResult: require('./functions.js').addResult,
	addSource: require('./functions.js').addSource,
	addError: require('./functions.js').addError,
	isCustom: require('./functions.js').isCustom,
	cidrSize: require('./functions.js').cidrSize,
	findOpenPorts: require('./functions.js').findOpenPorts,
	normalizePolicyDocument: require('./functions.js').normalizePolicyDocument,

	MAX_REGIONS_AT_A_TIME: 6
};