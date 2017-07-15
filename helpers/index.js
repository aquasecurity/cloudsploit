module.exports = {
	functions: require('./functions.js'),
	regions: require('./regions.js'),
	addResult: require('./functions.js').addResult,
	addSource: require('./functions.js').addSource,
	addError: require('./functions.js').addError,
	findOpenPorts: require('./functions.js').findOpenPorts,

	MAX_REGIONS_AT_A_TIME: 6
};