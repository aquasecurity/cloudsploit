module.exports = {
	functions: require('./functions.js'),
	regions: require('./regions.js'),
	addResult: require('./functions.js').addResult,
	addSource: require('./functions.js').addSource,

	MAX_REGIONS_AT_A_TIME: 6
};