// Source: https://azure.microsoft.com/en-us/global-infrastructure/services/

var locations = [
	'Central US',
	'East US',
	'East US 2',
	'North Central US',
	'South Central US',
	'West Central US',
	'West US',
	'West US 2'
];

module.exports = {
	all: locations,
	resourcegroups: ['East US', 'West US'],
	storageaccounts: ['East US', 'West US'],
	blobservice: ['East US', 'West US'],
	fileservice: ['East US', 'West US'],
	queueservice: ['East US', 'West US'],
	tableservice: ['East US', 'West US'],
};
