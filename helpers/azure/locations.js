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
	resourceGroups: ['East US', 'West US'],
	storageAccounts: ['East US', 'West US'],
	blobService: ['East US', 'West US'],
	fileService: ['East US', 'West US'],
	queueService: ['East US', 'West US'],
	tableService: ['East US', 'West US'],
	virtualMachines: ['East US', 'West US'],
	disks: ['East US', 'West US'],
	virtualMachineExtensions: ['East US', 'West US'],
};
