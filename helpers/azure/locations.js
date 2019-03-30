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
	BlobService: ['East US', 'West US'],
	FileService: ['East US', 'West US'],
	QueueService: ['East US', 'West US'],
	TableService: ['East US', 'West US'],
	virtualMachines: ['East US', 'West US'],
	disks: ['East US', 'West US'],
	virtualMachineExtensions: ['East US', 'West US'],
	activityLogAlerts: ['East US', 'West US'],
	resources: ['East US', 'West US']
};
