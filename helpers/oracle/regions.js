// Source: https://azure.microsoft.com/en-us/global-infrastructure/services/

var regions = [
	'us-ashburn-1',
	'us-phoenix-1',
	'ca-toronto-1',
	'eu-frankfurt-1',
	'uk-london-1'
];

module.exports = {
	all: regions,
	vcn: ['us-ashburn-1', 'us-phoenix-1'],
	publicIp: ['us-ashburn-1', 'us-phoenix-1'],
	securityList: ['us-ashburn-1', 'us-phoenix-1'],
};
