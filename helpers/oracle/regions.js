// Source: https://azure.microsoft.com/en-us/global-infrastructure/services/

var regions = [
    'us-ashburn-1',
    'us-phoenix-1',
    'eu-frankfurt-1',
    'uk-london-1',
    'ca-toronto-1',
    'ap-mumbai-1',
    'ap-seoul-1',
    'ap-tokyo-1',
];

module.exports = {
    default: ['us-ashburn-1'],
    all: regions,
    vcn: regions,
    group: regions,
    publicIp: regions,
    securityList: regions,
    loadBalancer: regions,
    user: regions,
    userGroupMembership: regions,
    authenticationPolicy: regions,
    exprt: regions,
    exportSummary: regions,
    compartment: regions,
    bucket: regions,
    waasPolicy: regions,
    policy: regions,
    subnet: regions,
    dbHome: regions,
    database: regions,
    instance: regions,
    instancePool: regions,
    autoscaleConfiguration: regions,
};