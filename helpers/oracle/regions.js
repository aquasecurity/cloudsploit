// Source: https://azure.microsoft.com/en-us/global-infrastructure/services/

var regions = [
    'us-ashburn-1',
    'us-phoenix-1',
    'ca-toronto-1',
    'eu-frankfurt-1',
    'uk-london-1',
];

module.exports = {
    default: ['us-ashburn-1'],
    all: regions,
    vcn: regions,
    group: regions,
    publicIp: regions,
    securityList: regions,
    user: regions,
    userGroupMembership: regions,
    authenticationPolicy: regions,
};
