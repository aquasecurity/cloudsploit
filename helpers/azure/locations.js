// Source: https://azure.microsoft.com/en-us/global-infrastructure/services/
// Source: az account list-locations -o table

var locations = [
    'eastus',               // (US) East US
    'eastus2',              // (US) East US 2
    'southcentralus',       // (US) South Central US
    'westus2',              // (US) West US 2
    'westus3',              // (US) West US 3
    'centralus',            // (US) Central US
    'northcentralus',       // (US) North Central US
    'westus',               // (US) West US
    'eastus2euap',          // (US) East US 2 EUAP
    'westcentralus',        // (US) West Central US
    'centraluseuap',        // (US) Central US EUAP
    'australiaeast',        // (Asia Pacific) Australia East
    'southeastasia' ,       // (Asia Pacific) Southeast Asia
    'centralindia',         // (Asia Pacific) Central India
    'eastasia',             // (Asia Pacific) East Asia
    'japaneast',            // (Asia Pacific) Japan East
    'jioindiawest',         // (Asia Pacific) Jio India West
    'koreacentral',         // (Asia Pacific) Korea Central
    'australiacentral',     // (Asia Pacific) Australia Central
    'australiacentral2',    // (Asia Pacific) Australia Central 2
    'australiasoutheast',   // (Asia Pacific) Australia Southeast
    'japanwest',            // (Asia Pacific) Japan West
    'koreasouth',           // (Asia Pacific) Korea South
    'jioindiacentral',      // (Asia Pacific) Jio India Central
    'southindia',           // (Asia Pacific) South India
    'westindia',            // (Asia Pacific) West India
    'westeurope',           // (Europe) West Europe
    'northeurope',          // (Europe) North Europe
    'swedencentral',        // (Europe) Sweden Central
    'uksouth',              // (Europe) UK South
    'francecentral',        // (Europe) France Central
    'germanywestcentral',   // (Europe) Germany West Central
    'germanycentral',       // (Europe) Germany Central
    'germanynortheast',     // (Europe) Germany Northeast
    'germanynorth',         // (Europe) Germany North
    'norwayeast',           // (Europe) Norway East
    'switzerlandnorth',     // (Europe) Switzerland North
    'francesouth',          // (Europe) France South
    'norwaywest',           // (Europe) Norway West
    'ukwest',               // (Europe) UK West
    'switzerlandwest',      // (Europe) Switzerland West
    'southafricawest',      // (Africa) South Africa West
    'southafricanorth',     // (Africa) South Africa North
    'uaenorth',             // (Middle East) UAE North
    'uaecentral',           // (Middle East) UAE Central
    'brazilsouth',          // (South America) Brazil South
    'brazilsoutheast',      // (South America) Brazil Southeast
    'canadacentral',        // (Canada) Canada Central
    'canadaeast',           // (Canada) Canada East
    'qatarcentral',         // (Middle East) Qatar
    'polandcentral',        // (Europe) Poland Central
    'italynorth',           // (Europe) Italy North
    'israelcentral',        // (Middle East) Israel Central
];

module.exports = {
    all: locations,
    resources: locations,
    storageAccounts: locations,
    virtualMachines: locations,
    snapshots: locations,
    disks: locations,
    activityLogAlerts: ['global'],
    vaults: locations,
    policyAssignments: locations.concat(['global']),
    recoveryServiceVaults: locations,
    backupPolicies: locations,
    backupProtectedItems: locations,
    webApps: locations,
    appServiceCertificates: locations,
    networkSecurityGroups: locations,
    servers: locations,
    logProfiles: ['global'],
    profiles: ['global'],
    managementLocks: ['global'],
    blobServices: locations,
    networkWatchers: locations,
    networkInterfaces: locations,
    managedClusters: locations,
    virtualMachineScaleSets: locations,
    autoProvisioningSettings: ['global'],
    securityContacts: ['global'],
    usages: ['global'],
    subscriptions: ['global'],
    loadBalancers: locations,
    availabilitySets: locations,
    virtualNetworks: locations,
    virtualNetworkPeerings: locations,
    virtualNetworkGateways: locations,
    networkGatewayConnections: locations,
    natGateways: locations,
    users: ['global'],
    registries: locations,
    redisCaches: locations,
    pricings: ['global'],
    roleDefinitions: ['global'],
    aad: ['global'],
    groups: ['global'],
    servicePrincipals: ['global'],
    autoscaleSettings: locations,
    resourceGroups: locations,
    policyDefinitions: locations,
    diagnosticSettingsOperations: ['global'],
    databaseAccounts: locations,
    securityCenter: ['global'],
    advisor: ['global'],
    publicIPAddresses: locations,
    privateDnsZones: ['global'],
    privateEndpoints: locations,
    securityContactv2: ['global'],
    images: locations,
    vmScaleSet: locations,
    applicationGateway: locations,
    wafPolicies: locations,
    routeTables: locations,
    bastionHosts: locations,
    applications: ['global'],
    eventGrid: locations,
    eventHub: locations,
    mediaServices: locations,
    serviceBus: locations,
    classicFrontDoors: ['global'],
    afdWafPolicies: ['global'],
    appConfigurations: locations,
    automationAccounts: locations,
    openAI: locations,
    logAnalytics: locations,
    publicIpAddresses: locations,
    computeGalleries: locations,
    containerApps: locations
};
