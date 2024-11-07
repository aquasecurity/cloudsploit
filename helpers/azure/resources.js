// This file contains a list of ARN paths for each API call type
// that are used to extract ARNs for resources

module.exports = {
    activityLogAlerts: {
        listBySubscriptionId: 'id'
    },
    advancedThreatProtectionSettings: {
        listByServer: 'id'
    },
    advancedThreatProtection: {
        get: 'id'
    },
    advisor: {
        recommendationsList: 'id'
    },
    autoscaleSettings: {
        listBySubscription: 'id'
    },
    autoProvisioningSettings: {
        list: 'id'
    },
    availabilitySets: {
        listByResourceGroup: 'id'
    },
    appServiceCertificates: {
        list: 'id'
    },
    backupPolicies: {
        listByVault: 'id'
    },
    backupProtectedItems: {
        listByVault: 'id'
    },
    backupShortTermRetentionPolicies: {
        listByDatabase: 'id'
    },
    blobServices: {
        list: 'id',
        getServiceProperties: 'id'
    },
    blobContainers: {
        list: 'id'
    },
    configurations: {
        listByServer: 'id'
    },
    databases: {
        listByServer: 'id'
    },
    databaseBlobAuditingPolicies:{
        get: 'id'
    },
    databaseAccounts: {
        list: 'id',
    },
    diagnosticSettings: {
        listByKeyVault: '',
        listByEndpoint: 'id',
        listByLoadBalancer: 'id',
        listByNetworkSecurityGroup: 'id',
        listByServiceBusNamespaces: 'id',
        listByPostgresFlexibleServers: 'id',
        listByPostgresServers: 'id',
        listByDatabase: 'id',
        listByApplicationGateways: 'id',
        listByOpenAIAccounts: 'id'
    },
    diagnosticSettingsOperations: {
        list: 'id'
    },
    disks: {
        list: 'id'
    },
    encryptionProtectors: {
        listByServer: 'id'
    },
    endpoints: {
        listByProfile: 'id'
    },
    failoverGroups: {
        listByServer: 'id'
    },
    fileShares: {
        list: 'id'
    },
    firewallRules: {
        listByServer: 'id',
        listByFlexibleServerPostgres: 'id'
    },
    fileService: {
        listSharesSegmented: '',
        getShareAcl: ''
    },
    flowLogs: {
        list: 'id'
    },
    loadBalancers: {
        listAll: 'id'
    },
    logProfiles: {
        list: 'id'
    },
    managementLocks: {
        listAtSubscriptionLevel: ''
    },
    managedClusters: {
        list: 'id',
        getUpgradeProfile: 'id'
    },
    natGateways: {
        listBySubscription: 'id'
    },
    networkInterfaces: {
        listAll: 'id'
    },
    networkSecurityGroups: {
        listAll: 'id',
    },
    networkGatewayConnections: {
        listByResourceGroup: 'id'
    },
    networkWatchers: {
        listAll: 'id'
    },
    profiles: {
        list: 'id'
    },
    policyAssignments: {
        list: 'id'
    },
    pricings: {
        list: 'id'
    },
    queueService: {
        listQueuesSegmented: '',
        getQueueAcl: ''
    },
    registries: {
        list: 'id'
    },
    redisCaches: {
        listBySubscription: 'id'
    },
    resources: {
        list: 'id'
    },
    resourceGroups: {
        list: 'id'
    },
    recoveryServiceVaults: {
        listBySubscriptionId: 'id'
    },
    roleDefinitions: {
        list: 'id'
    },
    aad: {
        listRoleAssignments: 'id',
        listDenyAssignments: 'id'
    },
    groups: {
        list: 'id'
    },
    servicePrincipals: {
        list: 'id'
    },
    securityContacts: {
        list: 'id'
    },
    securityCenter: {
        list: 'id'
    },
    servers: {
        listSql: 'id',
        listPostgres: 'id',
        listMysql: 'id',
        listPostgresFlexibleServer: 'id',
    },
    serverAdministrators: {
        list: 'id'
    },
    serverSecurityAlertPolicies: {
        listByServer: 'id'
    },
    serverBlobAuditingPolicies: {
        get: 'id'
    },
    serverAutomaticTuning: {
        get: 'id'
    },
    serverAzureADAdministrators: {
        listByServer: 'id'
    },
    snapshots: {
        list: 'id'
    },
    storageAccounts: {
        list: 'id',
        listKeys: ''
    },
    subscriptions: {
        listLocations: 'id'
    },
    tableService: {
        listTablesSegmented: '',
        getTableAcl: ''
    },
    users: {
        list: 'mail'
    },
    usages: {
        list: ''
    },
    vaults: {
        list: 'id',
        getKeys: '',
        getSecrets: '',
        getCertificates: 'id',
        getCertificatePolicy: 'id'
    },
    virtualNetworks: {
        listAll: 'id'
    },
    virtualNetworkGateways: {
        listByResourceGroup: 'id'
    },
    virtualNetworkPeerings: {
        list: 'id'
    },
    virtualMachines: {
        listAll: 'id',
        get: 'id'
    },
    virtualMachineExtensions: {
        list: 'id'
    },
    virtualMachineScaleSets: {
        listAll: 'id'
    },
    virtualMachineScaleSetVMs: {
        list: 'id'
    },
    vulnerabilityAssessments: {
        listByServer: 'id'
    },
    webApps: {
        list: 'id',
        listConfigurations: 'id',
        listAppSettings: 'id',
        getAuthSettings: '',
        getBackupConfiguration: 'id',
    },
    syncGroups: {
        list: 'id'
    },
    ledgerDigestUploads: {
        list: 'id'
    },
    transparentDataEncryption: {
        list: 'id'
    },
    dataMaskingPolicies: {
        list: 'id'
    },
    devOpsAuditingSettings:{
        list: 'id'
    },
    appConfigurations: {
        list: 'id'
    },
    serviceBus:{
        listNamespacesBySubscription: 'id'
    },
    flexibleServersConfigurations:{
        listByPostgresServer: 'id'
    },
    afdWafPolicies: {
        listAll: 'id'
    },
    classicFrontDoors: {
        list: 'id'
    },
    afdSecurityPolicies: {
        listByProfile: 'id'
    },
    automationAccounts:{
        list: 'id'
    },
    openAI: {
        listAccounts: 'id'
    },
    currentSensitivityLabels: {
        list: 'id'
    },
    connectionPolicies:{
        listByServer:'id'
    },
    publicIpAddresses: {
        list: 'id'
    },
    databricks: {
        listWorkspaces: 'id'
    },
    containerApps: {
        list: 'id'
    },
    machineLearning: {
        listWorkspaces: 'id'
    },
    apiManagementService: {
        list: 'id'
    }
};
