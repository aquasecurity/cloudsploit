// This file contains a list of ARN paths for each API call type
// that are used to extract ARNs for resources


module.exports = {
    keys:{
        list:'id'
    },
    vcn: {
        list: 'id'
    },
    logGroup: {
        list: ''
    },
    publicIp: {
        list: ''
    },
    instance: {
        list: 'id'
    },
    loadBalancer: {
        list: ''
    },
    cluster: {
        list: 'name'
    },
    user: {
        list: 'id'
    },
    authenticationPolicy: {
        get: ''
    },
    namespace: {
        get: ''
    },
    cloudguardConfiguration: {
        get: ''
    },
    group: {
        list: ''
    },
    exportSummary: {
        list: ''
    },
    fileSystem: {
        list: ''
    },
    mountTarget: {
        list: ''
    },
    defaultTags: {
        list: ''
    },
    waasPolicy: {
        list: ''
    },
    rules: {
        list: ''
    },
    topics: {
        list: 'topicId'
    },
    policy: {
        list: 'id'
    },
    dbHome: {
        list: 'id'
    },
    instancePool: {
        list: 'id'
    },
    autoscaleConfiguration: {
        list: 'resource.id'
    },
    bootVolume: {
        list: 'id'
    },
    volume: {
        list: 'id'
    },
    availabilityDomain: {
        list: ''
    },
    bootVolumeBackup: {
        list: ''
    },
    volumeBackup: {
        list: 'volumeId'
    },
    bootVolumeAttachment: {
        list: 'bootVolumeId'
    },
    volumeBackupPolicy: {
        list: ''
    },
    volumeGroup: {
        list: 'id'
    },
    volumeGroupBackup: {
        list: 'volumeGroupId'
    },
    configuration: {
        get: 'id'
    },
    networkSecurityGroup: {
        list: ''
    },
    dbSystem: {
        list: 'id'
    },
    vault: {
        list: 'id'
    },
    database: {
        list: 'id'
    }
};