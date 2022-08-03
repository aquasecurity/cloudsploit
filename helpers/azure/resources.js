// This file contains a list of ARN paths for each API call type
// that are used to extract ARNs for resources

module.exports = {
    roleDefinitions: {
        list: 'id'
    },
    networkSecurityGroups: {
        listAll: 'id',
    },
    blobContainers: {
        list: 'id'
    }
};