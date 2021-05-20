function defaultRegion(settings) {
    if (settings.defaultRegion) return settings.defaultRegion;
    return 'cn-hangzhou';
}

function createArn(service, account, resourceType, resourceId, region) {
    if (!region) region = '';
    return `arn:acs:${service}:${region}:${account}:${resourceType}/${resourceId}`;
}

module.exports = {
    defaultRegion: defaultRegion,
    createArn: createArn
};