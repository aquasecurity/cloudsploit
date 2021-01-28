// This file contains a list of ARN paths for each API call type
// that are used to extract ARNs for resources

module.exports = {
    cloudfront: {
        listDistributions: 'ARN',
        getDistribution: 'Distribution.ARN'
    }
};