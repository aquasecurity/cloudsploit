var engine = require('./engine');

describe('engine', function () {
    it('should run specific plugins and check clients', function (done) {
        const cloudConfig = {};
        const settings = {
            cloud: 'aws',
            plugins: ['s3BucketHasTags', 'ec2HasTags','iamRolePolicies'],
            mocha: true
        };

        engine(cloudConfig, settings);
        done();
    });
});
