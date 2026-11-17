var expect = require('chai').expect;
var plugin = require('./elasticacheServerlessCmkUsed');

const region = 'eu-west-1';
const keyId = '11111111-2222-3333-4444-555555555555';
const keyArn = 'arn:aws:kms:eu-west-1:123456789012:key/' + keyId;
const arn = 'arn:aws:elasticache:eu-west-1:123456789012:serverlesscache:c1';

const createCache = (caches, listKeys) => ({
    elasticache: { describeServerlessCaches: { [region]: caches } },
    kms: { listKeys: { [region]: listKeys || { data: [{ KeyId: keyId, KeyArn: keyArn }] } } }
});
const run = (cache) => {
    let output;
    plugin.run(cache, {}, (err, results) => { output = results; });
    return output;
};

describe('elasticacheServerlessCmkUsed', function () {
    it('should PASS when the cache uses a key ARN of the account', function () {
        const results = run(createCache({ data: [{ ServerlessCacheName: 'c1', ARN: arn, KmsKeyId: keyArn }] }));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal(arn);
    });

    it('should PASS when the cache uses a key id of the account', function () {
        expect(run(createCache({ data: [{ ServerlessCacheName: 'c1', KmsKeyId: keyId }] }))[0].status).to.equal(0);
    });

    it('should FAIL when the cache has no KMS key', function () {
        expect(run(createCache({ data: [{ ServerlessCacheName: 'c1', ARN: arn }] }))[0].status).to.equal(2);
    });

    it('should FAIL when the key is not a key of the account', function () {
        const results = run(createCache({ data: [{ ServerlessCacheName: 'c1', KmsKeyId: 'arn:aws:kms:eu-west-1:999999999999:key/x' }] }));

        expect(results[0].status).to.equal(2);
    });

    it('should PASS without serverless caches', function () {
        expect(run(createCache({ data: [] }))[0].status).to.equal(0);
    });

    it('should return UNKNOWN when the caches cannot be listed', function () {
        expect(run(createCache({ err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });

    it('should return UNKNOWN when keys cannot be listed', function () {
        expect(run(createCache({ data: [{ ServerlessCacheName: 'c1' }] }, { err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });
});
