var expect = require('chai').expect;
var plugin = require('./kmsKeyRequiredTags');

const region = 'eu-west-1';
const settings = { required_tags: '{"Owner":"*","Environment":"dev,prod"}' };
const run = (cache, extra) => {
    let output;
    plugin.run(cache, Object.assign({}, settings, extra || {}), (err, results) => { output = results; });
    return output;
};
const goodTags = [{ TagKey: 'Owner', TagValue: 'me' }, { TagKey: 'Environment', TagValue: 'dev' }];
const keyId = '11111111-2222-3333-4444-555555555555';
const keyArn = 'arn:aws:kms:eu-west-1:123456789012:key/' + keyId;
const createCache = (listKeys, manager, tags) => ({
    kms: {
        listKeys: { [region]: listKeys },
        describeKey: { [region]: { [keyId]: { data: { KeyMetadata: { KeyId: keyId, KeyManager: manager || 'CUSTOMER' } } } } },
        listResourceTags: { [region]: { [keyId]: tags || { data: { Tags: goodTags } } } }
    }
});
const keys = { data: [{ KeyId: keyId, KeyArn: keyArn }] };

describe('kmsKeyRequiredTags', function () {
    it('should PASS when all required tags are present', function () {
        const results = run(createCache(keys));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal(keyArn);
    });

    it('should FAIL when a required tag is missing', function () {
        expect(run(createCache(keys, 'CUSTOMER', { data: { Tags: [{ TagKey: 'Environment', TagValue: 'dev' }] } }))[0].status).to.equal(2);
    });

    it('should FAIL when a tag has a value that is not allowed', function () {
        expect(run(createCache(keys, 'CUSTOMER', { data: { Tags: [{ TagKey: 'Owner', TagValue: 'me' }, { TagKey: 'Environment', TagValue: 'acc' }] } }))[0].status).to.equal(2);
    });

    it('should not evaluate keys managed by AWS', function () {
        const results = run(createCache(keys, 'AWS', { data: { Tags: [] } }));

        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include('managed by AWS');
    });

    it('should not evaluate resources with an exempt tag key', function () {
        const results = run(createCache(keys, 'CUSTOMER', { data: { Tags: [{ TagKey: 'managed-by-x', TagValue: '1' }] } }), { required_tags_exempt_keys: 'x, managed-by-x' });

        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include('exempt');
    });

    it('should PASS when no required tags are configured', function () {
        expect(run(createCache(keys, 'CUSTOMER', { data: { Tags: [] } }), { required_tags: '{}' })[0].status).to.equal(0);
    });

    it('should return UNKNOWN when the setting is not valid JSON', function () {
        expect(run(createCache(keys), { required_tags: 'nope' })[0].status).to.equal(3);
    });

    it('should PASS when there are no keys', function () {
        expect(run(createCache({ data: [] }))[0].status).to.equal(0);
    });

    it('should return UNKNOWN when the keys cannot be listed', function () {
        expect(run(createCache({ err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });

    it('should return UNKNOWN when the tags cannot be queried', function () {
        expect(run(createCache(keys, 'CUSTOMER', { err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });
});
