var expect = require('chai').expect;
var plugin = require('./s3BucketRequiredTags');

const requiredTags = '{"Owner":"*","Environment":"dev,prod"}';
const goodTags = [{ Key: 'Owner', Value: 'me' }, { Key: 'Environment', Value: 'dev' }];
const run = (cache, settings) => {
    let output;
    plugin.run(cache, settings || {}, (err, results) => { output = results; });
    return output;
};
const createCache = (tagging) => ({
    s3: {
        listBuckets: { 'us-east-1': { data: [{ Name: 'bucket1' }] } },
        getBucketLocation: { 'us-east-1': { bucket1: { data: { LocationConstraint: 'eu-west-1' } } } },
        getBucketTagging: { 'eu-west-1': { bucket1: tagging } }
    }
});
const withTags = (tags) => createCache({ data: { TagSet: tags } });

describe('s3BucketRequiredTags', function () {
    it('should PASS every bucket when no required tags are configured', function () {
        const results = run(createCache({ err: { code: 'NoSuchTagSet' } }));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
    });

    it('should PASS when all required tags are present with allowed values', function () {
        const results = run(withTags(goodTags), { s3_required_tags: requiredTags });

        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal('arn:aws:s3:::bucket1');
        expect(results[0].region).to.equal('eu-west-1');
    });

    it('should FAIL when a required tag is missing', function () {
        const results = run(withTags(goodTags.slice(1)), { s3_required_tags: requiredTags });

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('Owner');
    });

    it('should FAIL when a tag has a value that is not allowed', function () {
        const results = run(withTags([goodTags[0], { Key: 'Environment', Value: 'acc' }]), { s3_required_tags: requiredTags });

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('Environment');
    });

    it('should FAIL when the bucket has no tags', function () {
        expect(run(createCache({ err: { code: 'NoSuchTagSet' } }), { s3_required_tags: requiredTags })[0].status).to.equal(2);
    });

    it('should not evaluate buckets that have an exempt tag key', function () {
        const results = run(withTags([{ Key: 'managed-by-x', Value: '1' }]),
            { s3_required_tags: requiredTags, s3_required_tags_exempt_keys: 'other, managed-by-x' });

        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include('out of scope');
    });

    it('should evaluate every bucket when no exempt tag keys are configured', function () {
        expect(run(withTags([{ Key: 'ZERTO_TAG', Value: 'x' }]), { s3_required_tags: requiredTags })[0].status).to.equal(2);
    });

    it('should return UNKNOWN when the tags cannot be queried', function () {
        const results = run(createCache({ err: { code: 'AccessDenied', message: 'denied' } }), { s3_required_tags: requiredTags });

        expect(results[0].status).to.equal(3);
    });

    it('should return UNKNOWN when the setting is not valid JSON', function () {
        expect(run(withTags(goodTags), { s3_required_tags: 'nope' })[0].status).to.equal(3);
    });
});
