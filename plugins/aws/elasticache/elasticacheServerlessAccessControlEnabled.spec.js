var expect = require('chai').expect;
var plugin = require('./elasticacheServerlessAccessControlEnabled');

const region = 'eu-west-1';
const run = (caches) => {
    let output;
    plugin.run({ elasticache: { describeServerlessCaches: { [region]: caches } } }, {}, (err, results) => { output = results; });
    return output;
};

describe('elasticacheServerlessAccessControlEnabled', function () {
    it('should PASS when the cache has a user group', function () {
        const results = run({ data: [{ ServerlessCacheName: 'c1', ARN: 'arn:c1', UserGroupId: 'group' }] });

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal('arn:c1');
    });

    it('should FAIL when the cache has no user group', function () {
        expect(run({ data: [{ ServerlessCacheName: 'c1' }] })[0].status).to.equal(2);
    });

    it('should PASS without serverless caches', function () {
        expect(run({ data: [] })[0].status).to.equal(0);
    });

    it('should return UNKNOWN when the caches cannot be listed', function () {
        expect(run({ err: { message: 'AccessDenied' } })[0].status).to.equal(3);
    });
});
