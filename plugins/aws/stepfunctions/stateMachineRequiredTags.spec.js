var expect = require('chai').expect;
var plugin = require('./stateMachineRequiredTags');

const region = 'eu-west-1';
const settings = { required_tags: '{"Owner":"*","Environment":"dev,prod"}' };
const run = (cache, extra) => {
    let output;
    plugin.run(cache, Object.assign({}, settings, extra || {}), (err, results) => { output = results; });
    return output;
};
const goodTags = [{ Key: 'Owner', Value: 'me' }, { Key: 'Environment', Value: 'dev' }];
const arn = 'arn:aws:states:eu-west-1:123456789012:stateMachine:sm1';
const createCache = (data, tagged) => ({
    stepfunctions: { listStateMachines: { [region]: data } },
    resourcegroupstaggingapi: { getResources: { [region]: tagged || { data: [] } } }
});
const listed = { data: [{ stateMachineArn: 'arn:aws:states:eu-west-1:123456789012:stateMachine:sm1' }] };
const tagged = (tags) => ({ data: [{ ResourceARN: arn, Tags: tags }] });

describe('stateMachineRequiredTags', function () {
    it('should PASS when all required tags are present', function () {
        const results = run(createCache(listed, tagged(goodTags)));

        expect(results.length).to.equal(1);
        expect(results[0].status).to.equal(0);
        expect(results[0].resource).to.equal(arn);
    });

    it('should FAIL when a required tag is missing', function () {
        const results = run(createCache(listed, tagged([{ Key: 'Environment', Value: 'dev' }])));

        expect(results[0].status).to.equal(2);
        expect(results[0].message).to.include('Owner');
    });

    it('should FAIL when a tag has a value that is not allowed', function () {
        expect(run(createCache(listed, tagged([{ Key: 'Owner', Value: 'me' }, { Key: 'Environment', Value: 'acc' }])))[0].status).to.equal(2);
    });

    it('should FAIL when the resource was never tagged', function () {
        expect(run(createCache(listed))[0].status).to.equal(2);
    });

    it('should not evaluate resources with an exempt tag key', function () {
        const results = run(createCache(listed, tagged([{ Key: 'managed-by-x', Value: '1' }])), { required_tags_exempt_keys: 'x, managed-by-x' });

        expect(results[0].status).to.equal(0);
        expect(results[0].message).to.include('exempt');
    });

    it('should PASS when no required tags are configured', function () {
        expect(run(createCache(listed), { required_tags: '{}' })[0].status).to.equal(0);
    });

    it('should return UNKNOWN when the setting is not valid JSON', function () {
        expect(run(createCache(listed, tagged(goodTags)), { required_tags: 'nope' })[0].status).to.equal(3);
    });

    it('should PASS when there are none', function () {
        expect(run(createCache({ data: [] }))[0].status).to.equal(0);
    });

    it('should return UNKNOWN when they cannot be listed', function () {
        expect(run(createCache({ err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });

    it('should return UNKNOWN when the tags cannot be queried', function () {
        expect(run(createCache(listed, { err: { message: 'AccessDenied' } }))[0].status).to.equal(3);
    });
});
